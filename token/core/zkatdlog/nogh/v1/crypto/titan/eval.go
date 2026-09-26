/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	mathlib "github.com/IBM/mathlib"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/rp/csp"
	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/sumcheck"
)

// Evaluation: two legs, because the commitment has two tiers
//
// A field commitment is a Pedersen tier over the rows of the matrix form of f,
// followed by a Merkle tier over the resulting group multilinear G. Proving
// f(alpha) = sigma has to say something about both tiers, so the proof has two
// legs, and alpha splits across the matrix to give each leg its half:
//
//	alphaCol = alpha[:m/2]   the COLUMN half -- the first variables
//	alphaRow = alpha[m/2:]   the ROW half    -- the last variables
//
//	sigmaPartial = sum_j eq(alphaRow, <j>) * G_j        a group element
//	             = G(alphaRow), the partial evaluation
//
//	leg 1 (rows):    group sum-check on G at alphaRow, output sigmaPartial
//	leg 2 (columns): CSP linear form proving <eq(alphaCol,.), a> = sigma,
//	                 where a is the folded row and sigmaPartial is its commitment
//
// Neither leg is optional. Leg 1 shows sigmaPartial really is the committed
// oracle's partial evaluation, but says nothing about alphaCol. Leg 2 proves an
// evaluation under the Pedersen commitment sigmaPartial, but on its own nobody has
// tied that commitment to the oracle. It is the *shared* sigmaPartial that joins
// them, which is why the tests check leg independence explicitly: a proof whose
// two legs are individually valid but describe different polynomials is the
// characteristic way a two-leg argument goes unsound.
//
// # Why sigmaPartial is simultaneously an evaluation and a commitment
//
// This is the pivot the whole construction turns on, and it is worth stating
// plainly because it looks like a coincidence.
//
// Tier 1 set G_j = MSM(gens, row_j), so G_j is a Pedersen commitment to row j.
// Taking the eq(alphaRow, .) combination of the G_j commutes with that MSM:
//
//	sigmaPartial = sum_j eq_j * MSM(gens, row_j) = MSM(gens, sum_j eq_j * row_j)
//	             = MSM(gens, a)     where a = fold of the rows at alphaRow
//
// So the same group element is an evaluation of G (what leg 1 proves) and a
// Pedersen commitment to the folded row vector a (what leg 2 opens). Linearity of
// the MSM in the message is the entire reason one element can play both parts, and
// it is why tier 1 must be a plain MSM: any non-linear row commitment breaks this.
//
// And a = fold(rows, alphaRow) satisfies <eq(alphaCol,.), a> = f(alpha), since
// eq(alpha, .) factorizes as eq(alphaCol,.) * eq(alphaRow,.) over the split.
//
// # Leg 2 is CSP, not a Bulletproof inner-product argument
//
// The reference implementation uses a Bulletproof here. It does not need to: the
// linear form is eq(alphaCol, .), and alphaCol is public, so the verifier computes
// the coefficient vector itself. There is no secret vector to hide from it, and a
// Bulletproof's extra machinery buys nothing over the compressed sigma-protocol
// already in this tree (crypto/rp/csp). Using the audited one also means there is
// one CSP implementation here rather than two.
//
// Neither leg is zero-knowledge, and the proof is not meant to be: tier 1 is
// non-hiding Pedersen, csp.ProveLinearForm is the non-ZK variant, and leg 2's
// witness is the folded row itself. Hiding is a separate change to tier 1.

// Generators is a set of Pedersen generators together with their mathlib form.
//
// # Why this type exists, with numbers
//
// Converting a generator into mathlib costs ~35us, because mathlib routes every G1
// constructor through a subgroup check (see bridge.go). That is per point, and leg
// 2 needs all of them, on both sides. Measured on an M4 Max, against the cost of
// the whole proof:
//
//	m    generators   convert    Eval      VerifyEval
//	12   64           2.19ms     14.7ms    3.34ms
//	14   128          4.52ms     25.7ms    5.91ms
//
// So the conversion is ~15-18% of the prover and **66-76% of the verifier**. The
// verifier is dominated by it: at m=14 it spends more time crossing the boundary
// than verifying anything.
//
// The generators are fixed setup parameters, though, so this is avoidable. A
// caller that converts them once and reuses the result pays the cost per *key*,
// not per proof, and the verifier's work drops to the 1.4ms it actually spends on
// the two legs. That is the whole point of this type: it makes the converted form
// something a caller can hold, rather than something each call rebuilds.
//
// Build one with NewGenerators and pass it to Eval and VerifyEval. The
// []bls12381.G1Affine overloads remain for callers that do not care.
type Generators struct {
	// Affine is the gnark-crypto form, used by tier 1 and the sum-check.
	Affine []bls12381.G1Affine
	// math is the mathlib form, used by leg 2. Unexported so it cannot drift out
	// of step with Affine.
	math []*mathlib.G1
	// curveID records which mathlib curve math was converted onto, because csp
	// validates every element's curve ID against the statement's curve and a
	// mismatch there reads as a soundness failure rather than a plumbing one.
	curveID mathlib.CurveID
}

// NewGenerators converts a set of generators once, for reuse across evaluations.
//
// curve may be nil, in which case this package's default is used. The point at
// infinity is rejected: csp rejects an identity generator, and reporting it here
// names the offending index.
func NewGenerators(curve *mathlib.Curve, gens []bls12381.G1Affine) (*Generators, error) {
	if curve == nil {
		curve = bridgeCurve()
	}
	if len(gens) == 0 {
		return nil, errors.Wrap(ErrInsufficientGenerators, "no generators supplied")
	}
	m, err := toMathG1Slice(gens, curve)
	if err != nil {
		return nil, err
	}
	affine := make([]bls12381.G1Affine, len(gens))
	copy(affine, gens)

	return &Generators{Affine: affine, math: m, curveID: curve.ID()}, nil
}

// Len returns the number of generators held.
func (g *Generators) Len() int {
	if g == nil {
		return 0
	}

	return len(g.Affine)
}

// prefix returns the first n generators in both forms, which is what leg 2 needs:
// the column count is the matrix width, and a caller may hold more than that.
//
// It also checks the cached mathlib form was built on the curve now in use.
// Converting onto one curve and proving on another produces elements csp rejects
// for a reason that looks nothing like the cause, so this turns it into a clear
// error at the point of misuse.
func (g *Generators) prefix(curve *mathlib.Curve, n int) ([]bls12381.G1Affine, []*mathlib.G1, error) {
	if g == nil || len(g.Affine) == 0 {
		return nil, nil, errors.Wrap(ErrInsufficientGenerators, "no generators supplied")
	}
	if len(g.Affine) < n {
		return nil, nil, errors.Wrapf(ErrInsufficientGenerators, "need %d generators, got %d", n, len(g.Affine))
	}
	if len(g.math) != len(g.Affine) {
		return nil, nil, errors.Wrap(ErrNumVarsMismatch, "the cached generators are inconsistent; rebuild with NewGenerators")
	}
	if curve != nil && g.curveID != curve.ID() {
		return nil, nil, errors.Wrapf(ErrNilCurve,
			"the generators were converted for curve %d but the proof uses %d; rebuild with NewGenerators",
			g.curveID, curve.ID())
	}

	return g.Affine[:n], g.math[:n], nil
}

// evalTranscriptHeader domain-separates leg 2's Fiat-Shamir transcript.
//
// Distinct from DomainSeparator (leg 1) and from anything rp.go uses, so a CSP
// proof produced for a range proof can never be replayed as a Titan column leg,
// nor a column leg as a row leg.
const evalTranscriptHeader = "TitanEvalColumnLeg-v1"

// EvalProof is a proof that a committed field multilinear evaluates to a claimed
// value at a point.
type EvalProof struct {
	// SigmaPartial is G(alphaRow): the partial evaluation that leg 1 proves and
	// leg 2 opens. It is the only element both legs touch, and therefore the only
	// thing binding them together.
	SigmaPartial bls12381.G1Affine

	// RowProof is leg 1, the group sum-check on G at alphaRow.
	RowProof *GroupSumCheckProof

	// RowOpening is the residual claim leg 1 reduces to: the challenge point and
	// the value the rounds telescope to. The verifier recomputes it rather than
	// trusting it, so this is prover-side convenience only and is not consulted
	// by VerifyEval.
	RowOpening *GroupSumCheckOpening

	// ColProof is leg 2, the CSP linear-form proof.
	ColProof *csp.Proof

	// Fold closes leg 1 against the committed coset oracle, or is nil if the
	// commitment carried no coset oracle.
	//
	// Leg 1 reduces "G sums to SigmaPartial" to a residual claim; leg 2 opens
	// SigmaPartial against the generators. Neither ties SigmaPartial to the
	// commitment -- Fold is what does, so without it the two legs prove an
	// evaluation of a polynomial nobody committed. See FoldProof.
	Fold *FoldProof
}

// GroupEvalProof is a proof that a committed *group* multilinear evaluates to a
// claimed group element at a point.
//
// # It has one leg, and that is not an omission
//
// A group polynomial's evaluation already *is* a group element, so there is no
// field value underneath it to bind and no Pedersen tier to open: the group
// commitment is tier 2 alone. Leg 1 is therefore the whole protocol here. The
// asymmetry with EvalProof reflects the asymmetry of the two commitments, not a
// missing half.
type GroupEvalProof struct {
	// RowProof is the group sum-check on G at alpha.
	RowProof *GroupSumCheckProof

	// Opening is the residual claim, retained for the caller's use; see the note
	// on closing it in VerifyEvalGroup.
	Opening *GroupSumCheckOpening

	// Fold closes the claim against the committed coset oracle, or is nil if the
	// commitment carried no coset oracle.
	//
	// Without it the proof only *reduces* the claim: RowProof shows the sum
	// follows from Opening, and nothing ties Opening to the commitment. Fold is
	// what makes the proof binding -- see FoldProof and verifyFold.
	Fold *FoldProof
}

// Eval proves that the committed field multilinear evaluates to sigma at alpha,
// returning the proof and the value sigma it computed.
//
// sigma is returned rather than accepted: it is determined by the polynomial and
// the point, so a caller that already believes a value should compare against
// this one rather than assert it.
//
// alpha must have m coordinates, where 2^m is the length of the committed
// polynomial -- note this is the number of variables of f, not the Commitment's
// NumVars, which counts only the row half.
//
// curve is the mathlib curve for the transcript and for leg 2; pass nil to use
// the one matching this package's types.
//
// gens should be built once with NewGenerators and reused: the conversion it caches
// is ~15-18% of this call's cost, and the bulk of VerifyEval's. See Generators.
// EvalAffine is the convenience form for a caller that has not got one.
func (h *FieldOpeningHint) Eval(curve *mathlib.Curve, gens *Generators, alpha []fr.Element) (*EvalProof, fr.Element, error) {
	var sigma fr.Element

	if h == nil {
		return nil, sigma, errors.Wrap(ErrNilTree, "cannot evaluate without an opening hint")
	}
	if curve == nil {
		curve = bridgeCurve()
	}
	m, err := numVarsOf(len(h.Rows))
	if err != nil {
		return nil, sigma, err
	}
	if len(alpha) != m {
		return nil, sigma, errors.Wrapf(ErrNumVarsMismatch, "polynomial has %d variables, alpha has %d coordinates", m, len(alpha))
	}
	_, mgens, err := gens.prefix(curve, h.NumCols)
	if err != nil {
		return nil, sigma, err
	}

	alphaCol, alphaRow := splitAlpha(alpha, m)

	// a = fold(rows, alphaRow): the eq(alphaRow,.) combination of the matrix rows.
	// This is leg 2's witness, and sigmaPartial is its Pedersen commitment.
	a, err := foldRows(h.Rows, h.NumRows, h.NumCols, alphaRow)
	if err != nil {
		return nil, sigma, err
	}

	// sigma = <eq(alphaCol,.), a> = f(alpha).
	sigma, err = innerProduct(eqTable(alphaCol), a)
	if err != nil {
		return nil, sigma, errors.Wrap(err, "failed to compute the claimed evaluation")
	}

	// Leg 1: the group sum-check produces sigmaPartial as its asserted sum, so it
	// is not computed separately here -- deriving it twice would let the two
	// derivations disagree silently.
	rowEll := DefaultSplit(len(alphaRow))
	rowTr := newGroupSumCheckTranscript(curve, len(alphaRow), rowEll, alphaRow)

	rowProof, rowOpening, sigmaPartial, err := ProveGroupEvalWithTranscript(rowTr, curve, h.G, alphaRow, rowEll)
	if err != nil {
		return nil, sigma, errors.Wrap(err, "failed to prove the row leg")
	}

	// The folding phase, on leg 1's transcript so its challenges depend on every
	// round message. Skipped when the commitment carried no coset oracle, in which
	// case the proof reduces the claim without closing it; VerifyEval says so.
	var foldProof *FoldProof
	if h.Cosets != nil {
		foldProof, err = proveFold(rowTr, h.G, h.Cosets, h.Fold, alphaRow, &sigmaPartial)
		if err != nil {
			return nil, sigma, errors.Wrap(err, "failed to prove the folding phase")
		}
	}

	// Leg 2: the CSP linear form, in mathlib.
	colProof, err := proveColumnLeg(curve, mgens, a, eqTable(alphaCol), &sigmaPartial, &sigma)
	if err != nil {
		return nil, sigma, errors.Wrap(err, "failed to prove the column leg")
	}

	return &EvalProof{
		SigmaPartial: sigmaPartial,
		RowProof:     rowProof,
		RowOpening:   rowOpening,
		ColProof:     colProof,
		Fold:         foldProof,
	}, sigma, nil
}

// VerifyEval checks an EvalProof against the claim f(alpha) = sigma.
//
// # What a nil error means, and what it does not
//
// Both legs are checked, and they are checked against the *same* SigmaPartial, so
// a proof that passes ties the claimed evaluation to the committed oracle's
// partial evaluation. What remains open is leg 1's residual claim: like every
// sum-check, VerifyGroupEval reduces the sum to an opening rather than closing it
// (see its own note). Closing that requires querying the Merkle oracle at the
// residual point and checking the queried value against Opening.Expected.
//
// Those queries are the WHIR proximity test, and they are not implemented yet --
// the folding rounds that make the oracle queryable at an arbitrary point are
// step 5. So this verifier is *complete but not yet sound against a prover that
// lies about the oracle*: it catches every inconsistency between the two legs and
// every malformed round message, but a prover free to invent G entirely can still
// satisfy it. The returned opening is what the missing check consumes, which is
// why it is returned rather than discarded.
//
// This is stated here rather than buried in the plan because a caller that treats
// the nil error as a full soundness guarantee today would be wrong.
func VerifyEval(curve *mathlib.Curve, c *Commitment, gens *Generators, alpha []fr.Element, sigma fr.Element, proof *EvalProof) (*GroupSumCheckOpening, error) {
	if c == nil {
		return nil, errors.Wrap(ErrNilElement, "commitment is required")
	}
	if proof == nil {
		return nil, ErrNilProof
	}
	if proof.RowProof == nil {
		return nil, errors.Wrap(ErrNilProof, "the row leg is missing")
	}
	if proof.ColProof == nil {
		return nil, errors.Wrap(ErrNilProof, "the column leg is missing")
	}
	if curve == nil {
		curve = bridgeCurve()
	}

	// m comes from alpha, and the commitment is then checked to be consistent with
	// it. It cannot be derived the other way round: see checkShape.
	m := len(alpha)
	numCols, err := checkShape(c, m)
	if err != nil {
		return nil, err
	}
	_, mgens, err := gens.prefix(curve, numCols)
	if err != nil {
		return nil, err
	}

	alphaCol, alphaRow := splitAlpha(alpha, m)

	// Leg 1: the row sum-check, asserting the sum is SigmaPartial.
	rowEll := DefaultSplit(len(alphaRow))
	rowTr := newGroupSumCheckTranscript(curve, len(alphaRow), rowEll, alphaRow)

	opening, err := VerifyGroupEvalWithTranscript(rowTr, curve, proof.RowProof, alphaRow, &proof.SigmaPartial, rowEll)
	if err != nil {
		return nil, errors.Wrap(err, "the row leg does not verify")
	}

	// The folding phase, which is what binds SigmaPartial to the commitment. As in
	// VerifyEvalGroup, a commitment carrying a coset oracle REQUIRES a fold proof:
	// otherwise omitting the field would downgrade a sound commitment.
	switch {
	case c.Cosets != nil:
		if proof.Fold == nil {
			return nil, errors.Wrap(ErrNilProof, "the commitment carries a coset oracle but the proof has no folding phase")
		}
		if err := verifyFold(rowTr, c.Cosets, c.Cosets.Fold, alphaRow, &proof.SigmaPartial, proof.Fold); err != nil {
			return nil, errors.Wrap(err, "the folding phase does not verify")
		}
	case proof.Fold != nil:
		return nil, errors.Wrap(ErrNilProof, "the proof carries a folding phase but the commitment has no coset oracle")
	}

	// Leg 2: the column CSP proof, against the same SigmaPartial. The verifier
	// builds eq(alphaCol, .) itself -- that is the reason this can be CSP at all.
	if err := verifyColumnLeg(curve, mgens, eqTable(alphaCol), &proof.SigmaPartial, &sigma, proof.ColProof); err != nil {
		return nil, errors.Wrap(err, "the column leg does not verify")
	}

	return opening, nil
}

// EvalGroup proves that the committed group multilinear evaluates to the returned
// group element at alpha. It is leg 1 alone; see GroupEvalProof for why.
func (h *GroupOpeningHint) EvalGroup(curve *mathlib.Curve, alpha []fr.Element) (*GroupEvalProof, bls12381.G1Affine, error) {
	var sigma bls12381.G1Affine

	if h == nil {
		return nil, sigma, errors.Wrap(ErrNilTree, "cannot evaluate without an opening hint")
	}
	if curve == nil {
		curve = bridgeCurve()
	}

	ell := DefaultSplit(len(alpha))

	// One transcript for both phases. The fold challenges and query indices then
	// depend on every sum-check message, so a prover cannot pick its polynomial
	// after seeing which cosets will be opened.
	tr := newGroupSumCheckTranscript(curve, len(alpha), ell, alpha)

	proof, opening, sigma, err := ProveGroupEvalWithTranscript(tr, curve, h.G, alpha, ell)
	if err != nil {
		return nil, sigma, errors.Wrap(err, "failed to prove the group evaluation")
	}

	out := &GroupEvalProof{RowProof: proof, Opening: opening}

	// The folding phase closes sigma against the oracle. A hint without a coset
	// oracle can still reduce the claim, so this is skipped rather than an error;
	// VerifyEvalGroup says so in its contract.
	if h.Cosets != nil {
		out.Fold, err = proveFold(tr, h.G, h.Cosets, h.Fold, alpha, &sigma)
		if err != nil {
			return nil, sigma, errors.Wrap(err, "failed to prove the folding phase")
		}
	}

	return out, sigma, nil
}

// VerifyEvalGroup checks a GroupEvalProof against the claim G(alpha) = sigma and
// returns the residual claim.
//
// The same caveat as VerifyEval applies and is in fact the whole caveat here,
// there being only one leg: a nil error means the claim follows from the returned
// opening, and closing it needs the oracle query that step 5 adds.
func VerifyEvalGroup(curve *mathlib.Curve, c *Commitment, alpha []fr.Element, sigma *bls12381.G1Affine, proof *GroupEvalProof) (*GroupSumCheckOpening, error) {
	if c == nil {
		return nil, errors.Wrap(ErrNilElement, "commitment is required")
	}
	if proof == nil || proof.RowProof == nil {
		return nil, ErrNilProof
	}
	if sigma == nil {
		return nil, errors.Wrap(ErrNilElement, "sigma is required")
	}
	if curve == nil {
		curve = bridgeCurve()
	}
	if len(alpha) != c.NumVars {
		return nil, errors.Wrapf(ErrNumVarsMismatch, "commitment is over %d variables, alpha has %d coordinates", c.NumVars, len(alpha))
	}

	ell := DefaultSplit(len(alpha))
	tr := newGroupSumCheckTranscript(curve, len(alpha), ell, alpha)

	opening, err := VerifyGroupEvalWithTranscript(tr, curve, proof.RowProof, alpha, sigma, ell)
	if err != nil {
		return nil, errors.Wrap(err, "the group evaluation does not verify")
	}

	// The commitment says whether this claim can be closed. If it carries a coset
	// oracle then a fold proof is REQUIRED: treating a missing one as acceptable
	// would let a prover downgrade a sound commitment to an unsound opening simply
	// by omitting a field.
	switch {
	case c.Cosets != nil:
		if proof.Fold == nil {
			return nil, errors.Wrap(ErrNilProof, "the commitment carries a coset oracle but the proof has no folding phase")
		}
		// The configuration -- crucially the query count -- comes from the
		// commitment, which was fixed before any challenge was drawn. Deriving it
		// from the proof would make the security level the prover's choice.
		if err := verifyFold(tr, c.Cosets, c.Cosets.Fold, alpha, sigma, proof.Fold); err != nil {
			return nil, errors.Wrap(err, "the folding phase does not verify")
		}
	case proof.Fold != nil:
		return nil, errors.Wrap(ErrNilProof, "the proof carries a folding phase but the commitment has no coset oracle")
	}

	return opening, nil
}

// splitAlpha divides the evaluation point into its column and row halves.
//
// # The split is the opposite way round from the reference, deliberately
//
// The reference implementation takes its row half as alpha[..m/2]. Here it is
// alpha[m/2:], and the difference is a layout difference, not a disagreement.
//
// Row j of the matrix is the contiguous block f[j*cols : (j+1)*cols] (see
// commitField), so the row index occupies the HIGH bits of the flat table index.
// In the little-endian convention this package and crypto/sumcheck share, table
// entry i holds f at the bit decomposition of i with b_k the k-th bit, so the high
// bits are the LAST variables. Rows therefore correspond to alpha[m/2:] and
// columns to alpha[:m/2].
//
// Getting this backwards is the worst kind of bug available here: eq factorizes
// over any split, so both assignments produce a well-formed proof that verifies
// against itself -- just for a different polynomial than the one committed. It
// fails only when checked against an independently computed f(alpha), which is
// why the tests do exactly that.
func splitAlpha(alpha []fr.Element, m int) (alphaCol, alphaRow []fr.Element) {
	return alpha[:m/2], alpha[m/2:]
}

// checkShape verifies that a commitment is over the row half of an m-variable
// matrix split, and returns the column count.
//
// # m is not recoverable from the commitment, so it is not derived from it
//
// The tempting move is to invert matrixShape and take m from the commitment, so
// that a prover cannot influence the split by choosing the length of alpha. It
// does not work: the commitment carries only NumVars = log2(rows), and every row
// count is produced by *two* different m. With rows = 2^(m - m/2), m = 2s gives
// s rows-exponent and m = 2s-1 gives the same, so 2^NumVars rows is consistent
// with both m = 2*NumVars and m = 2*NumVars - 1 -- they differ only in the column
// count, which the commitment does not carry. (An earlier version of this function
// claimed to resolve that by checking the row count; the check is vacuous, since
// both candidates reproduce it. A test over m = 1..16 caught it.)
//
// So m comes from alpha and the commitment is checked against it. That is not a
// weakening: alpha is public input to the verifier, not part of the proof, so a
// verifier asked about a point of the wrong length gets an error rather than a
// misleading accept. What must not happen -- and does not -- is for the two sides
// to silently disagree on the split, which the row-count check below rules out.
//
// Callers who need the column count on the wire should put it in the commitment;
// that is a format change, noted rather than made here.
func checkShape(c *Commitment, m int) (numCols int, err error) {
	if m < 1 {
		return 0, errors.Wrapf(ErrNumVarsMismatch, "alpha must have at least one coordinate")
	}
	rows, cols := matrixShape(m)
	if c.NumVars < 0 || c.NumVars > 62 || rows != 1<<c.NumVars {
		return 0, errors.Wrapf(ErrNumVarsMismatch,
			"a %d-variable polynomial has %d rows, but the commitment is over 2^%d", m, rows, c.NumVars)
	}

	return cols, nil
}

// foldRows returns the eq(alphaRow, .) combination of the matrix rows, i.e. the
// folded row vector a with a[c] = sum_j eq(alphaRow, <j>) * rows[j*cols + c].
//
// This is leg 2's witness. It is 2^m field multiplications, one pass over the
// polynomial, which is the cheapest thing the prover does.
func foldRows(f sumcheck.FieldPoly, numRows, numCols int, alphaRow []fr.Element) (sumcheck.FieldPoly, error) {
	if numRows*numCols != len(f) {
		return nil, errors.Wrapf(ErrNumVarsMismatch, "matrix shape %dx%d does not cover %d coefficients", numRows, numCols, len(f))
	}
	eqRow := eqTable(alphaRow)
	if len(eqRow) != numRows {
		return nil, errors.Wrapf(ErrNumVarsMismatch, "row half has %d coordinates, expected %d rows but got %d", len(alphaRow), numRows, len(eqRow))
	}

	a := make(sumcheck.FieldPoly, numCols)
	for j := range numRows {
		row := f[j*numCols : (j+1)*numCols]
		for c := range numCols {
			var t fr.Element
			t.Mul(&eqRow[j], &row[c])
			a[c].Add(&a[c], &t)
		}
	}

	return a, nil
}

// innerProduct returns <x, y> for two equal-length field vectors.
func innerProduct(x, y []fr.Element) (fr.Element, error) {
	var out fr.Element
	if len(x) != len(y) {
		return out, errors.Wrapf(ErrNumVarsMismatch, "inner product length mismatch: %d and %d", len(x), len(y))
	}
	for i := range x {
		var t fr.Element
		t.Mul(&x[i], &y[i])
		out.Add(&out, &t)
	}

	return out, nil
}

// proveColumnLeg builds leg 2's CSP statement and proves it.
//
// This is the mathlib boundary. The generators are the expensive conversion (see
// bridge.go) and are converted here per call; a caller proving many evaluations
// against one commitment should hoist them, which is what the benchmark measures.
func proveColumnLeg(
	curve *mathlib.Curve,
	gens []*mathlib.G1,
	witness, linearForm sumcheck.FieldPoly,
	commitment *bls12381.G1Affine,
	value *fr.Element,
) (*csp.Proof, error) {
	st, err := columnStatement(curve, gens, linearForm, commitment, value)
	if err != nil {
		return nil, err
	}
	mw, err := toMathZrSlice(witness, curve)
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert the column witness")
	}

	proof, err := csp.ProveLinearForm(st, mw, []byte(evalTranscriptHeader))
	if err != nil {
		return nil, errors.Wrap(err, "the CSP prover failed")
	}

	return proof, nil
}

// verifyColumnLeg rebuilds leg 2's statement from public data and checks the proof.
func verifyColumnLeg(
	curve *mathlib.Curve,
	gens []*mathlib.G1,
	linearForm sumcheck.FieldPoly,
	commitment *bls12381.G1Affine,
	value *fr.Element,
	proof *csp.Proof,
) error {
	st, err := columnStatement(curve, gens, linearForm, commitment, value)
	if err != nil {
		return err
	}

	return csp.VerifyLinearForm(st, proof, []byte(evalTranscriptHeader))
}

// columnStatement converts leg 2's public data into a CSP statement.
//
// Both sides build it the same way, from the same inputs, so there is one
// conversion path and no chance of prover and verifier disagreeing on the
// encoding -- a mismatch there would look like a soundness failure.
func columnStatement(
	curve *mathlib.Curve,
	gens []*mathlib.G1,
	linearForm sumcheck.FieldPoly,
	commitment *bls12381.G1Affine,
	value *fr.Element,
) (*csp.LinearFormStatement, error) {
	if curve == nil {
		return nil, ErrNilCurve
	}
	if commitment == nil || value == nil {
		return nil, errors.Wrap(ErrNilElement, "the column leg needs a commitment and a value")
	}

	mform, err := toMathZrSlice(linearForm, curve)
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert the linear form")
	}
	mcomm, err := toMathG1(commitment, curve)
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert the partial evaluation")
	}
	mvalue, err := toMathZr(value, curve)
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert the claimed value")
	}

	return &csp.LinearFormStatement{
		Commitment: mcomm,
		Generators: gens,
		LinearForm: mform,
		Value:      mvalue,
		Curve:      curve,
	}, nil
}

// EvalAffine is Eval for a caller that has not built a Generators.
//
// It converts the generators on every call, which the numbers on Generators argue
// against for anything but a one-off: at m=14 that is 4.5ms of a 25.7ms proof.
// Prefer NewGenerators plus Eval when proving more than once against a commitment.
func (h *FieldOpeningHint) EvalAffine(curve *mathlib.Curve, gens []bls12381.G1Affine, alpha []fr.Element) (*EvalProof, fr.Element, error) {
	if h == nil {
		var sigma fr.Element

		return nil, sigma, errors.Wrap(ErrNilTree, "cannot evaluate without an opening hint")
	}
	g, err := NewGenerators(curve, gens)
	if err != nil {
		var sigma fr.Element

		return nil, sigma, err
	}

	return h.Eval(curve, g, alpha)
}

// VerifyEvalAffine is VerifyEval for a caller that has not built a Generators.
//
// The same caveat applies and bites harder here: the conversion is the majority of
// this call's cost (66-76%, see Generators), so a verifier checking more than one
// proof against a key should hold a Generators rather than use this.
func VerifyEvalAffine(curve *mathlib.Curve, c *Commitment, gens []bls12381.G1Affine, alpha []fr.Element, sigma fr.Element, proof *EvalProof) (*GroupSumCheckOpening, error) {
	g, err := NewGenerators(curve, gens)
	if err != nil {
		return nil, err
	}

	return VerifyEval(curve, c, g, alpha, sigma, proof)
}
