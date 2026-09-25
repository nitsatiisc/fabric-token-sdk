/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/rp/csp"
	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/sumcheck"
)

// CosetOpening is one consistency query: a coset of the committed oracle, with the
// authentication path proving it lies under the committed root.
type CosetOpening struct {
	// Index is the folded-domain point whose coset this is.
	Index int

	// Leaf holds the 2^Ell points of the coset, in the order EncodeCosets produced
	// them -- Leaf[b] = G(b, powers(y)). The order is load bearing: foldCoset pairs
	// Leaf[b] with eq(r)[b], so a permuted leaf folds to a different value.
	Leaf []bls12381.G1Affine

	// Path is the Merkle authentication path for Leaf at Index.
	Path *MerkleProof
}

// FoldProof is the WHIR folding phase: what turns a reduced sum-check claim into a
// claim the verifier can check against the committed oracle.
//
// # Why this exists
//
// VerifyGroupEval reduces "sum_x eq(alpha,x) f(x) = sigma" to a claim about f at a
// random point. It does not close it: a prover free to choose the residual value
// proves any sum. FoldProof is what makes the residual claim binding.
//
// # Shape
//
// Ell rounds of sum-check fold the first Ell variables away. The remaining
// 2^(m-Ell) coefficients are then sent in plain, because at that size sending them
// is cheaper than continuing to fold, and a plain polynomial can be checked
// directly: the verifier computes the residual claim itself as a dot product with
// an eq table. Queries tie that plain polynomial back to the oracle committed
// before any challenge was drawn.
type FoldProof struct {
	// Rounds holds one sum-check message per folding round, Ell in total.
	Rounds [][numRoundEvals]bls12381.G1Affine

	// Reduced is the folded polynomial in plain, 2^(m-Ell) coefficients.
	Reduced sumcheck.GroupPoly

	// Queries holds the consistency openings, one per sampled index.
	Queries []*CosetOpening
}

// proveFold runs the folding phase over the oracle h commits to.
//
// claim is the value the folding rounds must sum to -- in Titan, the residual
// claim ProveGroupEval left. alphaRest is the eq point for the variables the
// folding operates on, so the round messages are messages for
// "sum_x eq(alphaRest, x) * G(x)".
//
// tr is advanced in place. It must be the transcript ProveGroupEvalWithTranscript
// returned, so the fold challenges depend on every sum-check message; see
// ProveGroupEvalWithTranscript for why a fresh transcript would be the wrong
// shape.
func proveFold(
	tr *csp.Transcript,
	G sumcheck.GroupPoly,
	h *CosetOpeningHint,
	cfg FoldConfig,
	alphaRest []fr.Element,
	claim *bls12381.G1Affine,
) (*FoldProof, error) {
	if tr == nil {
		return nil, errors.New("cannot prove a fold without a transcript")
	}
	if h == nil || h.Tree == nil || h.Folded == nil {
		return nil, errors.WithMessage(ErrNilTree, "cannot prove a fold without an oracle")
	}
	if claim == nil {
		return nil, errors.Wrap(ErrNilElement, "the folding claim is required")
	}
	m, err := numVarsOf(len(G))
	if err != nil {
		return nil, err
	}
	if err := cfg.Validate(m); err != nil {
		return nil, err
	}
	if len(alphaRest) != m {
		return nil, errors.Wrapf(ErrNumVarsMismatch,
			"polynomial has %d variables, alphaRest has %d coordinates", m, len(alphaRest))
	}

	proof := &FoldProof{Rounds: make([][numRoundEvals]bls12381.G1Affine, 0, cfg.Ell)}

	// cur is G restricted at the challenges drawn so far; eqCur is eq(alphaRest, .)
	// restricted the same way. Both bind the FIRST variable each round, matching
	// EncodeCosets' slice indexing -- the first Ell variables are the low index
	// bits, and the coset identity foldCoset(leaf, eq(r)) == reduced codeword is
	// pinned against exactly this order in TestFoldCosetMatchesReducedCodeword.
	cur := G
	eqCur := eqTable(alphaRest)
	challenges := make([]fr.Element, 0, cfg.Ell)

	absorbPoint(tr, claim)

	for round := range cfg.Ell {
		evals, err := foldRoundMessage(cur, eqCur)
		if err != nil {
			return nil, errors.WithMessagef(err, "fold round %d", round+1)
		}
		for i := range evals {
			absorbPoint(tr, &evals[i])
		}
		proof.Rounds = append(proof.Rounds, evals)

		r, err := squeezeScalar(tr)
		if err != nil {
			return nil, errors.WithMessagef(err, "fold round %d challenge", round+1)
		}
		challenges = append(challenges, r)

		if cur, err = foldFirstGroup(cur, &r); err != nil {
			return nil, errors.WithMessagef(err, "fold round %d", round+1)
		}
		eqCur = foldFirstField(eqCur, &r)
	}

	proof.Reduced = cur

	// The reduced polynomial goes into the transcript before the query indices are
	// drawn. Otherwise a prover could see the indices first and choose the
	// coefficients to satisfy exactly those cosets.
	for i := range proof.Reduced {
		absorbPoint(tr, &proof.Reduced[i])
	}

	indices, err := sampleQueryIndices(tr, h.Folded.Size(), cfg.Queries)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to sample consistency queries")
	}

	proof.Queries = make([]*CosetOpening, 0, len(indices))
	for _, idx := range indices {
		leaf, path, err := h.OpenCoset(idx)
		if err != nil {
			return nil, errors.WithMessagef(err, "failed to open coset %d", idx)
		}
		// OpenCoset returns the hint's own slice; the proof must not alias prover
		// state that a later commitment could reuse.
		cp := make([]bls12381.G1Affine, len(leaf))
		copy(cp, leaf)
		proof.Queries = append(proof.Queries, &CosetOpening{Index: idx, Leaf: cp, Path: path})
	}

	// Absorb every opened point, mirroring the verifier so the two transcripts stay
	// in lockstep. The prover has nothing to check and never derives the batching
	// challenge itself; see verifyFold on why the openings are bound by the Merkle
	// root rather than by this absorb.
	for _, q := range proof.Queries {
		for i := range q.Leaf {
			absorbPoint(tr, &q.Leaf[i])
		}
	}

	return proof, nil
}

// verifyFold checks a FoldProof against the committed oracle.
//
// It performs three checks, and all three are needed:
//
//  1. The Ell folding rounds are internally consistent with claim, as in any
//     sum-check.
//  2. The reduced polynomial, in plain, opens to the value the rounds left. This
//     is a dot product with an eq table the verifier builds itself, so the prover
//     cannot choose it.
//  3. Each sampled coset lies under the committed root and folds to the reduced
//     polynomial's codeword at that point.
//
// Check 3 is the one that closes the gap. Without it, checks 1 and 2 are
// satisfiable by a prover who ran the whole folding phase over a polynomial other
// than the one committed -- see TestFoldRejectsALyingProver.
//
// tr is advanced in place and must be positioned as
// VerifyGroupEvalWithTranscript left it.
func verifyFold(
	tr *csp.Transcript,
	c *CosetCommitment,
	cfg FoldConfig,
	alphaRest []fr.Element,
	claim *bls12381.G1Affine,
	proof *FoldProof,
) error {
	if tr == nil {
		return errors.New("cannot verify a fold without a transcript")
	}
	if c == nil {
		return errors.Wrap(ErrNilProof, "the coset commitment is required")
	}
	if proof == nil {
		return ErrNilProof
	}
	if claim == nil {
		return errors.Wrap(ErrNilElement, "the folding claim is required")
	}
	m := c.NumVars
	if err := cfg.Validate(m); err != nil {
		return err
	}
	if cfg.Ell != c.Ell {
		return errors.Wrapf(ErrInvalidFoldConfig,
			"configuration folds %d rounds but the oracle commits cosets of dimension %d", cfg.Ell, c.Ell)
	}
	if len(alphaRest) != m {
		return errors.Wrapf(ErrNumVarsMismatch,
			"oracle has %d variables, alphaRest has %d coordinates", m, len(alphaRest))
	}
	if len(proof.Rounds) != cfg.Ell {
		return errors.Wrapf(ErrFoldRoundMismatch,
			"proof has %d rounds, expected %d", len(proof.Rounds), cfg.Ell)
	}
	if len(proof.Reduced) != 1<<(m-cfg.Ell) {
		return errors.Wrapf(ErrReducedPolyMismatch,
			"reduced polynomial has %d coefficients, expected %d", len(proof.Reduced), 1<<(m-cfg.Ell))
	}
	if len(proof.Queries) != cfg.Queries {
		return errors.Wrapf(ErrQueryCountMismatch,
			"proof carries %d queries, configuration requires %d", len(proof.Queries), cfg.Queries)
	}

	folded, err := NewDomain(c.LogDomain)
	if err != nil {
		return errors.WithMessage(err, "failed to rebuild the folded domain")
	}

	absorbPoint(tr, claim)

	// Check 1: the folding rounds.
	expected := *claim
	eqCur := eqTable(alphaRest)
	challenges := make([]fr.Element, 0, cfg.Ell)

	for round := range cfg.Ell {
		evals := proof.Rounds[round]

		// g(0) + g(1) must equal what the previous round left.
		var got bls12381.G1Jac
		got.FromAffine(&evals[0])
		got.AddMixed(&evals[1])
		var gotAff bls12381.G1Affine
		gotAff.FromJacobian(&got)
		if !gotAff.Equal(&expected) {
			return errors.Wrapf(ErrFoldRoundMismatch, "round %d does not sum to the previous claim", round+1)
		}

		for i := range evals {
			absorbPoint(tr, &evals[i])
		}

		r, err := squeezeScalar(tr)
		if err != nil {
			return errors.WithMessagef(err, "fold round %d challenge", round+1)
		}
		challenges = append(challenges, r)

		if expected, err = interpolateGroupAt(&evals, &r); err != nil {
			return errors.WithMessagef(err, "fold round %d interpolation", round+1)
		}
		eqCur = foldFirstField(eqCur, &r)
	}

	for i := range proof.Reduced {
		absorbPoint(tr, &proof.Reduced[i])
	}

	// Check 2: the reduced polynomial opens to the residual claim. eqCur is
	// eq(alphaRest, .) restricted at the same challenges, so this is the same dot
	// product the honest prover's remaining rounds would have computed.
	got, err := msm(proof.Reduced, eqCur)
	if err != nil {
		return errors.WithMessage(err, "failed to evaluate the reduced claim")
	}
	if !got.Equal(&expected) {
		return ErrReducedClaimMismatch
	}

	// Check 3: the reduced polynomial is the fold of the COMMITTED oracle, not of
	// some other polynomial that happens to satisfy checks 1 and 2.
	//
	// The codeword is evaluated only at the queried points. Encoding the whole
	// folded domain here would make the verifier linear in the polynomial size and,
	// measured, slower than its own prover -- see EncodeGroupOracleAt.
	indices, err := sampleQueryIndices(tr, folded.Size(), cfg.Queries)
	if err != nil {
		return errors.WithMessage(err, "failed to sample consistency queries")
	}

	// The structural checks stay per query: they are cheap next to the group
	// operations, and each one can name the query that failed. Only the two MSMs
	// are batched, below.
	cosetSize := cfg.CosetSize()
	leaves := make([]bls12381.G1Affine, 0, cfg.Queries*cosetSize)

	for i, idx := range indices {
		q := proof.Queries[i]
		if q == nil {
			return errors.Wrapf(ErrCosetOpeningInvalid, "query %d is nil", i)
		}
		// The prover does not choose which cosets to open. Comparing against the
		// locally sampled index is what enforces that; accepting q.Index would let
		// a prover open only the cosets it had fixed up.
		if q.Index != idx {
			return errors.Wrapf(ErrCosetOpeningInvalid,
				"query %d opens coset %d, transcript requires %d", i, q.Index, idx)
		}
		if len(q.Leaf) != cosetSize {
			return errors.Wrapf(ErrCosetOpeningInvalid,
				"query %d holds %d points, expected %d", i, len(q.Leaf), cosetSize)
		}
		if !VerifyMerkleProof(c.Root, q.Leaf, q.Path) {
			return errors.Wrapf(ErrCosetOpeningInvalid, "query %d is not under the committed root", i)
		}

		leaves = append(leaves, q.Leaf...)
	}

	// The batching challenge.
	//
	// The usual hazard with batched verification is a prover who learns the
	// combining challenge before choosing what to open, and can then satisfy the
	// combined equation while individual queries fail. That is not reachable here,
	// and it is worth being precise about why rather than relying on absorb
	// ordering: gamma is squeezed only on this side, the prover never derives it,
	// and everything it could adapt is already pinned. The cosets are bound by
	// c.Root, fixed at commit time and long before this proof existed; the indices
	// come from the transcript, not the prover; and proof.Reduced was absorbed above
	// before those indices were drawn.
	//
	// Mutation-checked, and it corrected an earlier comment here that claimed the
	// absorb-then-squeeze order was itself load bearing: moving the squeeze before
	// the absorb leaves the whole suite green, because it changes only gamma's value
	// and the prover cannot see gamma either way. The absorb is retained because it
	// keeps gamma a function of the openings actually presented -- cheap insurance
	// against a future change that lets a prover pick cosets after seeing gamma --
	// but it is not what makes this sound today.
	for i := range leaves {
		absorbPoint(tr, &leaves[i])
	}
	gamma, err := squeezeScalar(tr)
	if err != nil {
		return errors.WithMessage(err, "failed to squeeze the batching challenge")
	}

	// gamma^0 .. gamma^(Q-1), computed once and used on BOTH sides. Deriving them
	// twice would be two places for the two sides to drift apart.
	//
	// The WEIGHTING is also defence in depth here, which is worth recording because
	// it is surprising. Replacing every power with 1 -- an unweighted sum, which
	// normally accepts any set of per-query errors that cancels -- leaves the suite
	// green, and that is correct rather than a missing test. Cancelling errors have
	// nowhere to live: the cosets are hashed whole into the Merkle leaves, and
	// proof.Reduced, though sent in plain, is absorbed before the query indices are
	// drawn, so perturbing it reshuffles the very eq vectors the perturbation would
	// have to be orthogonal to. Constructing such a perturbation needs a fixed point
	// of the hash; the attempt is written up in docs/crypto/titan.md section 13.7.
	//
	// So the ordering above is the load-bearing part, and gamma insures against a
	// future change that breaks it. TestFoldReducedIsAbsorbedBeforeQueriesAreSampled
	// fails if the absorb is ever moved after sampleQueryIndices, which is exactly
	// when the weighting would stop being redundant.
	gammaPow := make([]fr.Element, cfg.Queries)
	gammaPow[0].SetOne()
	for i := 1; i < cfg.Queries; i++ {
		gammaPow[i].Mul(&gammaPow[i-1], &gamma)
	}

	// Left side: one MSM over the CONCATENATED cosets. The eq(r) scalars are shared
	// across queries and the points differ, so batching cannot reduce the point
	// count -- every opened point must be touched. What it buys is a single
	// length-(Q*2^ell) Pippenger instead of Q length-2^ell MSMs, which at these
	// sizes are far too short for the bucket method to pay for itself.
	eqR := eqTable(challenges)
	if len(eqR) != cosetSize {
		return errors.Wrapf(ErrNumVarsMismatch,
			"eq table holds %d entries, cosets hold %d", len(eqR), cosetSize)
	}
	cosetScalars := make([]fr.Element, 0, len(leaves))
	for i := range indices {
		for b := range cosetSize {
			var s fr.Element
			s.Mul(&gammaPow[i], &eqR[b])
			cosetScalars = append(cosetScalars, s)
		}
	}
	cosetSide, err := msm(leaves, cosetScalars)
	if err != nil {
		return errors.WithMessage(err, "failed to fold the opened cosets")
	}

	// Right side: the coefficients are the SAME for every query and only the eq
	// vector changes, so the eq vectors aggregate into one and a single MSM over
	// proof.Reduced replaces Q of them. This is the side that was costing
	// Q*2^(m-ell) group operations.
	combined := make([]fr.Element, len(proof.Reduced))
	for i, idx := range indices {
		eqAt := oracleEqAt(folded, idx, m-cfg.Ell)
		if len(eqAt) != len(combined) {
			return errors.Wrapf(ErrNumVarsMismatch,
				"codeword eq table holds %d entries, reduced polynomial has %d", len(eqAt), len(combined))
		}
		for j := range eqAt {
			var t fr.Element
			t.Mul(&gammaPow[i], &eqAt[j])
			combined[j].Add(&combined[j], &t)
		}
	}
	codewordSide, err := msm(proof.Reduced, combined)
	if err != nil {
		return errors.WithMessage(err, "failed to evaluate the reduced codeword")
	}

	// One verdict for the whole batch. Unlike the per-query form this cannot name
	// which query failed; that is the cost of batching, and the structural checks
	// above still report per query.
	if !cosetSide.Equal(&codewordSide) {
		return errors.Wrap(ErrCosetOpeningInvalid,
			"the opened cosets do not fold to the reduced codeword")
	}

	return nil
}

// foldRoundMessage builds one sum-check round message for
// "sum_x eq(.) * G(x)", evaluated at 0, 1 and 2 in the first variable.
//
// The message is the univariate g(t) = sum_rest eq(t, rest) * G(t, rest). It has
// degree 2 because both eq and G are linear in the variable, so three evaluations
// determine it -- the same shape and the same numRoundEvals as the group
// sum-check's folklore rounds.
func foldRoundMessage(G sumcheck.GroupPoly, eq sumcheck.FieldPoly) ([numRoundEvals]bls12381.G1Affine, error) {
	var out [numRoundEvals]bls12381.G1Affine

	if len(G) != len(eq) {
		return out, errors.Wrapf(ErrNumVarsMismatch,
			"polynomial has %d entries but the eq table has %d", len(G), len(eq))
	}
	if len(G) < 2 {
		return out, errors.Wrap(ErrNotPowerOfTwo, "a fold round needs at least two entries")
	}

	for t := range numRoundEvals {
		var tt fr.Element
		tt.SetUint64(uint64(t))

		// Restrict both at t and take the dot product. Restricting is linear, so
		// this is the honest g(t) rather than an approximation of it.
		gt, err := foldFirstGroup(G, &tt)
		if err != nil {
			return out, err
		}
		eqt := foldFirstField(eq, &tt)

		v, err := msm(gt, eqt)
		if err != nil {
			return out, err
		}
		out[t] = v
	}

	return out, nil
}
