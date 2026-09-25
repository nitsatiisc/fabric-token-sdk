/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	"encoding/binary"
	"math/bits"

	mathlib "github.com/IBM/mathlib"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/rp/csp"
	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/sumcheck"
)

// Efficient group sum-check
//
// This is an *additional* primitive alongside crypto/sumcheck, not a replacement
// for it. It proves only one shape of claim, and only for a group polynomial:
//
//	sum_{x in {0,1}^m} eq(alpha, x) * f(x) = sigma,   f in G[X], sigma in G
//
// which is exactly an evaluation claim, sigma = f(alpha). The general sum-check in
// crypto/sumcheck stays the general primitive; this one exists because the Titan
// evaluation protocol needs precisely this shape, and the specialisation is what
// buys the speedup. A caller with any other claim wants crypto/sumcheck.
//
// Why it is faster. Naive group sum-check costs O(n) group exponentiations. Here
// the eq factor is known in advance, so with ell = m/2 the prover can precompute
// partial sums over suffixes
//
//	S_i(b) = sum_{x in {0,1}^(m-i)} h(b, x),      h(x) = eq(alpha, x) * f(x)
//
// for every prefix b in {0,1}^i. S_ell costs 2^ell multi-exponentiations of size
// 2^ell, and each lower table follows by S_(i-1)(b) = S_i(b,0) + S_i(b,1), which
// is group *additions* — about 137x cheaper than scalar multiplications on this
// curve. Rounds i <= ell then read their message straight off S_i with one MSM of
// size O(2^i); rounds past ell run on a polynomial already down to O(sqrt(n)) and
// use the folklore method. Total: sqrt(n) MSMs of size sqrt(n) plus O(sqrt(n))
// group exponentiations, against O(n) exponentiations naive.
//
// Round degree is 2, not 1. The summand h = eq * f is a product of two
// multilinears, so each round message is quadratic and needs three evaluations.
// This package sends g_i(0), g_i(1), g_i(2).

// numRoundEvals is the number of evaluations per round message. The summand
// eq*f is a product of two multilinears, hence quadratic in the round variable,
// and three points determine a quadratic.
const numRoundEvals = 3

// GroupSumCheckProof is a non-interactive proof for the evaluation claim
//
//	sum_x eq(alpha, x) * f(x) = sigma.
//
// Rounds holds one message per variable, each the three evaluations
// (g_i(0), g_i(1), g_i(2)) of that round's quadratic.
type GroupSumCheckProof struct {
	// Rounds[i] holds the three evaluations of the round-i message.
	Rounds [][numRoundEvals]bls12381.G1Affine
}

// GroupSumCheckOpening is the residual claim the protocol reduces to.
//
// As with crypto/sumcheck, verification succeeding means the sum *follows from*
// this opening; it does not mean the opening is correct. See VerifyGroupEval.
type GroupSumCheckOpening struct {
	// R is the challenge point, in the order the rounds consumed it: R[0] is the
	// value substituted for the first variable. This is the natural (table) order
	// for this package, because the protocol folds the first variable — unlike
	// crypto/sumcheck's Opening.R, which comes out reversed.
	R []fr.Element

	// Expected is the value the rounds telescope down to, namely
	// eq(alpha, R) * f(R). A caller closes the argument by checking it against
	// f(R) obtained from a commitment opening or oracle query, scaled by the
	// eq factor, which it can compute itself since alpha and R are public.
	Expected bls12381.G1Affine
}

// ProveGroupEval proves that sum_x eq(alpha, x)*f(x) = sigma for a group
// multilinear f, using the partial-sum method described above.
//
// ell selects where the prover switches from the MSM-based rounds to the folklore
// ones; it must be in [0, m]. ell = m/2 is the value the cost analysis is built
// around, and DefaultSplit returns it. The choice is a pure performance knob: the
// proof produced is identical for every ell, which the tests pin down.
//
// sigma is not taken as an argument: it is determined by f and alpha, so the
// prover computes it and returns it. A caller that already believes a value for
// sigma should compare it against the returned one.
//
// alpha must have m entries. On the honest path alpha is derived from a
// transcript, so its coordinates are never exactly 0 or 1; a coordinate that is
// makes eq(alpha_i, .) vanish and the prover returns ErrZeroDenominator rather
// than dividing by zero. That is a defensive error, not a supported input mode —
// Titan reaches this primitive only after sum-check has aggregated any
// boolean-coordinate evaluations into a single random point.
func ProveGroupEval(curve *mathlib.Curve, f sumcheck.GroupPoly, alpha []fr.Element, ell int) (*GroupSumCheckProof, *GroupSumCheckOpening, bls12381.G1Affine, error) {
	var zero bls12381.G1Affine
	if curve == nil {
		return nil, nil, zero, ErrNilCurve
	}
	m, err := checkGroupEvalParams(len(f), f == nil, alpha, ell)
	if err != nil {
		return nil, nil, zero, err
	}

	return ProveGroupEvalWithTranscript(newGroupSumCheckTranscript(curve, m, ell, alpha), curve, f, alpha, ell)
}

// ProveGroupEvalWithTranscript is ProveGroupEval against a caller-supplied
// transcript, which it absorbs into and squeezes from in place.
//
// Titan's folding phase needs its challenges to depend on every sum-check message,
// so the two protocols share one Fiat-Shamir chain rather than opening a second
// one. Passing the transcript in is what makes that possible: ProveGroupEval keeps
// its own transcript private and a caller that needs to continue the chain uses
// this entry point instead.
//
// tr must be positioned exactly as newGroupSumCheckTranscript leaves it -- the
// caller is responsible for the domain separator and for absorbing m, ell and
// alpha. ProveGroupEval does that itself; proveFold reuses the transcript this
// function returns, already advanced past every round message.
func ProveGroupEvalWithTranscript(tr *csp.Transcript, curve *mathlib.Curve, f sumcheck.GroupPoly, alpha []fr.Element, ell int) (*GroupSumCheckProof, *GroupSumCheckOpening, bls12381.G1Affine, error) {
	var sigma bls12381.G1Affine

	if curve == nil {
		return nil, nil, sigma, ErrNilCurve
	}

	m, err := checkGroupEvalParams(len(f), f == nil, alpha, ell)
	if err != nil {
		return nil, nil, sigma, err
	}

	eq := eqTable(alpha)

	// The S tables serve rounds 1..ell. tables[i] is S_(i+1), so tables[ell-1] is
	// S_ell; with ell == 0 there are none and every round is folklore.
	tables, err := computeSTables(f, eq, ell)
	if err != nil {
		return nil, nil, sigma, err
	}

	if tr == nil {
		return nil, nil, sigma, errors.New("cannot prove a group evaluation without a transcript")
	}

	proof := &GroupSumCheckProof{Rounds: make([][numRoundEvals]bls12381.G1Affine, 0, m)}
	challenges := make([]fr.Element, 0, m)

	// State for the folklore rounds: h and eqRest are the restrictions of f and
	// eq at the challenges drawn so far. They are only needed once the MSM rounds
	// are done, so the restriction is deferred until then.
	var hPoly sumcheck.GroupPoly
	var eqRest sumcheck.FieldPoly

	for round := 1; round <= m; round++ {
		var evals [numRoundEvals]bls12381.G1Affine

		if round <= ell {
			evals, err = roundMessageFromTable(tables[round-1], alpha, challenges, round)
			if err != nil {
				return nil, nil, sigma, errors.Wrapf(err, "failed to build round %d from partial sums", round)
			}
		} else {
			if hPoly == nil {
				// Entering the folklore phase: restrict both factors at the
				// challenges consumed so far. Done once, not per round.
				hPoly, eqRest, err = restrictBoth(f, eq, challenges)
				if err != nil {
					return nil, nil, sigma, errors.Wrap(err, "failed to restrict polynomials for the folklore rounds")
				}
			}
			evals, err = roundMessageFolklore(hPoly, eqRest)
			if err != nil {
				return nil, nil, sigma, errors.Wrapf(err, "failed to build round %d", round)
			}
		}

		if round == 1 {
			// The asserted sum is g_1(0) + g_1(1).
			var total bls12381.G1Jac
			total.FromAffine(&evals[0])
			total.AddMixed(&evals[1])
			sigma.FromJacobian(&total)
			absorbPoint(tr, &sigma)
		}

		for i := range evals {
			absorbPoint(tr, &evals[i])
		}
		proof.Rounds = append(proof.Rounds, evals)

		r, err := squeezeScalar(tr)
		if err != nil {
			return nil, nil, sigma, err
		}
		challenges = append(challenges, r)

		if hPoly != nil {
			hPoly, err = foldFirstGroup(hPoly, &r)
			if err != nil {
				return nil, nil, sigma, errors.Wrapf(err, "failed to fold round %d", round)
			}
			eqRest = foldFirstField(eqRest, &r)
		}
	}

	expected, err := interpolateGroupAt(&proof.Rounds[m-1], &challenges[m-1])
	if err != nil {
		return nil, nil, sigma, err
	}

	return proof, &GroupSumCheckOpening{R: challenges, Expected: expected}, sigma, nil
}

// VerifyGroupEval checks a GroupSumCheckProof against the claim
//
//	sum_x eq(alpha, x)*f(x) = sigma
//
// and returns the residual claim.
//
// # This reduces the claim; it does not close it
//
// A nil error means the sum *follows from* the returned opening. It does **not**
// mean the opening is correct: a prover free to choose the residual value can
// prove any sum. The caller must check Expected against something the prover could
// not choose freely — in Titan, f(R) from the WHIR oracle, scaled by the eq(alpha, R)
// factor the verifier computes itself. Omitting that leaves no soundness at all.
// This is the same contract as crypto/sumcheck.Verify.
//
// The verifier does not hold f, so it needs only m, alpha, sigma and the proof.
// It is written from the paper rather than ported: the reference implementation's
// verifier is incomplete (its final evaluation is commented out and its round loop
// runs one round short), so it could not serve as a guide.
func VerifyGroupEval(curve *mathlib.Curve, proof *GroupSumCheckProof, alpha []fr.Element, sigma *bls12381.G1Affine, ell int) (*GroupSumCheckOpening, error) {
	if curve == nil {
		return nil, ErrNilCurve
	}
	m := len(alpha)
	if m == 0 {
		return nil, errors.Wrap(ErrNumVarsMismatch, "alpha must have at least one coordinate")
	}
	if ell < 0 || ell > m {
		return nil, errors.Wrapf(ErrInvalidSplit, "ell is %d, must be in [0, %d]", ell, m)
	}

	return VerifyGroupEvalWithTranscript(newGroupSumCheckTranscript(curve, m, ell, alpha), curve, proof, alpha, sigma, ell)
}

// VerifyGroupEvalWithTranscript is VerifyGroupEval against a caller-supplied
// transcript, which it absorbs into and squeezes from in place.
//
// This is the verifier's half of the transcript threading described on
// ProveGroupEvalWithTranscript: the folding phase continues the same Fiat-Shamir
// chain, so verifyFold needs the transcript this function leaves behind, advanced
// past every round message and positioned identically to the prover's.
//
// tr must be positioned exactly as newGroupSumCheckTranscript leaves it.
func VerifyGroupEvalWithTranscript(tr *csp.Transcript, curve *mathlib.Curve, proof *GroupSumCheckProof, alpha []fr.Element, sigma *bls12381.G1Affine, ell int) (*GroupSumCheckOpening, error) {
	if curve == nil {
		return nil, ErrNilCurve
	}
	if proof == nil {
		return nil, ErrNilProof
	}
	if sigma == nil {
		return nil, errors.Wrap(ErrNilElement, "sigma is required")
	}
	m := len(alpha)
	if m == 0 {
		return nil, errors.Wrap(ErrNumVarsMismatch, "alpha must have at least one coordinate")
	}
	if ell < 0 || ell > m {
		return nil, errors.Wrapf(ErrInvalidSplit, "ell is %d, must be in [0, %d]", ell, m)
	}
	if len(proof.Rounds) != m {
		return nil, errors.Wrapf(ErrRoundCountMismatch, "proof has %d rounds, expected %d", len(proof.Rounds), m)
	}

	if tr == nil {
		return nil, errors.New("cannot verify a group evaluation without a transcript")
	}

	// expected is the value the current round must sum to: sigma in round 1, and
	// the previous round's message interpolated at the previous challenge after.
	expected := *sigma
	challenges := make([]fr.Element, 0, m)

	for round := 1; round <= m; round++ {
		evals := proof.Rounds[round-1]

		if round == 1 {
			absorbPoint(tr, sigma)
		}

		// g_i(0) + g_i(1) must equal the expected value.
		var got bls12381.G1Jac
		got.FromAffine(&evals[0])
		got.AddMixed(&evals[1])
		var gotAff bls12381.G1Affine
		gotAff.FromJacobian(&got)
		if !gotAff.Equal(&expected) {
			if round == 1 {
				return nil, errors.Wrapf(ErrSumMismatch, "round 1: g(0)+g(1) does not equal sigma")
			}

			return nil, errors.Wrapf(ErrRoundCheckFailed, "round %d: g(0)+g(1) does not equal the previous round's value", round)
		}

		for i := range evals {
			absorbPoint(tr, &evals[i])
		}

		r, err := squeezeScalar(tr)
		if err != nil {
			return nil, err
		}
		challenges = append(challenges, r)

		expected, err = interpolateGroupAt(&evals, &r)
		if err != nil {
			return nil, err
		}
	}

	return &GroupSumCheckOpening{R: challenges, Expected: expected}, nil
}

// DefaultSplit returns the split point the cost analysis is built around,
// ell = m/2, at which the prover does sqrt(n) MSMs of size sqrt(n).
func DefaultSplit(m int) int { return m / 2 }

// computeSTables returns the partial-sum tables S_1 .. S_ell, with the result
// indexed so that out[i-1] is S_i.
//
// S_ell is computed first, as 2^ell multi-exponentiations of size 2^(m-ell): the
// slice for a given prefix b is strided in the natural layout, so both the f and
// eq tables are transposed once up front to make each slice contiguous and let a
// single MSM call cover it. Each lower table then follows by adding the two halves
// of the one above, which costs group additions only.
//
// Returns an empty slice when ell == 0.
func computeSTables(f sumcheck.GroupPoly, eq sumcheck.FieldPoly, ell int) ([]sumcheck.GroupPoly, error) {
	if ell == 0 {
		return nil, nil
	}
	m := bits.Len(uint(len(f))) - 1
	numPrefixes := 1 << ell     // number of b values
	sliceSize := 1 << (m - ell) // number of x values per b

	// Transpose so that the sliceSize entries sharing a prefix b are contiguous.
	// In the little-endian layout the prefix b occupies the LOW bits of the index,
	// so entry (x, b) sits at x*numPrefixes + b and the slice for b is strided.
	fT := make([]bls12381.G1Affine, len(f))
	eqT := make([]fr.Element, len(eq))
	for b := range numPrefixes {
		for x := range sliceSize {
			fT[b*sliceSize+x] = f[x*numPrefixes+b]
			eqT[b*sliceSize+x] = eq[x*numPrefixes+b]
		}
	}

	sl := make(sumcheck.GroupPoly, numPrefixes)
	for b := range numPrefixes {
		lo := b * sliceSize
		hi := lo + sliceSize
		v, err := msm(fT[lo:hi], eqT[lo:hi])
		if err != nil {
			return nil, errors.Wrapf(err, "failed to compute S_%d at prefix %d", ell, b)
		}
		sl[b] = v
	}

	out := make([]sumcheck.GroupPoly, ell)
	out[ell-1] = sl
	// S_(i-1)(b) = S_i(b,0) + S_i(b,1). The newest variable is the HIGH bit of
	// the S_i index, so the two halves to add are the bottom and top of the table.
	for i := ell - 1; i >= 1; i-- {
		above := out[i]
		half := len(above) / 2
		cur := make(sumcheck.GroupPoly, half)
		for b := range half {
			var acc bls12381.G1Jac
			acc.FromAffine(&above[b])
			acc.AddMixed(&above[b+half])
			cur[b].FromJacobian(&acc)
		}
		out[i-1] = cur
	}

	return out, nil
}

// roundMessageFromTable computes the three evaluations of the round-i message
// from the partial-sum table S_i, following the paper's identity
//
//	g_i(u) = sum_{b in {0,1}^i} [ eq(z,b) * eq(z, alpha_i) / eq(alpha_i, b) ] * S_i(b)
//
// with z = (rho, u) the challenges so far with u appended.
//
// The u-dependent part is isolated so the three evaluations share the MSM work:
// splitting S_i at its newest variable into S_i(b,0) and S_i(b,1) gives two MSMs
// H0 and H1 of size 2^(i-1) that do not depend on u, after which each g_i(u) is
// just two scalar multiplications. That is an optimisation from the reference
// implementation rather than the paper text, and it is worth keeping: it turns
// three MSMs per round into two.
func roundMessageFromTable(si sumcheck.GroupPoly, alpha, rho []fr.Element, round int) ([numRoundEvals]bls12381.G1Affine, error) {
	var out [numRoundEvals]bls12381.G1Affine

	if len(si) != 1<<round {
		return out, errors.Wrapf(ErrNumVarsMismatch, "S_%d has %d entries, expected %d", round, len(si), 1<<round)
	}
	if len(rho) != round-1 {
		return out, errors.Wrapf(ErrNumVarsMismatch, "round %d needs %d prior challenges, got %d", round, round-1, len(rho))
	}

	half := 1 << (round - 1)
	alphaPrefix := alpha[:round-1] // alpha_(i-1) in the write-up
	aRound := alpha[round-1]       // alpha_i

	// scalars[b] = eq(rho, b) / eq(alphaPrefix, b), independent of u.
	numerators := eqTable(rho)
	denominators, err := batchInvert(eqTable(alphaPrefix))
	if err != nil {
		return out, errors.Wrapf(err, "round %d: eq(alpha_%d, .) is not invertible", round, round-1)
	}
	scalars := make([]fr.Element, half)
	for b := range half {
		scalars[b].Mul(&numerators[b], &denominators[b])
	}

	h0, err := msm(si[:half], scalars)
	if err != nil {
		return out, errors.Wrapf(err, "round %d: H0", round)
	}
	h1, err := msm(si[half:], scalars)
	if err != nil {
		return out, errors.Wrapf(err, "round %d: H1", round)
	}

	one := fr.One()
	var oneMinusA fr.Element
	oneMinusA.Sub(&one, &aRound)
	if aRound.IsZero() || oneMinusA.IsZero() {
		return out, errors.Wrapf(ErrZeroDenominator, "round %d: alpha coordinate is 0 or 1", round)
	}
	var aInv, oneMinusAInv fr.Element
	aInv.Inverse(&aRound)
	oneMinusAInv.Inverse(&oneMinusA)

	// eqPrefix = eq(rho, alpha_(i-1)), the u-independent part of eq(z, alpha_i).
	eqPrefix, err := eqPoint(rho, alphaPrefix)
	if err != nil {
		return out, errors.Wrapf(err, "round %d: eq(rho, alpha prefix)", round)
	}

	for j := range numRoundEvals {
		var u fr.Element
		u.SetUint64(uint64(j))

		// K = eq(z, alpha_i) = eq(rho, alpha_(i-1)) * (u*alpha_i + (1-u)*(1-alpha_i))
		var oneMinusU, t0, t1, k fr.Element
		oneMinusU.Sub(&one, &u)
		t0.Mul(&u, &aRound)
		t1.Mul(&oneMinusU, &oneMinusA)
		k.Add(&t0, &t1)
		k.Mul(&k, &eqPrefix)

		// left = K*(1-u)/(1-alpha_i), right = K*u/alpha_i
		var left, right fr.Element
		left.Mul(&oneMinusU, &oneMinusAInv)
		left.Mul(&left, &k)
		right.Mul(&u, &aInv)
		right.Mul(&right, &k)

		v, err := msm([]bls12381.G1Affine{h0, h1}, []fr.Element{left, right})
		if err != nil {
			return out, errors.Wrapf(err, "round %d: combining H0 and H1 at u=%d", round, j)
		}
		out[j] = v
	}

	return out, nil
}

// roundMessageFolklore computes the round message the usual way, from the
// restricted polynomials directly. It is used once the polynomial is down to
// O(sqrt(n)) entries, where the partial-sum machinery no longer pays for itself.
//
// With h the group factor and e the eq factor, both multilinear in the first
// variable, the message is
//
//	g(u) = sum_x [ (1-u)e(0,x) + u*e(1,x) ] * [ (1-u)h(0,x) + u*h(1,x) ]
//
// Expanding gives four u-independent inner products over the even/odd slices, and
// each g(u) is a fixed combination of them: g(0) = <e0,h0>, g(1) = <e1,h1>, and
// g(2) = <e0,h0> - 2<e0,h1> - 2<e1,h0> + 4<e1,h1>.
func roundMessageFolklore(h sumcheck.GroupPoly, e sumcheck.FieldPoly) ([numRoundEvals]bls12381.G1Affine, error) {
	var out [numRoundEvals]bls12381.G1Affine

	if len(h) != len(e) {
		return out, errors.Wrapf(ErrNumVarsMismatch, "group factor has %d entries, eq factor %d", len(h), len(e))
	}
	if len(h) < 2 {
		return out, errors.Wrap(ErrNumVarsMismatch, "folklore round needs at least two entries")
	}

	half := len(h) / 2
	hEven := make([]bls12381.G1Affine, half)
	hOdd := make([]bls12381.G1Affine, half)
	eEven := make([]fr.Element, half)
	eOdd := make([]fr.Element, half)
	for i := range half {
		hEven[i] = h[2*i]
		hOdd[i] = h[2*i+1]
		eEven[i] = e[2*i]
		eOdd[i] = e[2*i+1]
	}

	s00, err := msm(hEven, eEven)
	if err != nil {
		return out, err
	}
	s01, err := msm(hOdd, eEven)
	if err != nil {
		return out, err
	}
	s10, err := msm(hEven, eOdd)
	if err != nil {
		return out, err
	}
	s11, err := msm(hOdd, eOdd)
	if err != nil {
		return out, err
	}

	out[0] = s00
	out[1] = s11

	// g(2) = s00 - 2*s01 - 2*s10 + 4*s11
	var acc bls12381.G1Jac
	acc.FromAffine(&s00)
	var negS01, negS10 bls12381.G1Affine
	negS01.Neg(&s01)
	negS10.Neg(&s10)
	acc.AddMixed(&negS01)
	acc.AddMixed(&negS01)
	acc.AddMixed(&negS10)
	acc.AddMixed(&negS10)
	acc.AddMixed(&s11)
	acc.AddMixed(&s11)
	acc.AddMixed(&s11)
	acc.AddMixed(&s11)
	out[2].FromJacobian(&acc)

	return out, nil
}

// restrictBoth returns the restrictions f(rho, .) and eq(rho, .), substituting the
// challenges rho for the leading len(rho) variables of each.
//
// This is called once, on entering the folklore phase, rather than per round.
//
// # Why this is a batch of MSMs rather than repeated folding
//
// The obvious implementation folds one variable at a time, len(rho) times. That is
// correct but it is the single most expensive thing the prover could do: each fold
// is a full pass of scalar multiplications over a table that starts at 2^m entries,
// and it dominates every other phase combined. Measured at m=12 it cost 221ms,
// against 3ms for all the partial-sum round messages put together — enough to
// erase the entire speedup the partial-sum tables exist to provide, making the
// choice of ell look irrelevant.
//
// Instead, restriction is a single contraction against the eq(rho, .) table:
//
//	f(rho, y) = sum_{b in {0,1}^|rho|} eq(rho, b) * f(b, y)
//
// so each of the 2^(m-|rho|) surviving entries is one inner product of length
// 2^|rho|. The total number of scalar multiplications is the same, but they are
// batched into MSMs, so Pippenger amortizes the window precomputation across each
// slice instead of paying it per point. At m=12, ell=6 this takes the prover from
// 250ms to 30ms.
//
// No transpose is needed here, unlike in computeSTables. Folding the first variable
// repeatedly consumes rho in order, which makes the consumed prefix b the low bits
// *within* each contiguous block of sliceSize entries, so f[y*sliceSize : (y+1)*sliceSize]
// is already exactly the slice to contract. computeSTables needs a transpose because
// there it is the surviving suffix, not the prefix, that is strided.
func restrictBoth(f sumcheck.GroupPoly, eq sumcheck.FieldPoly, rho []fr.Element) (sumcheck.GroupPoly, sumcheck.FieldPoly, error) {
	if len(rho) == 0 {
		h := make(sumcheck.GroupPoly, len(f))
		copy(h, f)
		e := make(sumcheck.FieldPoly, len(eq))
		copy(e, eq)

		return h, e, nil
	}

	sliceSize := 1 << len(rho) // number of b values
	outSize := len(f) / sliceSize

	// Contract the group factor against eq(rho, .), one MSM per surviving entry.
	rhoEq := eqTable(rho)
	h := make(sumcheck.GroupPoly, outSize)
	for y := range outSize {
		v, err := msm(f[y*sliceSize:(y+1)*sliceSize], rhoEq)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "failed to restrict the group factor at entry %d", y)
		}
		h[y] = v
	}

	// The eq factor is scalar, so folding it is cheap and there is nothing to
	// batch; field multiplications are not the bottleneck.
	e := make(sumcheck.FieldPoly, len(eq))
	copy(e, eq)
	for i := range rho {
		e = foldFirstField(e, &rho[i])
	}

	return h, e, nil
}

// interpolateGroupAt evaluates, at x, the quadratic through
// (0, evals[0]), (1, evals[1]), (2, evals[2]).
//
// In Lagrange form on the nodes {0,1,2}:
//
//	g(x) = evals[0]*(x-1)(x-2)/2 - evals[1]*x(x-2) + evals[2]*x(x-1)/2
func interpolateGroupAt(evals *[numRoundEvals]bls12381.G1Affine, x *fr.Element) (bls12381.G1Affine, error) {
	one := fr.One()
	var two fr.Element
	two.SetUint64(2)
	var twoInv fr.Element
	twoInv.Inverse(&two)

	var xm1, xm2 fr.Element
	xm1.Sub(x, &one)
	xm2.Sub(x, &two)

	// c0 = (x-1)(x-2)/2
	var c0 fr.Element
	c0.Mul(&xm1, &xm2)
	c0.Mul(&c0, &twoInv)

	// c1 = -x(x-2) = x(2-x)
	var c1 fr.Element
	c1.Sub(&two, x)
	c1.Mul(&c1, x)

	// c2 = x(x-1)/2
	var c2 fr.Element
	c2.Mul(x, &xm1)
	c2.Mul(&c2, &twoInv)

	return msm([]bls12381.G1Affine{evals[0], evals[1], evals[2]}, []fr.Element{c0, c1, c2})
}

// checkGroupEvalParams validates the prover's inputs and returns m.
func checkGroupEvalParams(length int, isNil bool, alpha []fr.Element, ell int) (int, error) {
	if isNil || length == 0 {
		return 0, ErrNilPolynomial
	}
	if !isPowerOfTwo(length) {
		return 0, errors.Wrapf(ErrNotPowerOfTwo, "evaluation table has %d entries", length)
	}
	m := bits.Len(uint(length)) - 1
	if len(alpha) != m {
		return 0, errors.Wrapf(ErrNumVarsMismatch, "polynomial has %d variables, alpha has %d coordinates", m, len(alpha))
	}
	if ell < 0 || ell > m {
		return 0, errors.Wrapf(ErrInvalidSplit, "ell is %d, must be in [0, %d]", ell, m)
	}

	return m, nil
}

// DomainSeparator is the Fiat-Shamir domain separator for the group sum-check.
//
// It is distinct from crypto/sumcheck's, so a proof for one protocol can never be
// replayed as a proof for the other even where the two happen to agree on the
// number of rounds and the message shape.
const DomainSeparator = "TitanGroupSumCheck-v1"

// newGroupSumCheckTranscript builds a transcript bound to this protocol's domain
// separator and to the public parameters of the claim: the number of variables, the
// split point, and the evaluation point alpha.
//
// ell is bound even though it is only a performance knob, because the two sides
// must agree on it to agree on the challenges, and because binding it is free.
//
// m and ell are absorbed as 32-bit big-endian rather than as single bytes: a byte
// each would alias (m, ell) pairs 256 apart, and while nothing in this package
// reaches m = 256 today, a transcript that silently collides on its public
// parameters is the kind of latent break that is much cheaper to prevent than to
// find.
func newGroupSumCheckTranscript(curve *mathlib.Curve, m, ell int, alpha []fr.Element) *csp.Transcript {
	tr := &csp.Transcript{Curve: curve}
	tr.InitHasherWithDomain(DomainSeparator)
	var params [8]byte
	binary.BigEndian.PutUint32(params[0:4], uint32(m))
	binary.BigEndian.PutUint32(params[4:8], uint32(ell))
	tr.Absorb(params[:])
	for i := range alpha {
		b := alpha[i].Bytes()
		tr.Absorb(b[:])
	}

	return tr
}

// absorbPoint feeds a group element into the transcript in its compressed form.
func absorbPoint(tr *csp.Transcript, p *bls12381.G1Affine) {
	b := p.Bytes()
	tr.Absorb(b[:])
}

// squeezeScalar draws the next challenge as an fr.Element.
//
// csp.Transcript.Squeeze returns a *mathlib.Zr, so there is one conversion per
// round. At m rounds that is negligible, and keeping the Fiat-Shamir bytes
// identical to the CSP construction matters more than saving it — the same
// trade-off crypto/sumcheck makes.
func squeezeScalar(tr *csp.Transcript) (fr.Element, error) {
	var out fr.Element
	z, err := tr.Squeeze()
	if err != nil {
		return out, errors.Wrap(err, "failed to squeeze group sum-check challenge")
	}
	out.SetBytes(z.Bytes())

	return out, nil
}
