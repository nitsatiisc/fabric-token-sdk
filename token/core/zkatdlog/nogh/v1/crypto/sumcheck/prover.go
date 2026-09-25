/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sumcheck

import (
	mathlib "github.com/IBM/mathlib"
	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/rp/csp"
)

// Opening is the residual claim a sum-check run reduces to, at the single random
// point R.
//
// Sum-check proves only that the original hypercube sum *follows from* this
// residual claim; it does not prove the claim itself. The caller closes the
// argument by checking it against a polynomial commitment opening, an oracle, or a
// direct evaluation of the original polynomials at R.
//
// The prover and the verifier learn different things, so they fill in different
// fields, and which are populated depends on which side produced the Opening:
//
//   - Prove holds the polynomials, so it fills FieldEvals (and GroupEval), the
//     individual factor values f_i(R) and g_1(R).
//   - Verify never sees the polynomials. All it can derive is the single value the
//     rounds telescope down to, namely the whole product p(R), which it reports in
//     Product (field-only claims) or GroupEval (claims with a group factor). It
//     cannot split that product into per-factor values, so FieldEvals is nil.
//
// A caller closing the argument therefore compares Verify's Product against the
// product of the factor values it obtains from its commitment scheme, rather than
// comparing FieldEvals directly.
type Opening struct {
	// R is the challenge point, one scalar per variable, in the order the rounds
	// consumed them.
	R []*mathlib.Zr

	// FieldEvals holds f_i(R) for each field factor, in the claim's order. It is
	// set by Prove and is nil in an Opening returned by Verify.
	FieldEvals []*mathlib.Zr

	// GroupEval holds g_1(R) for a claim with a group factor, and is nil for a
	// field-only claim. Both Prove and Verify set it: for the verifier it is the
	// full product p(R), which for a group claim is a group element.
	GroupEval *mathlib.G1

	// Product holds p(R), the value of the whole product at R, for a field-only
	// claim. It is set by Verify. Prove leaves it nil, since a prover that wants it
	// can multiply FieldEvals.
	Product *mathlib.Zr
}

// Prove runs the sum-check prover over the claim.
//
// It returns the proof and the residual Opening at the challenge point. The
// claim's polynomials are not modified: Prove folds a deep copy.
func Prove(curve *mathlib.Curve, claim *Claim) (*Proof, *Opening, error) {
	if curve == nil {
		return nil, nil, ErrNilCurve
	}
	if claim == nil {
		return nil, nil, ErrNilPolynomial
	}
	if err := claim.validate(); err != nil {
		return nil, nil, err
	}

	tr := newTranscript(curve, claim.NumVars(), claim.Degree(), claim.IsGroup())

	return proveWith(curve, claim, tr)
}

// ProveWithTranscript is Prove with a caller-supplied transcript, for composing
// sum-check into a larger proof system.
//
// The transcript must already be initialized, and must already carry whatever
// public data the enclosing protocol commits to, including the claim's shape.
// Prove's own domain separation and shape binding are not applied here, so the
// caller owns them. Verification must use VerifyWithTranscript against a
// transcript in the identical state.
func ProveWithTranscript(curve *mathlib.Curve, claim *Claim, tr *csp.Transcript) (*Proof, *Opening, error) {
	if curve == nil {
		return nil, nil, ErrNilCurve
	}
	if claim == nil {
		return nil, nil, ErrNilPolynomial
	}
	if tr == nil {
		return nil, nil, errors.New("transcript cannot be nil")
	}
	if err := claim.validate(); err != nil {
		return nil, nil, err
	}

	return proveWith(curve, claim, tr)
}

// proveWith is the shared prover body. tr must be ready to absorb.
func proveWith(curve *mathlib.Curve, claim *Claim, tr *csp.Transcript) (*Proof, *Opening, error) {
	numVars := claim.NumVars()
	degree := claim.Degree()
	isGroup := claim.IsGroup()

	work := claim.clone()

	proof := &Proof{}
	if isGroup {
		proof.GroupRounds = make([][]*mathlib.G1, 0, numVars)
	} else {
		proof.FieldRounds = make([][]*mathlib.Zr, 0, numVars)
	}

	challenges := make([]*mathlib.Zr, 0, numVars)

	for round := range numVars {
		if isGroup {
			evals, err := groupRoundEvals(work, degree)
			if err != nil {
				return nil, nil, errors.Wrapf(err, "failed to build round %d", round)
			}

			out := make([]*mathlib.G1, len(evals))
			for i := range evals {
				g, err := toG1(curve, &evals[i])
				if err != nil {
					return nil, nil, errors.Wrapf(err, "failed to convert round %d evaluation %d", round, i)
				}
				out[i] = g
				tr.Absorb(g.Bytes())
			}
			proof.GroupRounds = append(proof.GroupRounds, out)

			// The asserted sum is q_0(0) + q_0(1), which is what the verifier
			// recomputes from the first round polynomial.
			if round == 0 {
				var total bls12381.G1Jac
				total.FromAffine(&evals[0])
				total.AddMixed(&evals[1])
				var totalAff bls12381.G1Affine
				totalAff.FromJacobian(&total)
				s, err := toG1(curve, &totalAff)
				if err != nil {
					return nil, nil, errors.Wrap(err, "failed to convert claimed group sum")
				}
				proof.GroupSum = s
			}
		} else {
			evals, err := fieldRoundEvals(work, degree)
			if err != nil {
				return nil, nil, errors.Wrapf(err, "failed to build round %d", round)
			}

			out := make([]*mathlib.Zr, len(evals))
			for i := range evals {
				z := toZr(curve, &evals[i])
				out[i] = z
				tr.Absorb(z.Bytes())
			}
			proof.FieldRounds = append(proof.FieldRounds, out)

			if round == 0 {
				var total fr.Element
				total.Add(&evals[0], &evals[1])
				proof.FieldSum = toZr(curve, &total)
			}
		}

		rFr, rZr, err := squeezeChallenge(tr)
		if err != nil {
			return nil, nil, err
		}
		challenges = append(challenges, rZr)

		foldClaim(work, &rFr)
	}

	opening := &Opening{
		R:          challenges,
		FieldEvals: make([]*mathlib.Zr, len(work.Field)),
	}
	for i := range work.Field {
		opening.FieldEvals[i] = toZr(curve, &work.Field[i][0])
	}
	if isGroup {
		g, err := toG1(curve, &work.Group[0])
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed to convert final group evaluation")
		}
		opening.GroupEval = g
	}

	return proof, opening, nil
}

// foldClaim folds every factor of the claim at r, in place.
func foldClaim(c *Claim, r *fr.Element) {
	for i := range c.Field {
		c.Field[i] = c.Field[i].fold(r)
	}
	if c.Group != nil {
		c.Group = c.Group.fold(r)
	}
}

// fieldRoundEvals computes the current round's univariate polynomial
//
//	q(t) = sum over x in {0,1}^{mu-1} of prod_i f_i(t, x)
//
// at the points t = 0, 1, ..., degree, returning degree+1 evaluations.
//
// Each factor is multilinear in the round variable, so f_i(t, x) is the straight
// line through f_i(0, x) and f_i(1, x). Evaluating it at successive integer t
// therefore needs only repeated addition of the slope, with no multiplication, and
// the only multiplications per point are the ones forming the product itself.
func fieldRoundEvals(c *Claim, degree int) ([]fr.Element, error) {
	if len(c.Field) == 0 {
		return nil, ErrNoFactors
	}
	n := len(c.Field[0])
	if n < 2 {
		return nil, errors.Wrapf(ErrNotPowerOfTwo, "cannot start a round on %d evaluations", n)
	}
	half := n / 2

	out := make([]fr.Element, degree+1)
	slope := make([]fr.Element, len(c.Field))
	cur := make([]fr.Element, len(c.Field))

	for x := range half {
		for i := range c.Field {
			f := c.Field[i]
			cur[i] = f[x]
			slope[i].Sub(&f[x+half], &f[x])
		}

		for t := range degree + 1 {
			var prod fr.Element
			prod.SetOne()
			for i := range cur {
				prod.Mul(&prod, &cur[i])
			}
			out[t].Add(&out[t], &prod)

			if t == degree {
				break
			}
			for i := range cur {
				cur[i].Add(&cur[i], &slope[i])
			}
		}
	}

	return out, nil
}

// groupRoundEvals computes the current round's univariate polynomial when a group
// factor is present:
//
//	q(t) = sum over x in {0,1}^{mu-1} of ( prod_i f_i(t, x) ) * g(t, x)
//
// at t = 0, 1, ..., degree. The field factors collapse to a scalar and the group
// factor supplies the point, so each term is one scalar multiplication.
//
// Scalar multiplications dominate the group side by a wide margin: benchmarked on
// BLS12-381 they are ~85% of a fold's cost, with additions ~137x cheaper. So the
// scalars and points for a whole evaluation point are gathered first and applied
// with a single multi-scalar multiplication, which amortizes the window
// precomputation across the round instead of repeating it per term.
func groupRoundEvals(c *Claim, degree int) ([]bls12381.G1Affine, error) {
	if c.Group == nil {
		return nil, ErrNoFactors
	}
	n := len(c.Group)
	if n < 2 {
		return nil, errors.Wrapf(ErrNotPowerOfTwo, "cannot start a round on %d evaluations", n)
	}
	half := n / 2

	scalars := make([][]fr.Element, degree+1)
	points := make([][]bls12381.G1Affine, degree+1)
	for t := range degree + 1 {
		scalars[t] = make([]fr.Element, half)
		points[t] = make([]bls12381.G1Affine, half)
	}

	fslope := make([]fr.Element, len(c.Field))
	fcur := make([]fr.Element, len(c.Field))

	for x := range half {
		for i := range c.Field {
			f := c.Field[i]
			fcur[i] = f[x]
			fslope[i].Sub(&f[x+half], &f[x])
		}

		// gdiff = g(1, x) - g(0, x), so g(t, x) = g(0, x) + t*gdiff and stepping t
		// costs one addition.
		var negZero bls12381.G1Affine
		negZero.Neg(&c.Group[x])
		var gdiffJac bls12381.G1Jac
		gdiffJac.FromAffine(&c.Group[x+half])
		gdiffJac.AddMixed(&negZero)
		var gdiff bls12381.G1Affine
		gdiff.FromJacobian(&gdiffJac)

		var gcurJac bls12381.G1Jac
		gcurJac.FromAffine(&c.Group[x])

		for t := range degree + 1 {
			var prod fr.Element
			prod.SetOne()
			for i := range fcur {
				prod.Mul(&prod, &fcur[i])
			}
			scalars[t][x] = prod
			points[t][x].FromJacobian(&gcurJac)

			if t == degree {
				break
			}
			for i := range fcur {
				fcur[i].Add(&fcur[i], &fslope[i])
			}
			gcurJac.AddMixed(&gdiff)
		}
	}

	out := make([]bls12381.G1Affine, degree+1)
	for t := range degree + 1 {
		acc, err := msm(points[t], scalars[t])
		if err != nil {
			return nil, errors.Wrapf(err, "failed to accumulate round evaluation at %d", t)
		}
		out[t] = acc
	}

	return out, nil
}

// msm returns sum_i scalars[i] * points[i].
//
// It dispatches on length following the crossovers rp/csp/msm.go measured for
// this curve: below three terms, MultiExp's goroutine fan-out and window setup
// cost more than they save, so a direct accumulation wins.
func msm(points []bls12381.G1Affine, scalars []fr.Element) (bls12381.G1Affine, error) {
	var out bls12381.G1Affine

	if len(points) != len(scalars) {
		return out, errors.Wrapf(ErrNumVarsMismatch, "msm length mismatch: %d points, %d scalars", len(points), len(scalars))
	}
	if len(points) == 0 {
		return out, nil
	}

	if len(points) >= 3 {
		var acc bls12381.G1Jac
		if _, err := acc.MultiExp(points, scalars, ecc.MultiExpConfig{}); err != nil {
			return out, errors.Wrap(err, "multi-scalar multiplication failed")
		}
		out.FromJacobian(&acc)

		return out, nil
	}

	var acc bls12381.G1Jac
	scaled := make([]bls12381.G1Affine, 1)
	for i := range points {
		if err := scaleByOne(points[i:i+1], &scalars[i], scaled); err != nil {
			return out, err
		}
		acc.AddMixed(&scaled[0])
	}
	out.FromJacobian(&acc)

	return out, nil
}
