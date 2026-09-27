/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sumcheck

import (
	mathlib "github.com/IBM/mathlib"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/rp/csp"
)

// Composite claims
//
// A Claim is a single product f_1 * ... * f_k. Some protocols need a composite of
// several multilinears, which a single Claim cannot express:
//
//	H = sum over x in {0,1}^mu of  Phi(h_1(x), ..., h_p(x))
//
// where the h_i are multilinear field polynomials and Phi is a public polynomial of
// low total degree. MultiClaim is the wrapper that lifts sum-check from one product
// to such a Phi.
//
// Phi is a plain function. The prover only ever evaluates it at points -- in each
// round it steps the pool polynomials along a line and calls Phi at t = 0, 1, ...,
// Degree -- and the verifier's caller evaluates it once, to close the residual
// claim. So Phi never needs to be expanded into monomials: X(1-Y)(1-Z) + XZ is one
// line.
//
// The polynomials live in a shared pool and Phi reads them by position. A
// polynomial Phi uses several times, or squares, is therefore stored and folded
// once, and the Opening reports one value per pool entry -- which is what a caller
// needs to discharge the residual claim.
//
// Only field polynomials are supported.

// MultiClaim is the claim that the hypercube sum of
//
//	p(x) = Phi(Polys[0](x), ..., Polys[p-1](x))
//
// equals the asserted value. All pool polynomials must have the same number of
// variables, and Phi need not use every one of them.
//
// Degree must bound the total degree of Phi; it is the degree of every round
// polynomial. An understated degree breaks completeness -- honest round
// polynomials no longer fit -- but not soundness: the verifier's caller closes the
// claim with the correct Phi, so a prover using any other polynomial is caught
// except with probability max(Degree, deg Phi) / |F| per round.
//
// Phi receives one value per pool polynomial and must not modify or retain the
// slice.
//
// ProveMulti folds a deep copy, so the caller's tables are not modified.
type MultiClaim struct {
	Polys  []FieldPoly
	Degree int
	Phi    func(vals []fr.Element) fr.Element
}

// NumVars returns the number of variables shared by the pool polynomials.
func (c *MultiClaim) NumVars() int {
	if len(c.Polys) == 0 {
		return 0
	}

	return c.Polys[0].NumVars()
}

// Shape returns the public shape a verifier needs for this claim.
func (c *MultiClaim) Shape() MultiShape {
	return MultiShape{NumVars: c.NumVars(), Degree: c.Degree}
}

// Evaluate returns p at the point where the pool polynomials take the values
// evals, one per pool entry. It is how a caller closes the argument: compare
// Evaluate(values from the commitment scheme) with the verifier's Product.
func (c *MultiClaim) Evaluate(evals []fr.Element) (fr.Element, error) {
	if c.Phi == nil {
		return fr.Element{}, ErrNoFactors
	}
	if len(evals) != len(c.Polys) {
		return fr.Element{}, errors.Wrapf(ErrPoolSize, "got %d values for a pool of %d", len(evals), len(c.Polys))
	}

	return c.Phi(evals), nil
}

// validate checks the structural invariants the protocol relies on.
func (c *MultiClaim) validate() error {
	if len(c.Polys) == 0 || c.Phi == nil {
		return ErrNoFactors
	}
	if c.Degree < 1 {
		return errors.Wrapf(ErrNoFactors, "degree must be at least 1, got %d", c.Degree)
	}
	nv := -1
	for i, p := range c.Polys {
		if p == nil {
			return errors.Wrapf(ErrNilPolynomial, "pool polynomial %d is nil", i)
		}
		if !isPowerOfTwo(len(p)) {
			return errors.Wrapf(ErrNotPowerOfTwo, "pool polynomial %d has %d evaluations", i, len(p))
		}
		if nv < 0 {
			nv = p.NumVars()
		} else if p.NumVars() != nv {
			return errors.Wrapf(ErrNumVarsMismatch, "pool polynomial %d has %d variables, expected %d", i, p.NumVars(), nv)
		}
	}
	if nv == 0 {
		return errors.Wrap(ErrNumVarsMismatch, "pool polynomials must have at least one variable")
	}

	return nil
}

// MultiShape is the public shape of a MultiClaim: what a verifier needs without
// the polynomials. Phi is not part of it, since the round checks do not
// depend on them; the caller uses them only to close the residual claim.
type MultiShape struct {
	NumVars int
	Degree  int
}

// asShape maps a MultiShape onto the single-product Shape that drives the round
// checks: a field-only product of Degree factors has exactly the same round
// structure, and the verifier never looks at the factors themselves.
func (s MultiShape) asShape() Shape {
	return Shape{NumVars: s.NumVars, NumFieldFactors: s.Degree}
}

// newMultiTranscript is newTranscript for a MultiClaim. The kind byte is 2, so a
// multi proof can never be replayed as a single-product proof of the same size.
func newMultiTranscript(curve *mathlib.Curve, numVars, degree int) *csp.Transcript {
	tr := &csp.Transcript{Curve: curve}
	tr.InitHasherWithDomain(DomainSeparator)
	tr.Absorb([]byte{byte(numVars), byte(degree), 2})

	return tr
}

// ProveMulti runs the sum-check prover over a composite claim.
//
// The Opening's FieldEvals holds one value per pool polynomial, in pool order, at
// the challenge point R. Only the FieldRounds and FieldSum of the proof are set.
func ProveMulti(curve *mathlib.Curve, claim *MultiClaim) (*Proof, *Opening, error) {
	if curve == nil {
		return nil, nil, ErrNilCurve
	}
	if claim == nil {
		return nil, nil, ErrNilPolynomial
	}
	if err := claim.validate(); err != nil {
		return nil, nil, err
	}

	return proveMultiWith(curve, claim, newMultiTranscript(curve, claim.NumVars(), claim.Degree))
}

// ProveMultiWithTranscript is ProveMulti with a caller-supplied transcript, for
// composing into a larger protocol. As with ProveWithTranscript the caller owns
// domain separation and shape binding.
func ProveMultiWithTranscript(curve *mathlib.Curve, claim *MultiClaim, tr *csp.Transcript) (*Proof, *Opening, error) {
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

	return proveMultiWith(curve, claim, tr)
}

// proveMultiWith is the shared prover body. tr must be ready to absorb.
func proveMultiWith(curve *mathlib.Curve, claim *MultiClaim, tr *csp.Transcript) (*Proof, *Opening, error) {
	numVars := claim.NumVars()
	degree := claim.Degree

	work := make([]FieldPoly, len(claim.Polys))
	for i, p := range claim.Polys {
		work[i] = p.Clone()
	}

	proof := &Proof{FieldRounds: make([][]*mathlib.Zr, 0, numVars)}
	challenges := make([]*mathlib.Zr, 0, numVars)

	for round := range numVars {
		evals := multiRoundEvals(work, claim.Phi, degree)

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

		rFr, rZr, err := squeezeChallenge(tr)
		if err != nil {
			return nil, nil, err
		}
		challenges = append(challenges, rZr)

		for i := range work {
			work[i] = work[i].fold(&rFr)
		}
	}

	opening := &Opening{R: challenges, FieldEvals: make([]*mathlib.Zr, len(work))}
	for i := range work {
		opening.FieldEvals[i] = toZr(curve, &work[i][0])
	}

	return proof, opening, nil
}

// multiRoundEvals computes the round polynomial
//
//	q(t) = sum over x in {0,1}^{mu-1} of Phi(h_1(t, x), ..., h_p(t, x))
//
// at t = 0, 1, ..., degree. Each pool polynomial is stepped along its line once per
// point, so the cost per point is one addition per pool entry plus one evaluation
// of Phi.
func multiRoundEvals(polys []FieldPoly, phi func([]fr.Element) fr.Element, degree int) []fr.Element {
	half := len(polys[0]) / 2
	out := make([]fr.Element, degree+1)
	cur := make([]fr.Element, len(polys))
	slope := make([]fr.Element, len(polys))

	for x := range half {
		for i, p := range polys {
			cur[i] = p[x]
			slope[i].Sub(&p[x+half], &p[x])
		}
		for t := range degree + 1 {
			v := phi(cur)
			out[t].Add(&out[t], &v)
			if t == degree {
				break
			}
			for i := range cur {
				cur[i].Add(&cur[i], &slope[i])
			}
		}
	}

	return out
}

// VerifyMulti checks a MultiClaim proof against the sum asserted in the proof.
//
// As with Verify, a nil error means only that the sum follows from the returned
// Opening. Opening.Product is p(R); the caller closes the argument by checking it
// against Phi applied to the pool values its commitment scheme opens to.
func VerifyMulti(curve *mathlib.Curve, shape MultiShape, proof *Proof) (*Opening, error) {
	if curve == nil {
		return nil, ErrNilCurve
	}
	if proof == nil {
		return nil, ErrNilProof
	}
	if err := shape.asShape().validate(); err != nil {
		return nil, err
	}

	return verifyWith(curve, shape.asShape(), proof, newMultiTranscript(curve, shape.NumVars, shape.Degree))
}

// VerifyMultiWithTranscript is VerifyMulti with a caller-supplied transcript,
// matching ProveMultiWithTranscript.
func VerifyMultiWithTranscript(curve *mathlib.Curve, shape MultiShape, proof *Proof, tr *csp.Transcript) (*Opening, error) {
	if curve == nil {
		return nil, ErrNilCurve
	}
	if proof == nil {
		return nil, ErrNilProof
	}
	if tr == nil {
		return nil, errors.New("transcript cannot be nil")
	}
	if err := shape.asShape().validate(); err != nil {
		return nil, err
	}

	return verifyWith(curve, shape.asShape(), proof, tr)
}
