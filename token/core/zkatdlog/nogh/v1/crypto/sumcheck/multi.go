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

// Sum-of-products claims
//
// A Claim is a single product f_1 * ... * f_k. Some protocols need a sum of
// structurally different products, which a single Claim cannot express:
//
//	H = sum over x in {0,1}^mu of  sum_j c_j * prod_{i in S_j} h_i(x)
//
// where the h_i are multilinear field polynomials and each S_j is a multiset of
// indices into them. This is exactly a polynomial Phi(h_1, ..., h_p) with public
// coefficients, written as its list of monomials, so MultiClaim is the wrapper that
// lifts sum-check from one product to Phi of several multilinears.
//
// The polynomials live in a shared pool and the terms refer to them by index. A
// polynomial used by several terms, or several times in one term (a square), is
// therefore stored and folded once, and the Opening reports one value per pool
// entry -- which is what a caller needs to discharge the residual claim.
//
// Only field polynomials are supported. The per-round degree is the largest term
// degree; shorter terms are evaluated at the same points, which is equivalent to
// padding them.

// Term is one product of a MultiClaim: Coeff times the product of the pool
// polynomials named by Factors. An index may repeat, which raises that polynomial
// to a power. Factors must be non-empty.
type Term struct {
	Coeff   fr.Element
	Factors []int
}

// MultiClaim is the claim that the hypercube sum of
//
//	p(x) = sum_j Terms[j].Coeff * prod_{i in Terms[j].Factors} Polys[i](x)
//
// equals the asserted value. All pool polynomials must have the same number of
// variables, and every pool polynomial need not be used.
//
// ProveMulti folds a deep copy, so the caller's tables are not modified.
type MultiClaim struct {
	Polys []FieldPoly
	Terms []Term
}

// NumVars returns the number of variables shared by the pool polynomials.
func (c *MultiClaim) NumVars() int {
	if len(c.Polys) == 0 {
		return 0
	}

	return c.Polys[0].NumVars()
}

// Degree returns the per-round degree, the largest number of factors of any term.
func (c *MultiClaim) Degree() int {
	d := 0
	for _, t := range c.Terms {
		if len(t.Factors) > d {
			d = len(t.Factors)
		}
	}

	return d
}

// Shape returns the public shape a verifier needs for this claim.
func (c *MultiClaim) Shape() MultiShape {
	return MultiShape{NumVars: c.NumVars(), Degree: c.Degree()}
}

// Evaluate returns p at the point where the pool polynomials take the values
// evals, one per pool entry. It is how a caller closes the argument: compare
// Evaluate(values from the commitment scheme) with the verifier's Product.
func (c *MultiClaim) Evaluate(evals []fr.Element) (fr.Element, error) {
	return EvaluateTerms(c.Terms, evals)
}

// EvaluateTerms returns sum_j terms[j].Coeff * prod_{i in terms[j].Factors} evals[i].
//
// It is exported separately from MultiClaim.Evaluate because a verifier holds the
// terms but not the pool polynomials.
func EvaluateTerms(terms []Term, evals []fr.Element) (fr.Element, error) {
	var out fr.Element
	for j, t := range terms {
		prod := t.Coeff
		for _, f := range t.Factors {
			if f < 0 || f >= len(evals) {
				return out, errors.Wrapf(ErrFactorIndex, "term %d names pool entry %d, have %d values", j, f, len(evals))
			}
			prod.Mul(&prod, &evals[f])
		}
		out.Add(&out, &prod)
	}

	return out, nil
}

// validate checks the structural invariants the protocol relies on.
func (c *MultiClaim) validate() error {
	if len(c.Polys) == 0 || len(c.Terms) == 0 {
		return ErrNoFactors
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
	for j, t := range c.Terms {
		if len(t.Factors) == 0 {
			return errors.Wrapf(ErrNoFactors, "term %d has no factors", j)
		}
		for _, f := range t.Factors {
			if f < 0 || f >= len(c.Polys) {
				return errors.Wrapf(ErrFactorIndex, "term %d names pool entry %d, pool has %d", j, f, len(c.Polys))
			}
		}
	}

	return nil
}

// MultiShape is the public shape of a MultiClaim: what a verifier needs without
// the polynomials. The terms are not part of it, since the round checks do not
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

// ProveMulti runs the sum-check prover over a sum-of-products claim.
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

	return proveMultiWith(curve, claim, newMultiTranscript(curve, claim.NumVars(), claim.Degree()))
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
	degree := claim.Degree()

	work := make([]FieldPoly, len(claim.Polys))
	for i, p := range claim.Polys {
		work[i] = p.Clone()
	}

	proof := &Proof{FieldRounds: make([][]*mathlib.Zr, 0, numVars)}
	challenges := make([]*mathlib.Zr, 0, numVars)

	for round := range numVars {
		evals := multiRoundEvals(work, claim.Terms, degree)

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
//	q(t) = sum over x in {0,1}^{mu-1} of sum_j c_j * prod_{i in S_j} h_i(t, x)
//
// at t = 0, 1, ..., degree. Each pool polynomial is stepped along its line once per
// point and shared by every term that uses it, so the cost per point is one
// addition per pool entry plus one multiplication per factor occurrence.
func multiRoundEvals(polys []FieldPoly, terms []Term, degree int) []fr.Element {
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
			for _, term := range terms {
				prod := term.Coeff
				for _, f := range term.Factors {
					prod.Mul(&prod, &cur[f])
				}
				out[t].Add(&out[t], &prod)
			}
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
// against EvaluateTerms applied to the pool values its commitment scheme opens to.
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
