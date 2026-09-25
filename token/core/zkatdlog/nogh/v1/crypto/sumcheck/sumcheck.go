/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package sumcheck implements the sum-check protocol, Fiat-Shamir compiled,
// for claims of the form
//
//	H = sum over x in {0,1}^mu of p(x),    p(X) = f_1(X) * ... * f_k(X) * g_1(X)
//
// where each f_i is a multilinear polynomial over the scalar field and g_1 is an
// optional multilinear polynomial whose evaluations are points in G1. There may
// be zero or more field factors and at most one group factor: a product of two
// group elements is not defined in this setting, so a claim with two group
// polynomials is rejected.
//
// When a group factor is present the claimed sum, and every round polynomial,
// lives in G1; challenges are drawn from the scalar field in both cases.
//
// The protocol reduces the claim about a sum over 2^mu points to a single claim
// about the value of each factor at one random point r in F^mu. Verify returns r
// together with those claimed evaluations and leaves it to the caller to
// discharge them, by a polynomial commitment opening, an oracle query, or direct
// evaluation. This keeps the package independent of any commitment scheme.
//
// Fiat-Shamir uses the Transcript from the CSP range-proof package under its own
// domain separator, so sum-check challenges can never be confused with CSP
// challenges. The transcript is never reset between rounds, which binds every
// challenge to all previously sent data.
package sumcheck

import (
	mathlib "github.com/IBM/mathlib"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/rp/csp"
)

// DomainSeparator is the Fiat-Shamir domain separator for this protocol. It
// differs from the CSP range proof's separator so that a transcript from one
// protocol can never be replayed as the other.
const DomainSeparator = "SumCheck-v1"

// Claim describes the product whose hypercube sum is being proven.
//
// Field holds the field factors f_1, ..., f_k, with k >= 0. Group optionally
// holds the single group factor g_1; it is nil for a field-only claim. All
// factors must have the same number of variables, and at least one factor must
// be present.
//
// Prove folds its factors in place, so Claim holds the caller's slices by
// reference. Use Clone on the individual polynomials beforehand if the inputs
// must survive.
type Claim struct {
	Field []FieldPoly
	Group GroupPoly
}

// NumVars returns the number of variables shared by all factors.
func (c *Claim) NumVars() int {
	if len(c.Field) > 0 {
		return c.Field[0].NumVars()
	}
	if c.Group != nil {
		return c.Group.NumVars()
	}

	return 0
}

// Degree returns the degree of the per-round univariate polynomial: one per
// field factor, plus one more if a group factor is present.
func (c *Claim) Degree() int {
	d := len(c.Field)
	if c.Group != nil {
		d++
	}

	return d
}

// IsGroup reports whether the claim carries a group factor, and therefore whether
// its sum and round polynomials live in G1 rather than in the field.
func (c *Claim) IsGroup() bool { return c.Group != nil }

// validate checks the structural invariants the protocol relies on.
func (c *Claim) validate() error {
	if len(c.Field) == 0 && c.Group == nil {
		return ErrNoFactors
	}

	nv := -1
	for i, f := range c.Field {
		if f == nil {
			return errors.Wrapf(ErrNilPolynomial, "field factor %d is nil", i)
		}
		if !isPowerOfTwo(len(f)) {
			return errors.Wrapf(ErrNotPowerOfTwo, "field factor %d has %d evaluations", i, len(f))
		}
		if nv < 0 {
			nv = f.NumVars()
		} else if f.NumVars() != nv {
			return errors.Wrapf(ErrNumVarsMismatch, "field factor %d has %d variables, expected %d", i, f.NumVars(), nv)
		}
	}
	if c.Group != nil {
		if !isPowerOfTwo(len(c.Group)) {
			return errors.Wrapf(ErrNotPowerOfTwo, "group factor has %d evaluations", len(c.Group))
		}
		if nv >= 0 && c.Group.NumVars() != nv {
			return errors.Wrapf(ErrNumVarsMismatch, "group factor has %d variables, expected %d", c.Group.NumVars(), nv)
		}
	}

	return nil
}

// clone returns a deep copy of the claim, so that folding does not disturb the
// caller's tables.
func (c *Claim) clone() *Claim {
	out := &Claim{}
	if c.Field != nil {
		out.Field = make([]FieldPoly, len(c.Field))
		for i, f := range c.Field {
			out.Field[i] = f.Clone()
		}
	}
	if c.Group != nil {
		out.Group = c.Group.Clone()
	}

	return out
}

// Proof is the transcript of a sum-check execution.
//
// Exactly one of FieldRounds or GroupRounds is populated, matching the claim's
// shape, and it holds one entry per variable. Round i holds the evaluations of
// that round's univariate polynomial at the points 0, 1, ..., Degree, which is
// Degree+1 values; the verifier interpolates from them.
//
// Sum is the asserted hypercube sum: FieldSum for a field-only claim, GroupSum
// when a group factor is present.
type Proof struct {
	FieldRounds [][]*mathlib.Zr
	GroupRounds [][]*mathlib.G1

	FieldSum *mathlib.Zr
	GroupSum *mathlib.G1
}

// IsGroup reports whether this is a group proof.
func (p *Proof) IsGroup() bool { return p.GroupRounds != nil || p.GroupSum != nil }

// Rounds returns the number of rounds recorded in the proof.
func (p *Proof) Rounds() int {
	if p.IsGroup() {
		return len(p.GroupRounds)
	}

	return len(p.FieldRounds)
}

// newTranscript builds a transcript bound to this protocol's domain separator and
// to the claim's public shape, so that a proof for one claim shape cannot be
// reinterpreted as a proof for another.
func newTranscript(curve *mathlib.Curve, numVars, degree int, isGroup bool) *csp.Transcript {
	tr := &csp.Transcript{Curve: curve}
	tr.InitHasherWithDomain(DomainSeparator)

	header := []byte{byte(numVars), byte(degree), 0}
	if isGroup {
		header[2] = 1
	}
	tr.Absorb(header)

	return tr
}

// squeezeChallenge draws the next challenge and returns it in both
// representations: fr.Element for the arithmetic, *mathlib.Zr for the caller.
//
// Squeeze returns a *mathlib.Zr, so there is one conversion per round. At log n
// rounds this is negligible, and it keeps the Fiat-Shamir bytes byte-identical to
// the CSP construction, which matters more than saving the conversion.
func squeezeChallenge(tr *csp.Transcript) (fr.Element, *mathlib.Zr, error) {
	z, err := tr.Squeeze()
	if err != nil {
		var zero fr.Element

		return zero, nil, errors.Wrap(err, "failed to squeeze sum-check challenge")
	}

	return fromZr(z), z, nil
}

// interpolateAt evaluates, at x, the unique univariate polynomial of degree
// len(evals)-1 that passes through (0, evals[0]), (1, evals[1]), ...
//
// It uses the Lagrange form on the fixed node set {0, 1, ..., d}. The nodes are
// known in advance and small, so the barycentric weights are computed directly
// rather than being tabulated.
func interpolateAt(evals []fr.Element, x *fr.Element) fr.Element {
	var out fr.Element
	d := len(evals)

	for i := range d {
		// term = evals[i] * prod_{j != i} (x - j) / (i - j)
		var num, den fr.Element
		num.SetOne()
		den.SetOne()

		var xi fr.Element
		xi.SetUint64(uint64(i))

		for j := range d {
			if j == i {
				continue
			}
			var xj fr.Element
			xj.SetUint64(uint64(j))

			var t fr.Element
			t.Sub(x, &xj)
			num.Mul(&num, &t)

			t.Sub(&xi, &xj)
			den.Mul(&den, &t)
		}

		den.Inverse(&den)
		num.Mul(&num, &den)
		num.Mul(&num, &evals[i])
		out.Add(&out, &num)
	}

	return out
}

// interpolateAtG1 is interpolateAt for evaluations that are group elements: the
// Lagrange coefficients are computed in the field and applied as scalars.
func interpolateAtG1(evals []bls12381.G1Affine, x *fr.Element) bls12381.G1Affine {
	d := len(evals)
	coeffs := make([]fr.Element, d)

	for i := range d {
		var num, den fr.Element
		num.SetOne()
		den.SetOne()

		var xi fr.Element
		xi.SetUint64(uint64(i))

		for j := range d {
			if j == i {
				continue
			}
			var xj fr.Element
			xj.SetUint64(uint64(j))

			var t fr.Element
			t.Sub(x, &xj)
			num.Mul(&num, &t)

			t.Sub(&xi, &xj)
			den.Mul(&den, &t)
		}

		den.Inverse(&den)
		coeffs[i].Mul(&num, &den)
	}

	// The Lagrange coefficients differ per term, so this is a genuine
	// multi-scalar multiplication rather than the shared-scalar fold case.
	res, err := msm(evals, coeffs)
	if err != nil {
		// msm only reports a length mismatch, and coeffs is allocated at len(evals).
		return bls12381.G1Affine{}
	}

	return res
}
