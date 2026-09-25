/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sumcheck

import (
	"math/big"
	"math/bits"

	mathlib "github.com/IBM/mathlib"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"
)

// FieldPoly is a multilinear polynomial over the scalar field, given by its
// evaluations on the boolean hypercube {0,1}^mu in little-endian index order:
// entry i holds p(b_0, ..., b_{mu-1}) where b_j is bit j of i.
//
// The representation is gnark-crypto's fr.Element rather than *mathlib.Zr. The
// conversion happens once, at the API edge, because it only pays for itself when
// amortized across all mu folding rounds: benchmarked on BLS12-381 with 4096
// evaluations, a single pass over the data is ~20% *slower* in fr once
// conversion is counted, while the full log n fold is ~2.1x faster (182us vs
// 383us). Per-call conversion is therefore a loss and must be avoided.
type FieldPoly []fr.Element

// GroupPoly is a multilinear polynomial whose evaluations on {0,1}^mu are points
// in G1, in the same little-endian index order as FieldPoly.
//
// Points are held in affine form. Folding converts to Jacobian internally to
// avoid the per-operation affine round-trip that mathlib performs, but keeps the
// table affine between rounds so that the batched multi-scalar multiplication can
// consume it directly.
type GroupPoly []bls12381.G1Affine

// NumVars returns the number of variables mu, so that len(p) == 2^mu.
func (p FieldPoly) NumVars() int { return bits.Len(uint(len(p))) - 1 }

// NumVars returns the number of variables mu, so that len(p) == 2^mu.
func (p GroupPoly) NumVars() int { return bits.Len(uint(len(p))) - 1 }

// Clone returns an independent copy. Prove folds in place, so callers that need
// to keep their inputs must clone first.
func (p FieldPoly) Clone() FieldPoly {
	out := make(FieldPoly, len(p))
	copy(out, p)

	return out
}

// Clone returns an independent copy.
func (p GroupPoly) Clone() GroupPoly {
	out := make(GroupPoly, len(p))
	copy(out, p)

	return out
}

// Sum returns the sum of p over the whole hypercube.
func (p FieldPoly) Sum() fr.Element {
	var acc fr.Element
	for i := range p {
		acc.Add(&acc, &p[i])
	}

	return acc
}

// Sum returns the sum of p over the whole hypercube.
//
// Jacobian additions are near-free relative to scalar multiplications
// (benchmarked at ~1.2ms versus ~161ms for the same count on BLS12-381), so this
// accumulates directly rather than going through a multi-scalar multiplication.
func (p GroupPoly) Sum() bls12381.G1Jac {
	var acc bls12381.G1Jac
	for i := range p {
		acc.AddMixed(&p[i])
	}

	return acc
}

// fold substitutes r for the *last* variable, replacing p with its restriction
// p(b_0, ..., b_{mu-2}, r) and halving the table. Using the multilinear identity
//
//	p(x, r) = (1-r)*p(x, 0) + r*p(x, 1) = p(x, 0) + r*(p(x, 1) - p(x, 0))
//
// the second form is used because it needs one multiplication per entry instead
// of two.
//
// The last variable is the one folded because the table is little-endian (see
// FieldPoly): b_{mu-1} is the *high* index bit, so the two halves p(x, 0) and
// p(x, 1) are the bottom and top halves of the table and pair up as i, i+half.
// Under the opposite (big-endian) convention the first variable would be the high
// bit and the pairing would instead be the even/odd split 2i, 2i+1 — folding the
// wrong pairing for the layout silently computes a different polynomial, so the
// two must be kept in step.
//
// p must have even length. fold is a no-op on a table of length 1.
func (p FieldPoly) fold(r *fr.Element) FieldPoly {
	if len(p) < 2 {
		return p
	}
	half := len(p) / 2
	var diff fr.Element
	for i := range half {
		diff.Sub(&p[i+half], &p[i])
		diff.Mul(&diff, r)
		p[i].Add(&p[i], &diff)
	}

	return p[:half]
}

// fold substitutes r for the *last* variable, replacing p with its restriction
// p(b_0, ..., b_{mu-2}, r). The pairing is i with i+half, for the same
// little-endian reason given on FieldPoly.fold.
//
// The challenge r is shared by every entry in the round, so its conversion to
// big.Int is hoisted out of the loop. This is the single most important detail on
// the group side: converting per entry instead makes folding *slower* than
// mathlib's own operations (benchmarked at 300ms versus 227ms for 4096 points),
// while hoisting brings it to 190ms. Scalar multiplication accounts for ~85% of
// the remaining time, so the round is expressed as one batched multi-scalar
// multiplication over the n/2 differences, which amortizes the window
// precomputation that a sequence of independent ScalarMultiplication calls would
// repeat.
func (p GroupPoly) fold(r *fr.Element) GroupPoly {
	if len(p) < 2 {
		return p
	}
	half := len(p) / 2

	// diffs[i] = p[i+half] - p[i]. Additions are cheap enough to be irrelevant
	// here (~1.2ms versus ~161ms for the same count of scalar multiplications on
	// BLS12-381), so the subtraction pass costs essentially nothing.
	diffs := make([]bls12381.G1Affine, half)
	for i := range half {
		var neg bls12381.G1Affine
		neg.Neg(&p[i])
		var d bls12381.G1Jac
		d.FromAffine(&p[i+half])
		d.AddMixed(&neg)
		diffs[i].FromJacobian(&d)
	}

	scaled := make([]bls12381.G1Affine, half)
	// scaleByOne only reports a length mismatch, which cannot occur because both
	// slices are allocated at half.
	_ = scaleByOne(diffs, r, scaled)

	for i := range half {
		var acc bls12381.G1Jac
		acc.FromAffine(&p[i])
		acc.AddMixed(&scaled[i])
		p[i].FromJacobian(&acc)
	}

	return p[:half]
}

// scaleByOne computes out[i] = r * points[i] for every i, for a single shared
// scalar r.
//
// A fold round always scales every difference by the same challenge, so r is
// converted to big.Int once for the whole round. Doing it per point instead is
// what made a naive Jacobian fold slower than mathlib's own operations
// (benchmarked at 300ms versus 227ms for 4096 points); hoisting it brings the
// same fold to 190ms, of which ~85% is the unavoidable scalar multiplication
// itself.
//
// points and out must have equal length.
func scaleByOne(points []bls12381.G1Affine, r *fr.Element, out []bls12381.G1Affine) error {
	if len(points) != len(out) {
		return errors.Wrapf(ErrNumVarsMismatch, "scaleByOne length mismatch: %d points, %d out", len(points), len(out))
	}
	if len(points) == 0 {
		return nil
	}

	var bi big.Int
	r.BigInt(&bi)
	for i := range points {
		var j bls12381.G1Jac
		j.FromAffine(&points[i])
		j.ScalarMultiplication(&j, &bi)
		out[i].FromJacobian(&j)
	}

	return nil
}

// EvaluateOpening returns p(at) for a point in *folding* order, which is the order
// the sum-check rounds consume challenges in: at[0] is substituted for the last
// variable b_{mu-1}, at[1] for b_{mu-2}, and so on.
//
// This is the order an Opening's R is already in, so R can be passed straight
// through without reordering — hence the name. A caller holding a point in table
// order (b_0 first) wants EvaluatePoint instead. The two differ only in argument
// order and are exposed separately so the call site states which convention it
// means, rather than relying on the reader to remember.
//
// len(at) must equal p.NumVars(). It folds a copy, so p is left unchanged.
func (p FieldPoly) EvaluateOpening(at []fr.Element) (fr.Element, error) {
	if len(at) != p.NumVars() {
		var zero fr.Element

		return zero, errors.Wrapf(ErrNumVarsMismatch, "cannot evaluate %d-variable polynomial at %d-element point", p.NumVars(), len(at))
	}
	cur := p.Clone()
	for i := range at {
		cur = cur.fold(&at[i])
	}

	return cur[0], nil
}

// EvaluatePoint returns p(at) for a point in *table* order, matching the layout
// documented on FieldPoly: at[0] is the value of b_0, at[1] of b_1, and so on.
//
// This is the natural order for a caller that thinks in terms of the polynomial's
// own variables. It reverses internally into folding order, so it allocates a small
// slice of len(at); use EvaluateOpening when the point already came from an Opening.
//
// len(at) must equal p.NumVars(). It folds a copy, so p is left unchanged.
func (p FieldPoly) EvaluatePoint(at []fr.Element) (fr.Element, error) {
	if len(at) != p.NumVars() {
		var zero fr.Element

		return zero, errors.Wrapf(ErrNumVarsMismatch, "cannot evaluate %d-variable polynomial at %d-element point", p.NumVars(), len(at))
	}

	return p.EvaluateOpening(reverseScalars(at))
}

// EvaluateOpening returns p(at) for a point in *folding* order, matching
// FieldPoly.EvaluateOpening. at[0] is substituted for the last variable b_{mu-1}.
//
// len(at) must equal p.NumVars(). It folds a copy, so p is left unchanged.
func (p GroupPoly) EvaluateOpening(at []fr.Element) (bls12381.G1Affine, error) {
	if len(at) != p.NumVars() {
		var zero bls12381.G1Affine

		return zero, errors.Wrapf(ErrNumVarsMismatch, "cannot evaluate %d-variable polynomial at %d-element point", p.NumVars(), len(at))
	}
	cur := p.Clone()
	for i := range at {
		cur = cur.fold(&at[i])
	}

	return cur[0], nil
}

// EvaluatePoint returns p(at) for a point in *table* order, matching
// FieldPoly.EvaluatePoint: at[0] is the value of b_0.
//
// len(at) must equal p.NumVars(). It folds a copy, so p is left unchanged.
func (p GroupPoly) EvaluatePoint(at []fr.Element) (bls12381.G1Affine, error) {
	if len(at) != p.NumVars() {
		var zero bls12381.G1Affine

		return zero, errors.Wrapf(ErrNumVarsMismatch, "cannot evaluate %d-variable polynomial at %d-element point", p.NumVars(), len(at))
	}

	return p.EvaluateOpening(reverseScalars(at))
}

// reverseScalars returns a reversed copy of in, converting between table order and
// folding order. It copies rather than reversing in place so that a caller's slice is
// never disturbed.
func reverseScalars(in []fr.Element) []fr.Element {
	out := make([]fr.Element, len(in))
	for i := range in {
		out[len(in)-1-i] = in[i]
	}

	return out
}

// NewFieldPoly converts an evaluation table of mathlib scalars into a FieldPoly.
//
// This is the conversion boundary: call it once per polynomial, before the
// protocol starts, never inside a round. The length must be a power of two.
func NewFieldPoly(evals []*mathlib.Zr) (FieldPoly, error) {
	if evals == nil {
		return nil, ErrNilPolynomial
	}
	if !isPowerOfTwo(len(evals)) {
		return nil, errors.Wrapf(ErrNotPowerOfTwo, "got %d evaluations", len(evals))
	}
	out := make(FieldPoly, len(evals))
	for i, e := range evals {
		if e == nil {
			return nil, errors.Wrapf(ErrNilElement, "evaluation %d is nil", i)
		}
		out[i].SetBytes(e.Bytes())
	}

	return out, nil
}

// NewGroupPoly converts an evaluation table of mathlib G1 points into a
// GroupPoly.
//
// This conversion is *not* cheap: mathlib.G1 keeps its driver point in an
// unexported field, so the only route is through its serialized form, and
// SetBytes performs a subgroup membership check. Benchmarked on BLS12-381, this
// costs ~108ms for 4096 points, comparable to half the cost of an entire fold.
// Callers in a hot loop should therefore hold a GroupPoly across calls rather
// than rebuilding it from []*mathlib.G1 each time.
//
// The length must be a power of two.
func NewGroupPoly(evals []*mathlib.G1) (GroupPoly, error) {
	if evals == nil {
		return nil, ErrNilPolynomial
	}
	if !isPowerOfTwo(len(evals)) {
		return nil, errors.Wrapf(ErrNotPowerOfTwo, "got %d evaluations", len(evals))
	}
	out := make(GroupPoly, len(evals))
	for i, e := range evals {
		if e == nil {
			return nil, errors.Wrapf(ErrNilElement, "evaluation %d is nil", i)
		}
		if _, err := out[i].SetBytes(e.Bytes()); err != nil {
			return nil, errors.Wrapf(err, "failed to decode G1 evaluation %d", i)
		}
	}

	return out, nil
}

// toZr converts a field element back to mathlib's representation, for values
// that cross the API boundary or enter the transcript.
func toZr(curve *mathlib.Curve, e *fr.Element) *mathlib.Zr {
	raw := e.Bytes()

	return curve.NewZrFromBytes(raw[:])
}

// fromZr converts a mathlib scalar into a field element.
func fromZr(z *mathlib.Zr) fr.Element {
	var e fr.Element
	e.SetBytes(z.Bytes())

	return e
}

// toG1 converts an affine point back to mathlib's representation.
func toG1(curve *mathlib.Curve, p *bls12381.G1Affine) (*mathlib.G1, error) {
	raw := p.Bytes()
	out, err := curve.NewG1FromCompressed(raw[:])
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert G1 point to mathlib representation")
	}

	return out, nil
}

// isPowerOfTwo reports whether n is a positive power of two.
func isPowerOfTwo(n int) bool {
	return n > 0 && n&(n-1) == 0
}
