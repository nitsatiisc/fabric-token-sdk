/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/sumcheck"
)

// Variable order: why this package folds the *first* variable
//
// crypto/sumcheck consumes variables from the last position inward, because its
// round polynomial is defined that way and its Opening.R comes out in that order.
// The Titan group sum-check is specified the other way round: the paper's round i
// message fixes rho_i = (r_1, ..., r_(i-1)) as a *prefix*, and the partial-sum
// tables S_i(b) are indexed by prefixes b in {0,1}^i. Nothing is gained by
// fighting that — the prefix structure is exactly what makes the S tables
// reusable across rounds — so this package folds the first variable and keeps the
// paper's indexing.
//
// Both conventions therefore exist in the codebase, deliberately:
//
//	sumcheck.FieldPoly.fold  substitutes the LAST variable, pairing i with i+half
//	titan.foldFirstField     substitutes the FIRST variable, pairing 2i with 2i+1
//
// In the little-endian layout both packages share (entry i holds
// p(b_0, ..., b_(mu-1)) with b_j the j-th bit of i), b_0 is the low index bit, so
// its two slices are the even and odd entries — hence the 2i / 2i+1 pairing here
// against the i / i+half pairing there. Mixing them up silently computes a
// different polynomial, which is why they are named for the variable they consume
// rather than for their pairing.

// foldFirstField returns the restriction p(r, b_1, ..., b_(mu-1)), substituting r
// for the *first* variable. The result has half as many entries.
//
// Contrast sumcheck.FieldPoly.fold, which substitutes the last variable; see the
// commentary above on why this package needs the other one. It allocates a new
// slice rather than folding in place, because the caller keeps the unfolded table.
func foldFirstField(p sumcheck.FieldPoly, r *fr.Element) sumcheck.FieldPoly {
	if len(p) < 2 {
		return p
	}
	half := len(p) / 2
	out := make(sumcheck.FieldPoly, half)
	for i := range half {
		// out[i] = p[2i] + r*(p[2i+1] - p[2i])
		var diff fr.Element
		diff.Sub(&p[2*i+1], &p[2*i])
		diff.Mul(&diff, r)
		out[i].Add(&p[2*i], &diff)
	}

	return out
}

// foldFirstGroup returns the restriction p(r, b_1, ..., b_(mu-1)) of a group
// multilinear, substituting r for the *first* variable.
//
// As in sumcheck.GroupPoly.fold, the round shares one challenge across every
// entry, so the conversion of r to big.Int is hoisted out of the loop and the
// n/2 scalar multiplications are applied as a single batched multi-scalar
// multiplication; doing either per entry dominates the round.
func foldFirstGroup(p sumcheck.GroupPoly, r *fr.Element) (sumcheck.GroupPoly, error) {
	if len(p) < 2 {
		return p, nil
	}
	half := len(p) / 2

	diffs := make([]bls12381.G1Affine, half)
	for i := range half {
		var neg bls12381.G1Affine
		neg.Neg(&p[2*i])
		var d bls12381.G1Jac
		d.FromAffine(&p[2*i+1])
		d.AddMixed(&neg)
		diffs[i].FromJacobian(&d)
	}

	scalars := make([]fr.Element, half)
	for i := range scalars {
		scalars[i] = *r
	}
	scaled, err := scaleEach(diffs, scalars)
	if err != nil {
		return nil, err
	}

	out := make(sumcheck.GroupPoly, half)
	for i := range half {
		var acc bls12381.G1Jac
		acc.FromAffine(&p[2*i])
		acc.AddMixed(&scaled[i])
		out[i].FromJacobian(&acc)
	}

	return out, nil
}

// eqTable returns the evaluation table of eq(alpha, .) over the boolean
// hypercube, so out[i] = eq(alpha, <i>) where <i> is the little-endian bit
// decomposition of i.
//
// eq is the multilinear extension of equality,
//
//	eq(alpha, x) = prod_j ( alpha_j*x_j + (1-alpha_j)*(1-x_j) )
//
// and the table is built incrementally: after processing variable j the first
// 2^(j+1) entries hold the partial products, each new variable doubling the
// filled prefix. That is 2^mu multiplications in total rather than the mu*2^mu a
// per-entry product would cost.
func eqTable(alpha []fr.Element) sumcheck.FieldPoly {
	out := make(sumcheck.FieldPoly, 1<<len(alpha))
	out[0] = fr.One()
	filled := 1
	for _, a := range alpha {
		one := fr.One()
		var oneMinus fr.Element
		oneMinus.Sub(&one, &a)
		for i := range filled {
			// The high slice takes alpha_j, the low slice takes 1-alpha_j. The
			// high slice must be written first, since it reads the old low value.
			out[i+filled].Mul(&out[i], &a)
			out[i].Mul(&out[i], &oneMinus)
		}
		filled <<= 1
	}

	return out
}

// eqPoint returns eq(a, b) for two equal-length points, computed directly in
// len(a) multiplications without materializing a table.
func eqPoint(a, b []fr.Element) (fr.Element, error) {
	if len(a) != len(b) {
		var zero fr.Element

		return zero, errors.Wrapf(ErrNumVarsMismatch, "eq needs equal-length points, got %d and %d", len(a), len(b))
	}
	acc := fr.One()
	one := fr.One()
	for i := range a {
		// term = a_i*b_i + (1-a_i)*(1-b_i)
		var ab, lo, hi, term fr.Element
		ab.Mul(&a[i], &b[i])
		lo.Sub(&one, &a[i])
		hi.Sub(&one, &b[i])
		term.Mul(&lo, &hi)
		term.Add(&term, &ab)
		acc.Mul(&acc, &term)
	}

	return acc, nil
}

// batchInvert returns the element-wise inverse of in, using Montgomery's trick:
// one field inversion plus 3n multiplications, rather than n inversions.
//
// A zero input has no inverse, so it returns ErrZeroDenominator naming the index
// rather than silently producing zero. See the note on roundMessages about why
// that case is unreachable on the honest path.
func batchInvert(in []fr.Element) ([]fr.Element, error) {
	out := make([]fr.Element, len(in))
	if len(in) == 0 {
		return out, nil
	}

	// prefix[i] = in[0]*...*in[i-1], so prefix accumulates left to right.
	acc := fr.One()
	for i := range in {
		if in[i].IsZero() {
			return nil, errors.Wrapf(ErrZeroDenominator, "element %d is zero and cannot be inverted", i)
		}
		out[i] = acc
		acc.Mul(&acc, &in[i])
	}

	// acc is now the product of everything; invert once and unwind.
	var accInv fr.Element
	accInv.Inverse(&acc)
	for i := len(in) - 1; i >= 0; i-- {
		out[i].Mul(&out[i], &accInv)
		accInv.Mul(&accInv, &in[i])
	}

	return out, nil
}

// msm computes the multi-scalar multiplication sum_i scalars[i]*points[i].
//
// It mirrors the dispatch in crypto/sumcheck: below three terms, MultiExp's
// goroutine fan-out and window setup cost more than they save.
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

	scaled, err := scaleEach(points, scalars)
	if err != nil {
		return out, err
	}
	var acc bls12381.G1Jac
	for i := range scaled {
		acc.AddMixed(&scaled[i])
	}
	out.FromJacobian(&acc)

	return out, nil
}

// scaleEach returns the points scaled pointwise by the scalars.
func scaleEach(points []bls12381.G1Affine, scalars []fr.Element) ([]bls12381.G1Affine, error) {
	if len(points) != len(scalars) {
		return nil, errors.Wrapf(ErrNumVarsMismatch, "scale length mismatch: %d points, %d scalars", len(points), len(scalars))
	}
	out := make([]bls12381.G1Affine, len(points))
	for i := range points {
		var bi big.Int
		scalars[i].BigInt(&bi)
		var j bls12381.G1Jac
		j.FromAffine(&points[i])
		j.ScalarMultiplication(&j, &bi)
		out[i].FromJacobian(&j)
	}

	return out, nil
}
