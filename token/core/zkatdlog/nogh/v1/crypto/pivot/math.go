/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pivot

import (
	"math/big"

	mathlib "github.com/IBM/mathlib"
	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/sumcheck"
)

// Points and variable order
//
// Every point in this package is in TABLE order: coordinate j is the value of
// variable j, the j-th bit of a table index, which is the order titan's Alpha and
// sumcheck's EvaluatePoint use. A sum-check Opening.R is in FOLDING order instead
// -- the rounds substitute the last variable first -- so it is converted exactly
// once, by tablePoint, and nowhere else. A prover and a verifier that both got the
// order wrong would agree with each other on a proof about a different polynomial,
// which no round-trip test can see; keeping one conversion site is the defence.

// tablePoint converts a sum-check challenge vector, in folding order, into a point
// in table order.
func tablePoint(r []*mathlib.Zr) []fr.Element {
	out := make([]fr.Element, len(r))
	for i, z := range r {
		out[len(r)-1-i] = fromZr(z)
	}

	return out
}

// concat returns the point (a, b): a's coordinates are the low variables.
func concat(a, b []fr.Element) []fr.Element {
	out := make([]fr.Element, 0, len(a)+len(b))
	out = append(out, a...)

	return append(out, b...)
}

// boolPoint returns the boolean point of index i over nv variables, in table order.
func boolPoint(i, nv int) []fr.Element {
	out := make([]fr.Element, nv)
	for j := range nv {
		if (i>>j)&1 == 1 {
			out[j].SetOne()
		}
	}

	return out
}

// eqTable returns the table of eq(point, x) over the hypercube, entry i holding
// eq(point, <i>) with <i> the little-endian bits of i.
func eqTable(point []fr.Element) sumcheck.FieldPoly {
	out := make(sumcheck.FieldPoly, 1<<len(point))
	out[0].SetOne()
	filled := 1
	for _, a := range point {
		var oneMinus fr.Element
		oneMinus.SetOne()
		oneMinus.Sub(&oneMinus, &a)
		for i := range filled {
			out[i+filled].Mul(&out[i], &a)
			out[i].Mul(&out[i], &oneMinus)
		}
		filled <<= 1
	}

	return out
}

// eqEval returns eq(a, b) = prod_j (a_j b_j + (1 - a_j)(1 - b_j)).
func eqEval(a, b []fr.Element) fr.Element {
	var out fr.Element
	out.SetOne()
	for j := range a {
		var ab, t fr.Element
		ab.Mul(&a[j], &b[j])
		// a b + (1-a)(1-b) = 1 - a - b + 2ab
		t.SetOne()
		t.Sub(&t, &a[j])
		t.Sub(&t, &b[j])
		t.Add(&t, &ab)
		t.Add(&t, &ab)
		out.Mul(&out, &t)
	}

	return out
}

// innerProduct returns sum_i a_i b_i.
func innerProduct(a, b []fr.Element) fr.Element {
	var out fr.Element
	for i := range a {
		var t fr.Element
		t.Mul(&a[i], &b[i])
		out.Add(&out, &t)
	}

	return out
}

// powers returns 1, x, x^2, ..., x^(n-1).
func powers(x fr.Element, n int) []fr.Element {
	out := make([]fr.Element, n)
	if n == 0 {
		return out
	}
	out[0].SetOne()
	for i := 1; i < n; i++ {
		out[i].Mul(&out[i-1], &x)
	}

	return out
}

// restrictRows returns the n-vector sum_z weights[z] * rows[z]: the restriction of a
// position-first table to a fixed instance point when weights is its eq table.
func restrictRows(rows [][]fr.Element, weights []fr.Element, n int) []fr.Element {
	out := make([]fr.Element, n)
	for z, row := range rows {
		if weights[z].IsZero() {
			continue
		}
		for x := range row {
			var t fr.Element
			t.Mul(&weights[z], &row[x])
			out[x].Add(&out[x], &t)
		}
	}

	return out
}

// sparseApply returns M v for a sparse matrix with the given number of rows.
func sparseApply(entries []SparseEntry, v []fr.Element, rows int) []fr.Element {
	out := make([]fr.Element, rows)
	for _, e := range entries {
		var t fr.Element
		t.Mul(&e.Val, &v[e.Col])
		out[e.Row].Add(&out[e.Row], &t)
	}

	return out
}

// sparseRowCombine returns u^T M, the column vector sum_r u[r] M[r, .], of length
// cols. With u an eq table this is M~(point, .) over the column hypercube.
func sparseRowCombine(entries []SparseEntry, u []fr.Element, cols int) []fr.Element {
	out := make([]fr.Element, cols)
	for _, e := range entries {
		var t fr.Element
		t.Mul(&e.Val, &u[e.Row])
		out[e.Col].Add(&out[e.Col], &t)
	}

	return out
}

// sparseEval returns M~(rowPoint, colPoint) = sum over non-zeros of
// val * eq(row, rowPoint) * eq(col, colPoint), from the two eq tables. It costs one
// multiply-add per non-zero, which is what makes the verifier's selector checks
// cheap.
func sparseEval(entries []SparseEntry, rowEq, colEq []fr.Element) fr.Element {
	var out fr.Element
	for _, e := range entries {
		var t fr.Element
		t.Mul(&e.Val, &rowEq[e.Row])
		t.Mul(&t, &colEq[e.Col])
		out.Add(&out, &t)
	}

	return out
}

// formValue returns L(w) for one affine form.
func formValue(f AffineForm, w []fr.Element) fr.Element {
	out := f.Const
	for _, e := range f.Coeffs {
		var t fr.Element
		t.Mul(&e.Val, &w[e.Col])
		out.Add(&out, &t)
	}

	return out
}

// formLinearTable returns the linear part of L as a dense n-vector.
func formLinearTable(f AffineForm, n int) []fr.Element {
	out := make([]fr.Element, n)
	for _, e := range f.Coeffs {
		out[e.Col].Add(&out[e.Col], &e.Val)
	}

	return out
}

// phiValue returns Phi at the form values z.
func phiValue(phi []Monomial, z []fr.Element) fr.Element {
	var out fr.Element
	for _, m := range phi {
		t := m.Coeff
		for _, v := range m.Vars {
			t.Mul(&t, &z[v])
		}
		out.Add(&out, &t)
	}

	return out
}

// fromZr converts a mathlib scalar into a field element.
func fromZr(z *mathlib.Zr) fr.Element {
	var e fr.Element
	e.SetBytes(z.Bytes())

	return e
}

// fromG1 converts a mathlib point into an affine point, checking subgroup
// membership.
func fromG1(g *mathlib.G1) (bls12381.G1Affine, error) {
	var p bls12381.G1Affine
	if g == nil {
		return p, errors.Wrap(ErrMalformedProof, "group element is nil")
	}
	if _, err := p.SetBytes(g.Bytes()); err != nil {
		return p, errors.Wrap(err, "failed to decode group element")
	}

	return p, nil
}

// scale returns s * p.
func scale(p bls12381.G1Affine, s fr.Element) bls12381.G1Affine {
	var bi big.Int
	s.BigInt(&bi)
	var out bls12381.G1Affine
	out.ScalarMultiplication(&p, &bi)

	return out
}

// add returns a + b.
func add(a, b bls12381.G1Affine) bls12381.G1Affine {
	var out bls12381.G1Affine
	out.Add(&a, &b)

	return out
}

// neg returns -a.
func neg(a bls12381.G1Affine) bls12381.G1Affine {
	var out bls12381.G1Affine
	out.Neg(&a)

	return out
}

// msm returns sum_i scalars[i] * points[i].
func msm(points []bls12381.G1Affine, scalars []fr.Element) (bls12381.G1Affine, error) {
	var out bls12381.G1Affine
	if len(points) == 0 {
		return out, nil
	}
	var acc bls12381.G1Jac
	if _, err := acc.MultiExp(points, scalars, ecc.MultiExpConfig{}); err != nil {
		return out, errors.Wrap(err, "multi-scalar multiplication failed")
	}
	out.FromJacobian(&acc)

	return out, nil
}

// EqTable returns the table of eq(point, x) over the hypercube, entry i holding
// eq(point, <i>) with <i> the little-endian bits of i and point in table order.
// With point = Outcome.Tau these are the weights of the column aggregates, which a
// caller needs to prove statements about them.
func EqTable(point []fr.Element) []fr.Element { return eqTable(point) }
