/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pivot

import (
	"math/big"
	"testing"

	mathlib "github.com/IBM/mathlib"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/sumcheck"
	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/titan"
)

func testCurve() *mathlib.Curve { return mathlib.Curves[mathlib.BLS12_381_BBS] }

func randFr(t *testing.T) fr.Element {
	t.Helper()
	var e fr.Element
	_, err := e.SetRandom()
	require.NoError(t, err)

	return e
}

func randG1(t *testing.T) bls12381.G1Affine {
	t.Helper()
	_, _, g, _ := bls12381.Generators()

	return scale(g, randFr(t))
}

func frU(v uint64) fr.Element {
	var e fr.Element
	e.SetUint64(v)

	return e
}

func frNeg(v uint64) fr.Element {
	e := frU(v)
	e.Neg(&e)

	return e
}

// testGenerators returns n distinct generators for the field commitment.
func testGenerators(n int) []bls12381.G1Affine {
	_, _, g, _ := bls12381.Generators()
	out := make([]bls12381.G1Affine, n)
	for i := range out {
		out[i].ScalarMultiplication(&g, big.NewInt(int64(5*i+7)))
	}

	return out
}

// fixture is a relation, a statement and a witness that satisfies them.
type fixture struct {
	setup *Setup
	rel   *Relation
	st    *Statement
	wit   *Witness
}

// testRelation builds a random relation over s. The field constraint is
//
//	Phi = Z0 Z1 - Z2 + 7 (Z3^2 - Z3),  L0 = w0, L1 = w1, L2 = w2 + 5, L3 = w3,
//
// so an instance satisfies it when w2 = w0 w1 - 5 and w3 is a bit: a product, a
// constant term and a bit constraint, which exercises every kind of monomial.
func testRelation(t *testing.T, s Sizes, withPhi bool) *Relation {
	t.Helper()
	rel := &Relation{G0: randG1(t)}
	rel.Alpha = make([]fr.Element, s.C())
	for i := range rel.Alpha {
		rel.Alpha[i] = randFr(t)
	}
	for b := range s.C() {
		for _, col := range []int{b % s.N(), (3*b + 5) % s.N()} {
			rel.B = append(rel.B, SparseEntry{Row: b, Col: col, Val: randFr(t)})
		}
	}
	for y := range s.L() {
		for _, col := range []int{(2*y + 1) % s.N(), (7*y + 4) % s.N()} {
			rel.Gamma = append(rel.Gamma, SparseEntry{Row: y, Col: col, Val: randFr(t)})
		}
	}
	rel.G = make([]bls12381.G1Affine, s.L())
	for i := range rel.G {
		rel.G[i] = randG1(t)
	}
	// The public table: every column has a constant coefficient, and column 1 is
	// also multiplied by a field slot, so SC1Pub carries both kinds of term.
	rel.AlphaPub = make([]fr.Element, publicWidth)
	for i := range rel.AlphaPub {
		rel.AlphaPub[i] = randFr(t)
	}
	rel.BPub = []SparseEntry{{Row: 1, Col: 5 % s.N(), Val: randFr(t)}, {Row: 3, Col: 6 % s.N(), Val: randFr(t)}}
	if withPhi {
		one := fr.One()
		rel.Forms = []AffineForm{
			{Coeffs: []LinearEntry{{Col: 0, Val: one}}},
			{Coeffs: []LinearEntry{{Col: 1, Val: one}}},
			{Coeffs: []LinearEntry{{Col: 2, Val: one}}, Const: frU(5)},
			{Coeffs: []LinearEntry{{Col: 3, Val: one}}},
		}
		rel.Phi = []Monomial{
			{Coeff: one, Vars: []int{0, 1}},
			{Coeff: frNeg(1), Vars: []int{2}},
			{Coeff: frU(7), Vars: []int{3, 3}},
			{Coeff: frNeg(7), Vars: []int{3}},
		}
	}

	return rel
}

// publicWidth is the width of the fixtures' public table.
const publicWidth = 4

// publicTerm returns sum_t (AlphaPub_t + (BPub w)_t) x_t.
func publicTerm(rel *Relation, w []fr.Element, x []bls12381.G1Affine) bls12381.G1Affine {
	var acc bls12381.G1Affine
	bw := sparseApply(rel.BPub, w, len(x))
	for i := range x {
		var c fr.Element
		c.Add(&rel.AlphaPub[i], &bw[i])
		acc = add(acc, scale(x[i], c))
	}

	return acc
}

// balance sets the last group slot so that the group equation of (g, w, x) holds.
func balance(t *testing.T, rel *Relation, s Sizes, w []fr.Element, g, x []bls12381.G1Affine) {
	t.Helper()
	bw := sparseApply(rel.B, w, s.C())
	gw := sparseApply(rel.Gamma, w, s.L())
	rest := add(rel.G0, publicTerm(rel, w, x))
	last := s.C() - 1
	for b := range last {
		var c fr.Element
		c.Add(&rel.Alpha[b], &bw[b])
		rest = add(rest, scale(g[b], c))
	}
	for y := range s.L() {
		rest = add(rest, scale(rel.G[y], gw[y]))
	}
	var c fr.Element
	c.Add(&rel.Alpha[last], &bw[last])
	require.False(t, c.IsZero())
	c.Inverse(&c)
	g[last] = neg(scale(rest, c))
}

// satisfyingInstance returns an instance of rel with its public row. bit is the
// value of w3.
func satisfyingInstance(t *testing.T, rel *Relation, s Sizes, bit uint64) ([]fr.Element, []bls12381.G1Affine, []bls12381.G1Affine) {
	t.Helper()
	w := make([]fr.Element, s.N())
	for i := range w {
		w[i] = randFr(t)
	}
	w[2].Mul(&w[0], &w[1])
	five := frU(5)
	w[2].Sub(&w[2], &five)
	w[3] = frU(bit)

	g := make([]bls12381.G1Affine, s.C())
	for i := range g {
		g[i] = randG1(t)
	}
	x := make([]bls12381.G1Affine, publicWidth)
	for i := range x {
		x[i] = randG1(t)
	}
	balance(t, rel, s, w, g, x)

	return w, g, x
}

// checkInstance evaluates f(g, w) directly, as an independent oracle for the tests.
func checkInstance(rel *Relation, s Sizes, w []fr.Element, g, x []bls12381.G1Affine) (bool, bool) {
	bw := sparseApply(rel.B, w, s.C())
	gw := sparseApply(rel.Gamma, w, s.L())
	acc := add(rel.G0, publicTerm(rel, w, x))
	for b := range s.C() {
		var c fr.Element
		c.Add(&rel.Alpha[b], &bw[b])
		acc = add(acc, scale(g[b], c))
	}
	for y := range s.L() {
		acc = add(acc, scale(rel.G[y], gw[y]))
	}
	z := make([]fr.Element, len(rel.Forms))
	for k, f := range rel.Forms {
		z[k] = formValue(f, w)
	}
	phi := phiValue(rel.Phi, z)

	return acc.IsInfinity(), phi.IsZero()
}

func newFixture(t *testing.T, s Sizes, opts SetupOptions, withPhi bool) *fixture {
	t.Helper()
	split := titan.DefaultMatrixSplit(s.LogN + s.LogK)
	if opts.FieldSplit != nil {
		split = *opts.FieldSplit
	}
	setup, err := NewSetup(s, testGenerators(split.Cols()), testCurve(), opts)
	require.NoError(t, err)

	rel := testRelation(t, s, withPhi)
	wit := &Witness{W: make([][]fr.Element, s.K()), H: make([][]bls12381.G1Affine, s.K())}
	st := &Statement{Public: make([][]bls12381.G1Affine, s.K()), RevealCols: []int{1}}
	for k := range s.K() {
		wit.W[k], wit.H[k], st.Public[k] = satisfyingInstance(t, rel, s, uint64(k%2))
		okG, okF := checkInstance(rel, s, wit.W[k], wit.H[k], st.Public[k])
		require.True(t, okG && okF, "fixture instance %d must satisfy the relation", k)
	}

	return &fixture{setup: setup, rel: rel, st: st, wit: wit}
}

// prove runs Commit and Prove on fresh transcripts.
func (f *fixture) prove(t *testing.T) (Commitments, *Proof) {
	t.Helper()
	tr := NewTranscript(f.setup.Curve())
	c, err := Commit(f.setup, f.wit, tr)
	require.NoError(t, err)
	proof, _, err := Prove(f.setup, f.rel, f.st, c, tr)
	require.NoError(t, err)

	return c.Commitments(), proof
}

// verify runs AbsorbCommitments and Verify on a fresh transcript.
func (f *fixture) verify(coms Commitments, proof *Proof) (*Outcome, error) {
	tr := NewTranscript(f.setup.Curve())
	if err := AbsorbCommitments(f.setup, coms, tr); err != nil {
		return nil, err
	}

	return Verify(f.setup, f.rel, f.st, coms, proof, tr)
}

var (
	// sizesDefault commits W over 8 variables, which the balanced split folds.
	sizesDefault = Sizes{LogN: 4, LogC: 2, LogL: 2, LogK: 4}
	// sizesSplit commits W over 6 variables, which needs an explicit split.
	sizesSplit = Sizes{LogN: 4, LogC: 2, LogL: 1, LogK: 2}
	splitSix   = titan.Split{M: 6, M1: 2}
)

func TestRoundTrip(t *testing.T) {
	cases := map[string]struct {
		sizes   Sizes
		opts    SetupOptions
		withPhi bool
	}{
		"default split":       {sizesDefault, SetupOptions{}, true},
		"explicit split":      {sizesSplit, SetupOptions{FieldSplit: &splitSix}, true},
		"no field constraint": {sizesDefault, SetupOptions{}, false},
		"no public table":     {sizesDefault, SetupOptions{}, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, tc.sizes, tc.opts, tc.withPhi)
			if name == "no public table" {
				// Fold the public row into G0's place: drop the table and make
				// every instance's public term zero by zeroing its coefficients.
				f.rel.AlphaPub, f.rel.BPub = nil, nil
				for k := range f.st.Public {
					balance(t, f.rel, tc.sizes, f.wit.W[k], f.wit.H[k], nil)
				}
				f.st.Public = nil
			}
			coms, proof := f.prove(t)
			out, err := f.verify(coms, proof)
			require.NoError(t, err)

			// The revealed aggregate is exactly sum_k eq(k, tau) H[k][1].
			want, err := columnAggregate(f.wit.H, 1, eqTable(out.Tau))
			require.NoError(t, err)
			require.Len(t, out.Revealed, 1)
			assert.True(t, out.Revealed[0].Equal(&want))
		})
	}
}

// The test that shows aggregation happened: K-1 honest instances and one violating
// instance must be rejected, whichever equation it violates.
func TestOneBadInstanceAmongK(t *testing.T) {
	const bad = 5

	t.Run("group equation", func(t *testing.T) {
		f := newFixture(t, sizesDefault, SetupOptions{}, true)
		// Perturb a private group slot of one instance.
		f.wit.H[bad][2] = add(f.wit.H[bad][2], randG1(t))
		okG, okF := checkInstance(f.rel, sizesDefault, f.wit.W[bad], f.wit.H[bad], f.st.Public[bad])
		require.False(t, okG)
		require.True(t, okF)

		coms, proof := f.prove(t)
		_, err := f.verify(coms, proof)
		require.ErrorIs(t, err, ErrVerificationFailed)
	})

	t.Run("field constraint", func(t *testing.T) {
		f := newFixture(t, sizesDefault, SetupOptions{}, true)
		// w3 = 2 is not a bit. Rebalance so that only the field constraint fails.
		f.wit.W[bad][3] = frU(2)
		balance(t, f.rel, sizesDefault, f.wit.W[bad], f.wit.H[bad], f.st.Public[bad])
		okG, okF := checkInstance(f.rel, sizesDefault, f.wit.W[bad], f.wit.H[bad], f.st.Public[bad])
		require.True(t, okG)
		require.False(t, okF)

		coms, proof := f.prove(t)
		_, err := f.verify(coms, proof)
		require.ErrorIs(t, err, ErrVerificationFailed)
	})
}

// The public table is not committed: it enters the group equations directly. A
// statement whose public row does not match the witness therefore breaks that
// instance's group equation, even though prover and verifier agree on it.
func TestPublicTableMismatchRejected(t *testing.T) {
	t.Run("statement disagrees with the witness", func(t *testing.T) {
		for _, col := range []int{0, 1} { // 1 also carries a BPub term
			f := newFixture(t, sizesDefault, SetupOptions{}, true)
			f.st.Public[3][col] = randG1(t)
			coms, proof := f.prove(t)
			_, err := f.verify(coms, proof)
			require.ErrorIs(t, err, ErrVerificationFailed, "column %d", col)
		}
	})

	t.Run("statement changed after proving", func(t *testing.T) {
		// The statement is bound into the transcript, so a verifier holding a
		// different one draws different challenges.
		f := newFixture(t, sizesDefault, SetupOptions{}, true)
		coms, proof := f.prove(t)
		f.st.Public[3] = append([]bls12381.G1Affine(nil), f.st.Public[3]...)
		f.st.Public[3][2] = randG1(t)
		_, err := f.verify(coms, proof)
		require.Error(t, err)
	})
}

func TestTamperedProofRejected(t *testing.T) {
	f := newFixture(t, sizesDefault, SetupOptions{}, true)
	coms, proof := f.prove(t)

	one := fr.One()
	bump := func(e fr.Element) fr.Element {
		e.Add(&e, &one)

		return e
	}
	cases := map[string]func(p *Proof){
		"PEval": func(p *Proof) { p.PEval = bump(p.PEval) },
		"GEval": func(p *Proof) { p.GEval = add(p.GEval, randG1(t)) },
		"QEval": func(p *Proof) { p.QEval = bump(p.QEval) },
		"FormEvals": func(p *Proof) {
			p.FormEvals = append([]fr.Element(nil), p.FormEvals...)
			p.FormEvals[2] = bump(p.FormEvals[2])
		},
		"WEvals[0]": func(p *Proof) { p.WEvals = append([]fr.Element(nil), p.WEvals...); p.WEvals[0] = bump(p.WEvals[0]) },
		"WEvals[1]": func(p *Proof) { p.WEvals = append([]fr.Element(nil), p.WEvals...); p.WEvals[1] = bump(p.WEvals[1]) },
		"WEvals[2]": func(p *Proof) { p.WEvals = append([]fr.Element(nil), p.WEvals...); p.WEvals[2] = bump(p.WEvals[2]) },
		"WOpen":     func(p *Proof) { p.WOpen = bump(p.WOpen) },
		"GOpen":     func(p *Proof) { p.GOpen = add(p.GOpen, randG1(t)) },
		"Revealed": func(p *Proof) {
			p.Revealed = append([]bls12381.G1Affine(nil), p.Revealed...)
			p.Revealed[0] = add(p.Revealed[0], randG1(t))
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			bad := *proof
			tamper(&bad)
			_, err := f.verify(coms, &bad)
			require.Error(t, err)
		})
	}

	t.Run("honest proof still verifies", func(t *testing.T) {
		_, err := f.verify(coms, proof)
		require.NoError(t, err)
	})
}

func TestWrongCommitmentRejected(t *testing.T) {
	f := newFixture(t, sizesDefault, SetupOptions{}, true)
	coms, proof := f.prove(t)

	other := newFixture(t, sizesDefault, SetupOptions{}, true)
	other.setup, other.rel, other.st = f.setup, f.rel, f.st
	otherComs, _ := other.prove(t)

	_, err := f.verify(Commitments{W: otherComs.W, G: coms.G}, proof)
	require.Error(t, err)
	_, err = f.verify(Commitments{W: coms.W, G: otherComs.G}, proof)
	require.Error(t, err)
}

func TestMalformedProof(t *testing.T) {
	f := newFixture(t, sizesDefault, SetupOptions{}, true)
	coms, proof := f.prove(t)

	cases := map[string]func(p *Proof){
		"missing SC2":         func(p *Proof) { p.SC2 = nil },
		"missing SC3":         func(p *Proof) { p.SC3 = nil },
		"missing field PCS":   func(p *Proof) { p.WPCS = nil },
		"short WEvals":        func(p *Proof) { p.WEvals = p.WEvals[:2] },
		"short FormEvals":     func(p *Proof) { p.FormEvals = p.FormEvals[:1] },
		"extra revealed":      func(p *Proof) { p.Revealed = append(p.Revealed, p.Revealed[0]) },
		"missing group batch": func(p *Proof) { p.GBatch = nil },
		"missing SC1Pub":      func(p *Proof) { p.SC1Pub = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			bad := *proof
			mutate(&bad)
			_, err := f.verify(coms, &bad)
			require.ErrorIs(t, err, ErrMalformedProof)
		})
	}
}

// A relation may depend on challenges drawn after the commitments, as the UTXO
// instantiation's collapse does. Both sides squeeze the same challenge from the
// transcript between the commitment phase and Prove/Verify.
func TestRelationFromPostCommitmentChallenge(t *testing.T) {
	f := newFixture(t, sizesDefault, SetupOptions{}, true)

	// Scale every monomial of Phi by the challenge: the constraint still holds.
	withChallenge := func(xi fr.Element) *Relation {
		r := *f.rel
		r.Phi = make([]Monomial, len(f.rel.Phi))
		for m, mono := range f.rel.Phi {
			r.Phi[m] = mono
			r.Phi[m].Coeff.Mul(&mono.Coeff, &xi)
		}

		return &r
	}

	ptr := NewTranscript(f.setup.Curve())
	c, err := Commit(f.setup, f.wit, ptr)
	require.NoError(t, err)
	xi, err := squeezeFr(ptr)
	require.NoError(t, err)
	proof, pOut, err := Prove(f.setup, withChallenge(xi), f.st, c, ptr)
	require.NoError(t, err)

	vtr := NewTranscript(f.setup.Curve())
	require.NoError(t, AbsorbCommitments(f.setup, c.Commitments(), vtr))
	vxi, err := squeezeFr(vtr)
	require.NoError(t, err)
	vOut, err := Verify(f.setup, withChallenge(vxi), f.st, c.Commitments(), proof, vtr)
	require.NoError(t, err)
	// Prover and verifier agree on the outcome.
	require.Len(t, pOut.Tau, len(vOut.Tau))
	for i := range pOut.Tau {
		assert.True(t, pOut.Tau[i].Equal(&vOut.Tau[i]))
	}

	// A verifier that skips the challenge is in a different transcript state.
	vtr = NewTranscript(f.setup.Curve())
	require.NoError(t, AbsorbCommitments(f.setup, c.Commitments(), vtr))
	_, err = Verify(f.setup, withChallenge(vxi), f.st, c.Commitments(), proof, vtr)
	require.Error(t, err)
}

// tablePoint is the single place the sum-check's folding order is turned into
// table order; pin it against sumcheck's own two evaluators.
func TestTablePointOrder(t *testing.T) {
	curve := testCurve()
	p := make(sumcheck.FieldPoly, 1<<5)
	for i := range p {
		p[i] = randFr(t)
	}
	r := make([]*mathlib.Zr, 5)
	folding := make([]fr.Element, 5)
	for i := range r {
		e := randFr(t)
		b := e.Bytes()
		r[i] = curve.NewZrFromBytes(b[:])
		folding[i] = e
	}
	byOpening, err := p.EvaluateOpening(folding)
	require.NoError(t, err)
	byPoint, err := p.EvaluatePoint(tablePoint(r))
	require.NoError(t, err)
	assert.True(t, byOpening.Equal(&byPoint))
}

func TestSetupValidation(t *testing.T) {
	gens := testGenerators(16)
	_, err := NewSetup(Sizes{LogN: 4, LogC: 1, LogL: 2, LogK: 4}, gens, testCurve(), SetupOptions{})
	require.ErrorIs(t, err, ErrInvalidSizes, "log c + log K odd")
	_, err = NewSetup(Sizes{LogN: 0, LogC: 2, LogL: 2, LogK: 4}, gens, testCurve(), SetupOptions{})
	require.ErrorIs(t, err, ErrInvalidSizes)
	bad := titan.Split{M: 7, M1: 3}
	_, err = NewSetup(sizesDefault, gens, testCurve(), SetupOptions{FieldSplit: &bad})
	require.ErrorIs(t, err, ErrInvalidSizes)
}

func TestInputValidation(t *testing.T) {
	f := newFixture(t, sizesDefault, SetupOptions{}, true)
	tr := NewTranscript(f.setup.Curve())

	_, err := Commit(f.setup, &Witness{W: f.wit.W[:3], H: f.wit.H}, tr)
	require.ErrorIs(t, err, ErrInvalidWitness)

	c, err := Commit(f.setup, f.wit, tr)
	require.NoError(t, err)

	badRel := *f.rel
	badRel.B = append([]SparseEntry(nil), f.rel.B...)
	badRel.B[0].Col = sizesDefault.N()
	_, _, err = Prove(f.setup, &badRel, f.st, c, tr)
	require.ErrorIs(t, err, ErrInvalidRelation)

	badRel = *f.rel
	badRel.Phi = []Monomial{{Coeff: fr.One(), Vars: []int{9}}}
	_, _, err = Prove(f.setup, &badRel, f.st, c, tr)
	require.ErrorIs(t, err, ErrInvalidRelation)

	_, _, err = Prove(f.setup, f.rel, &Statement{Public: f.st.Public[:3]}, c, tr)
	require.ErrorIs(t, err, ErrInvalidStatement)
	_, _, err = Prove(f.setup, f.rel, &Statement{Public: [][]bls12381.G1Affine{{randG1(t)}}}, c, tr)
	require.ErrorIs(t, err, ErrInvalidStatement)
	// A relation with public coefficients but a statement without a table.
	_, _, err = Prove(f.setup, f.rel, &Statement{}, c, tr)
	require.ErrorIs(t, err, ErrInvalidRelation)
	_, _, err = Prove(f.setup, f.rel, &Statement{RevealCols: []int{sizesDefault.C()}}, c, tr)
	require.ErrorIs(t, err, ErrInvalidStatement)
}
