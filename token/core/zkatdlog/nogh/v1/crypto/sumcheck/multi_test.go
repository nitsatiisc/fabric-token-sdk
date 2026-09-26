/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sumcheck

import (
	"testing"

	mathlib "github.com/IBM/mathlib"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/rp/csp"
)

// frInt returns the field element v, which may be negative.
func frInt(v int64) fr.Element {
	var e fr.Element
	if v < 0 {
		e.SetUint64(uint64(-v))
		e.Neg(&e)

		return e
	}
	e.SetUint64(uint64(v))

	return e
}

// phiClaim builds Phi(h_0, h_1, h_2) = 3*h_0*h_1 - h_2*h_2*h_0 + 5*h_1 on random
// multilinears: a square, a repeated pool entry across terms, and terms of three
// different degrees, so the round degree is 3 and two terms are shorter.
func phiClaim(t *testing.T, curve *mathlib.Curve, numVars int) *MultiClaim {
	t.Helper()
	_, rng := testCurve(t)
	polys := []FieldPoly{
		randomFieldPoly(t, curve, rng, numVars),
		randomFieldPoly(t, curve, rng, numVars),
		randomFieldPoly(t, curve, rng, numVars),
	}

	return &MultiClaim{
		Polys: polys,
		Terms: []Term{
			{Coeff: frInt(3), Factors: []int{0, 1}},
			{Coeff: frInt(-1), Factors: []int{2, 2, 0}},
			{Coeff: frInt(5), Factors: []int{1}},
		},
	}
}

// bruteForceMulti sums the claim's polynomial over the hypercube directly.
func bruteForceMulti(c *MultiClaim) fr.Element {
	var total fr.Element
	vals := make([]fr.Element, len(c.Polys))
	for x := range len(c.Polys[0]) {
		for i, p := range c.Polys {
			vals[i] = p[x]
		}
		v, _ := c.Evaluate(vals)
		total.Add(&total, &v)
	}

	return total
}

func TestMultiRoundTrip(t *testing.T) {
	curve, _ := testCurve(t)
	for numVars := 1; numVars <= 6; numVars++ {
		claim := phiClaim(t, curve, numVars)
		assert.Equal(t, 3, claim.Degree())

		proof, pOpen, err := ProveMulti(curve, claim)
		require.NoError(t, err)

		want := bruteForceMulti(claim)
		got := fromZr(proof.FieldSum)
		assert.True(t, got.Equal(&want), "claimed sum must equal the brute-force sum at %d variables", numVars)

		vOpen, err := VerifyMulti(curve, claim.Shape(), proof)
		require.NoError(t, err)

		// Prover and verifier agree on the point, and the pool values the prover
		// reports are the pool polynomials evaluated there.
		require.Len(t, vOpen.R, numVars)
		evals := make([]fr.Element, len(claim.Polys))
		for j := range vOpen.R {
			assert.True(t, pOpen.R[j].Equals(vOpen.R[j]))
		}
		for i, p := range claim.Polys {
			at := make([]fr.Element, numVars)
			for j := range at {
				at[j] = fromZr(vOpen.R[j])
			}
			e, err := p.EvaluateOpening(at)
			require.NoError(t, err)
			reported := fromZr(pOpen.FieldEvals[i])
			assert.True(t, reported.Equal(&e), "pool entry %d", i)
			evals[i] = e
		}

		// The verifier's Product is Phi at the pool values: this is how a caller
		// closes the argument.
		phi, err := EvaluateTerms(claim.Terms, evals)
		require.NoError(t, err)
		product := fromZr(vOpen.Product)
		assert.True(t, product.Equal(&phi))
	}
}

// A MultiClaim with one term is a single product, so under the same transcript it
// must produce exactly the proof Prove produces for the equivalent Claim.
func TestMultiSingleTermMatchesClaim(t *testing.T) {
	curve, rng := testCurve(t)
	f := randomFieldPoly(t, curve, rng, 5)
	g := randomFieldPoly(t, curve, rng, 5)

	newTr := func() *csp.Transcript {
		tr := &csp.Transcript{Curve: curve}
		tr.InitHasherWithDomain("multi-vs-single")

		return tr
	}

	single, sOpen, err := ProveWithTranscript(curve, &Claim{Field: []FieldPoly{f, g}}, newTr())
	require.NoError(t, err)
	multi, mOpen, err := ProveMultiWithTranscript(curve, &MultiClaim{
		Polys: []FieldPoly{f, g},
		Terms: []Term{{Coeff: fr.One(), Factors: []int{0, 1}}},
	}, newTr())
	require.NoError(t, err)

	require.Len(t, multi.FieldRounds, len(single.FieldRounds))
	for r := range single.FieldRounds {
		for i := range single.FieldRounds[r] {
			assert.True(t, single.FieldRounds[r][i].Equals(multi.FieldRounds[r][i]), "round %d eval %d", r, i)
		}
	}
	for i := range sOpen.FieldEvals {
		assert.True(t, sOpen.FieldEvals[i].Equals(mOpen.FieldEvals[i]))
	}
}

func TestMultiRejectsTampering(t *testing.T) {
	curve, _ := testCurve(t)
	claim := phiClaim(t, curve, 4)
	proof, _, err := ProveMulti(curve, claim)
	require.NoError(t, err)

	t.Run("claimed sum", func(t *testing.T) {
		bad := *proof
		bad.FieldSum = proof.FieldSum.Plus(curve.NewZrFromInt(1))
		_, err := VerifyMulti(curve, claim.Shape(), &bad)
		require.ErrorIs(t, err, ErrSumMismatch)
	})
	t.Run("round polynomial", func(t *testing.T) {
		bad := *proof
		bad.FieldRounds = make([][]*mathlib.Zr, len(proof.FieldRounds))
		copy(bad.FieldRounds, proof.FieldRounds)
		round := append([]*mathlib.Zr(nil), proof.FieldRounds[2]...)
		round[3] = round[3].Plus(curve.NewZrFromInt(1))
		bad.FieldRounds[2] = round
		_, err := VerifyMulti(curve, claim.Shape(), &bad)
		require.Error(t, err)
	})
	t.Run("degree", func(t *testing.T) {
		shape := claim.Shape()
		shape.Degree = 2
		_, err := VerifyMulti(curve, shape, proof)
		require.ErrorIs(t, err, ErrRoundDegreeMismatch)
	})
	t.Run("replayed as a single-product proof", func(t *testing.T) {
		// Same numVars and degree, but the kind byte of the transcript header
		// differs, so the challenges diverge and a round check fails.
		_, err := Verify(curve, Shape{NumVars: 4, NumFieldFactors: 3}, proof)
		require.Error(t, err)
	})
}

func TestMultiValidation(t *testing.T) {
	curve, rng := testCurve(t)
	f := randomFieldPoly(t, curve, rng, 3)
	g := randomFieldPoly(t, curve, rng, 4)

	cases := map[string]struct {
		claim *MultiClaim
		err   error
	}{
		"no terms":                {&MultiClaim{Polys: []FieldPoly{f}}, ErrNoFactors},
		"no polys":                {&MultiClaim{Terms: []Term{{Coeff: fr.One(), Factors: []int{0}}}}, ErrNoFactors},
		"empty term":              {&MultiClaim{Polys: []FieldPoly{f}, Terms: []Term{{Coeff: fr.One()}}}, ErrNoFactors},
		"index out of range":      {&MultiClaim{Polys: []FieldPoly{f}, Terms: []Term{{Coeff: fr.One(), Factors: []int{1}}}}, ErrFactorIndex},
		"negative index":          {&MultiClaim{Polys: []FieldPoly{f}, Terms: []Term{{Coeff: fr.One(), Factors: []int{-1}}}}, ErrFactorIndex},
		"variable mismatch":       {&MultiClaim{Polys: []FieldPoly{f, g}, Terms: []Term{{Coeff: fr.One(), Factors: []int{0, 1}}}}, ErrNumVarsMismatch},
		"not a power of two":      {&MultiClaim{Polys: []FieldPoly{f[:3]}, Terms: []Term{{Coeff: fr.One(), Factors: []int{0}}}}, ErrNotPowerOfTwo},
		"single-point polynomial": {&MultiClaim{Polys: []FieldPoly{f[:1]}, Terms: []Term{{Coeff: fr.One(), Factors: []int{0}}}}, ErrNumVarsMismatch},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := ProveMulti(curve, tc.claim)
			require.ErrorIs(t, err, tc.err)
		})
	}

	_, err := EvaluateTerms([]Term{{Coeff: fr.One(), Factors: []int{2}}}, []fr.Element{fr.One()})
	require.ErrorIs(t, err, ErrFactorIndex)
}
