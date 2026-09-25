/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sumcheck

import (
	"testing"

	mathlib "github.com/IBM/mathlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cloneProof deep-copies a proof so a test can tamper with one field in
// isolation.
func cloneProof(p *Proof) *Proof {
	out := &Proof{FieldSum: p.FieldSum, GroupSum: p.GroupSum}
	if p.FieldRounds != nil {
		out.FieldRounds = make([][]*mathlib.Zr, len(p.FieldRounds))
		for i, r := range p.FieldRounds {
			out.FieldRounds[i] = make([]*mathlib.Zr, len(r))
			copy(out.FieldRounds[i], r)
		}
	}
	if p.GroupRounds != nil {
		out.GroupRounds = make([][]*mathlib.G1, len(p.GroupRounds))
		for i, r := range p.GroupRounds {
			out.GroupRounds[i] = make([]*mathlib.G1, len(r))
			copy(out.GroupRounds[i], r)
		}
	}

	return out
}

// TestFieldSoundness covers the ways a field proof can be malformed or forged.
func TestFieldSoundness(t *testing.T) {
	curve, rng := testCurve(t)
	const numVars = 4
	const numFactors = 2
	shape := Shape{NumVars: numVars, NumFieldFactors: numFactors}

	build := func(t *testing.T) *Proof {
		t.Helper()
		factors := make([]FieldPoly, numFactors)
		for i := range factors {
			factors[i] = randomFieldPoly(t, curve, rng, numVars)
		}
		proof, _, err := Prove(curve, &Claim{Field: factors})
		require.NoError(t, err)

		return proof
	}

	// Sanity: the unmodified proof verifies, so every failure below is caused by
	// the specific tamper and not by a broken fixture.
	t.Run("honest proof verifies", func(t *testing.T) {
		_, err := Verify(curve, shape, build(t))
		require.NoError(t, err)
	})

	t.Run("wrong claimed sum", func(t *testing.T) {
		p := cloneProof(build(t))
		p.FieldSum = p.FieldSum.Plus(curve.NewZrFromInt(1))

		_, err := Verify(curve, shape, p)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrSumMismatch)
	})

	t.Run("tampered first round polynomial", func(t *testing.T) {
		p := cloneProof(build(t))
		p.FieldRounds[0][0] = p.FieldRounds[0][0].Plus(curve.NewZrFromInt(1))

		_, err := Verify(curve, shape, p)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrSumMismatch)
	})

	t.Run("tampered later round polynomial", func(t *testing.T) {
		p := cloneProof(build(t))
		// Shifting one evaluation of round 2 keeps round 0 and 1 consistent, so
		// the failure must surface at the round that was altered.
		p.FieldRounds[2][0] = p.FieldRounds[2][0].Plus(curve.NewZrFromInt(1))

		_, err := Verify(curve, shape, p)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrRoundCheckFailed)
	})

	t.Run("tampered final round polynomial", func(t *testing.T) {
		p := cloneProof(build(t))
		last := len(p.FieldRounds) - 1
		p.FieldRounds[last][1] = p.FieldRounds[last][1].Plus(curve.NewZrFromInt(1))

		_, err := Verify(curve, shape, p)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrRoundCheckFailed)
	})

	t.Run("compensating tamper is still rejected", func(t *testing.T) {
		// Move value between q(0) and q(1) so that q(0)+q(1) is unchanged. The
		// round check passes, but the interpolation at the challenge changes, so
		// the next round must fail. This is the case that would slip through if
		// the verifier only checked the sum and never interpolated.
		p := cloneProof(build(t))
		one := curve.NewZrFromInt(1)
		p.FieldRounds[0][0] = p.FieldRounds[0][0].Plus(one)
		p.FieldRounds[0][1] = p.FieldRounds[0][1].Minus(one)

		_, err := Verify(curve, shape, p)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrRoundCheckFailed)
	})

	t.Run("dropped round", func(t *testing.T) {
		p := cloneProof(build(t))
		p.FieldRounds = p.FieldRounds[:len(p.FieldRounds)-1]

		_, err := Verify(curve, shape, p)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrRoundCountMismatch)
	})

	t.Run("extra round", func(t *testing.T) {
		p := cloneProof(build(t))
		p.FieldRounds = append(p.FieldRounds, p.FieldRounds[0])

		_, err := Verify(curve, shape, p)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrRoundCountMismatch)
	})

	t.Run("round with wrong degree", func(t *testing.T) {
		p := cloneProof(build(t))
		p.FieldRounds[1] = p.FieldRounds[1][:len(p.FieldRounds[1])-1]

		_, err := Verify(curve, shape, p)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrRoundDegreeMismatch)
	})

	t.Run("nil evaluation in a round", func(t *testing.T) {
		p := cloneProof(build(t))
		p.FieldRounds[0][0] = nil

		_, err := Verify(curve, shape, p)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNilElement)
	})

	t.Run("missing claimed sum", func(t *testing.T) {
		p := cloneProof(build(t))
		p.FieldSum = nil

		_, err := Verify(curve, shape, p)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNilProof)
	})

	t.Run("field proof rejected under group shape", func(t *testing.T) {
		p := build(t)
		groupShape := shape
		groupShape.HasGroupFactor = true

		_, err := Verify(curve, groupShape, p)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrMixedProofKind)
	})

	t.Run("swapped rounds", func(t *testing.T) {
		p := cloneProof(build(t))
		p.FieldRounds[1], p.FieldRounds[2] = p.FieldRounds[2], p.FieldRounds[1]

		_, err := Verify(curve, shape, p)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrRoundCheckFailed)
	})
}

// TestGroupSoundness covers the same tampering for a claim with a group factor.
func TestGroupSoundness(t *testing.T) {
	curve, rng := testCurve(t)
	const numVars = 4
	const numFieldFactors = 1
	shape := Shape{
		NumVars:         numVars,
		NumFieldFactors: numFieldFactors,
		HasGroupFactor:  true,
	}

	build := func(t *testing.T) *Proof {
		t.Helper()
		factors := make([]FieldPoly, numFieldFactors)
		for i := range factors {
			factors[i] = randomFieldPoly(t, curve, rng, numVars)
		}
		group, _ := randomGroupPoly(t, curve, rng, numVars)
		proof, _, err := Prove(curve, &Claim{Field: factors, Group: group})
		require.NoError(t, err)

		return proof
	}

	t.Run("honest proof verifies", func(t *testing.T) {
		_, err := Verify(curve, shape, build(t))
		require.NoError(t, err)
	})

	t.Run("wrong claimed sum", func(t *testing.T) {
		p := cloneProof(build(t))
		tampered := p.GroupSum.Copy()
		tampered.Add(curve.GenG1)
		p.GroupSum = tampered

		_, err := Verify(curve, shape, p)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrSumMismatch)
	})

	t.Run("tampered first round polynomial", func(t *testing.T) {
		p := cloneProof(build(t))
		tampered := p.GroupRounds[0][0].Copy()
		tampered.Add(curve.GenG1)
		p.GroupRounds[0][0] = tampered

		_, err := Verify(curve, shape, p)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrSumMismatch)
	})

	t.Run("tampered later round polynomial", func(t *testing.T) {
		p := cloneProof(build(t))
		tampered := p.GroupRounds[2][0].Copy()
		tampered.Add(curve.GenG1)
		p.GroupRounds[2][0] = tampered

		_, err := Verify(curve, shape, p)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrRoundCheckFailed)
	})

	t.Run("compensating tamper is still rejected", func(t *testing.T) {
		p := cloneProof(build(t))
		plus := p.GroupRounds[0][0].Copy()
		plus.Add(curve.GenG1)
		minus := p.GroupRounds[0][1].Copy()
		minus.Sub(curve.GenG1)
		p.GroupRounds[0][0] = plus
		p.GroupRounds[0][1] = minus

		_, err := Verify(curve, shape, p)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrRoundCheckFailed)
	})

	t.Run("dropped round", func(t *testing.T) {
		p := cloneProof(build(t))
		p.GroupRounds = p.GroupRounds[:len(p.GroupRounds)-1]

		_, err := Verify(curve, shape, p)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrRoundCountMismatch)
	})

	t.Run("round with wrong degree", func(t *testing.T) {
		p := cloneProof(build(t))
		p.GroupRounds[1] = p.GroupRounds[1][:len(p.GroupRounds[1])-1]

		_, err := Verify(curve, shape, p)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrRoundDegreeMismatch)
	})

	t.Run("nil evaluation in a round", func(t *testing.T) {
		p := cloneProof(build(t))
		p.GroupRounds[0][0] = nil

		_, err := Verify(curve, shape, p)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNilElement)
	})

	t.Run("missing claimed sum", func(t *testing.T) {
		p := cloneProof(build(t))
		p.GroupSum = nil

		_, err := Verify(curve, shape, p)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNilProof)
	})

	t.Run("group proof rejected under field shape", func(t *testing.T) {
		p := build(t)
		fieldShape := shape
		fieldShape.HasGroupFactor = false

		_, err := Verify(curve, fieldShape, p)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrMixedProofKind)
	})
}

// TestClaimValidation covers the structural preconditions on a claim, including
// the rule that a product may contain at most one group polynomial.
func TestClaimValidation(t *testing.T) {
	curve, rng := testCurve(t)

	t.Run("nil curve", func(t *testing.T) {
		f := randomFieldPoly(t, curve, rng, 2)
		_, _, err := Prove(nil, &Claim{Field: []FieldPoly{f}})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNilCurve)
	})

	t.Run("nil claim", func(t *testing.T) {
		_, _, err := Prove(curve, nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNilPolynomial)
	})

	t.Run("no factors", func(t *testing.T) {
		_, _, err := Prove(curve, &Claim{})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNoFactors)
	})

	t.Run("nil field factor", func(t *testing.T) {
		_, _, err := Prove(curve, &Claim{Field: []FieldPoly{nil}})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNilPolynomial)
	})

	t.Run("mismatched variable counts", func(t *testing.T) {
		a := randomFieldPoly(t, curve, rng, 3)
		b := randomFieldPoly(t, curve, rng, 4)
		_, _, err := Prove(curve, &Claim{Field: []FieldPoly{a, b}})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNumVarsMismatch)
	})

	t.Run("group factor with mismatched variable count", func(t *testing.T) {
		a := randomFieldPoly(t, curve, rng, 3)
		g, _ := randomGroupPoly(t, curve, rng, 4)
		_, _, err := Prove(curve, &Claim{Field: []FieldPoly{a}, Group: g})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNumVarsMismatch)
	})

	t.Run("evaluation table not a power of two", func(t *testing.T) {
		evals := make([]*mathlib.Zr, 3)
		for i := range evals {
			evals[i] = curve.NewZrFromInt(int64(i))
		}
		_, err := NewFieldPoly(evals)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNotPowerOfTwo)
	})

	t.Run("nil element in evaluation table", func(t *testing.T) {
		evals := []*mathlib.Zr{curve.NewZrFromInt(1), nil}
		_, err := NewFieldPoly(evals)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNilElement)
	})

	t.Run("nil group evaluation table", func(t *testing.T) {
		_, err := NewGroupPoly(nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNilPolynomial)
	})

	// The type system enforces the at-most-one-group-factor rule: Claim.Group is a
	// single GroupPoly, not a slice, so a second group factor cannot be expressed.
	// This asserts the shape of the API rather than a runtime check.
	t.Run("at most one group factor is structural", func(t *testing.T) {
		g, _ := randomGroupPoly(t, curve, rng, 2)
		c := &Claim{Group: g}
		require.NoError(t, c.validate())
		assert.Equal(t, 1, c.Degree(), "a lone group factor gives degree 1")
		assert.True(t, c.IsGroup())
	})
}

// TestShapeValidation covers the verifier-side shape preconditions.
func TestShapeValidation(t *testing.T) {
	curve, rng := testCurve(t)
	f := randomFieldPoly(t, curve, rng, 3)
	proof, _, err := Prove(curve, &Claim{Field: []FieldPoly{f}})
	require.NoError(t, err)

	t.Run("nil curve", func(t *testing.T) {
		_, err := Verify(nil, Shape{NumVars: 3, NumFieldFactors: 1}, proof)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNilCurve)
	})

	t.Run("nil proof", func(t *testing.T) {
		_, err := Verify(curve, Shape{NumVars: 3, NumFieldFactors: 1}, nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNilProof)
	})

	t.Run("zero variables", func(t *testing.T) {
		_, err := Verify(curve, Shape{NumVars: 0, NumFieldFactors: 1}, proof)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNumVarsMismatch)
	})

	t.Run("no factors in shape", func(t *testing.T) {
		_, err := Verify(curve, Shape{NumVars: 3}, proof)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNoFactors)
	})

	t.Run("wrong variable count", func(t *testing.T) {
		_, err := Verify(curve, Shape{NumVars: 2, NumFieldFactors: 1}, proof)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrRoundCountMismatch)
	})
}
