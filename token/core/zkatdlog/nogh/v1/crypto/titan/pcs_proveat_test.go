/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A protocol that commits first and derives its evaluation point from later
// challenges builds the prover with no point and opens with ProveAt. One
// commitment must then open correctly at every point it is asked for.
func TestFieldPCSProveAtDeferredPoint(t *testing.T) {
	t.Parallel()

	setup, _, w := newFieldPCS(t, 8)
	prover, err := NewFieldProver(setup, FieldStatement{}, w)
	require.NoError(t, err)

	for range 3 {
		alpha := randomPoint(t, 8)
		proof, sigma, err := prover.ProveAt(alpha)
		require.NoError(t, err)

		want, err := w.Poly.EvaluatePoint(alpha)
		require.NoError(t, err)
		assert.True(t, sigma.Equal(&want), "sigma must be the polynomial at alpha")

		verifier, err := NewFieldVerifier(setup, FieldStatement{Alpha: alpha}, prover.Commitment())
		require.NoError(t, err)
		require.NoError(t, verifier.VerifyErr(proof, sigma))
	}

	// Without a point Prove has nothing to open at.
	_, _, err = prover.Prove()
	require.ErrorIs(t, err, ErrNumVarsMismatch)

	_, _, err = prover.ProveAt(randomPoint(t, 7))
	require.ErrorIs(t, err, ErrNumVarsMismatch)
}

func TestGroupPCSProveAtDeferredPoint(t *testing.T) {
	t.Parallel()

	setup, _, w := newGroupPCS(t, 6)
	prover, err := NewGroupProver(setup, GroupStatement{}, w)
	require.NoError(t, err)

	for range 3 {
		alpha := randomPoint(t, 6)
		proof, sigma, err := prover.ProveAt(alpha)
		require.NoError(t, err)

		want, err := w.Poly.EvaluatePoint(alpha)
		require.NoError(t, err)
		assert.True(t, sigma.Equal(&want), "sigma must be the polynomial at alpha")

		verifier, err := NewGroupVerifier(setup, GroupStatement{Alpha: alpha}, prover.Commitment())
		require.NoError(t, err)
		require.NoError(t, verifier.VerifyErr(proof, &sigma))
	}

	_, _, err = prover.Prove()
	require.ErrorIs(t, err, ErrNumVarsMismatch)

	_, _, err = prover.ProveAt(randomPoint(t, 5))
	require.ErrorIs(t, err, ErrNumVarsMismatch)
}
