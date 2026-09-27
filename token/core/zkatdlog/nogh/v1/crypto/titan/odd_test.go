/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	"fmt"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/require"
)

// Odd variable counts
//
// Nothing in the construction needs an even number of variables. The group
// sum-check splits its variables at DefaultSplit(m) = floor(m/2), a prover cost
// parameter both sides derive identically; the coset oracle needs only
// 1 <= Ell <= m; and the field path's matrix split puts floor(m/2) variables on
// the column (CSP) leg and ceil(m/2) on the row leg that the fold attaches to,
// whatever their parity. These tests pin that odd sizes are not only complete but
// reject the same forgeries as even ones.

// bump returns p + generator, a different point.
func bump(p bls12381.G1Affine) bls12381.G1Affine {
	_, _, g, _ := bls12381.Generators()
	var out bls12381.G1Affine
	out.Add(&p, &g)

	return out
}

func TestGroupPCSOddNumVars(t *testing.T) {
	t.Parallel()

	for _, m := range []int{5, 7, 9, 11} {
		t.Run(fmt.Sprintf("m=%d", m), func(t *testing.T) {
			t.Parallel()
			_, err := NewGroupSetup(m, testCurve(), FoldConfig{})
			require.ErrorIs(t, err, ErrInvalidFoldConfig, "the canonical configuration is for even m only")

			setup, err := NewGroupSetup(m, testCurve(), customFold(t, m))
			require.NoError(t, err)
			st := GroupStatement{Alpha: randomPoint(t, m)}
			w := GroupWitness{Poly: randomGroupPoly(t, m)}
			p, err := NewGroupProver(setup, st, w)
			require.NoError(t, err)
			prove := func() (*GroupEvalProof, bls12381.G1Affine) {
				proof, sigma, err := p.Prove()
				require.NoError(t, err)

				return proof, sigma
			}
			v, err := NewGroupVerifier(setup, st, p.Commitment())
			require.NoError(t, err)

			proof, sigma := prove()
			want, err := w.Poly.EvaluatePoint(st.Alpha)
			require.NoError(t, err)
			require.True(t, want.Equal(&sigma), "sigma must be G(alpha)")
			require.NoError(t, v.VerifyErr(proof, &sigma))

			wrong := bump(sigma)
			require.Error(t, v.VerifyErr(proof, &wrong), "wrong value")

			other, err := NewGroupVerifier(setup, GroupStatement{Alpha: randomPoint(t, m)}, p.Commitment())
			require.NoError(t, err)
			require.Error(t, other.VerifyErr(proof, &sigma), "wrong point")

			fp, err := NewGroupProver(setup, st, GroupWitness{Poly: randomGroupPoly(t, m)})
			require.NoError(t, err)
			foreign, fsigma, err := fp.Prove()
			require.NoError(t, err)
			require.Error(t, v.VerifyErr(foreign, &fsigma), "proof for another commitment")

			proof, sigma = prove()
			proof.RowProof.Rounds[len(proof.RowProof.Rounds)-1][0] = bump(proof.RowProof.Rounds[len(proof.RowProof.Rounds)-1][0])
			require.Error(t, v.VerifyErr(proof, &sigma), "tampered sum-check round")

			proof, sigma = prove()
			proof.Fold.Rounds[0][1] = bump(proof.Fold.Rounds[0][1])
			require.Error(t, v.VerifyErr(proof, &sigma), "tampered fold round")

			proof, sigma = prove()
			proof.Fold.Reduced[len(proof.Fold.Reduced)-1] = bump(proof.Fold.Reduced[len(proof.Fold.Reduced)-1])
			require.Error(t, v.VerifyErr(proof, &sigma), "tampered reduced polynomial")
		})
	}
}

func TestFieldPCSOddNumVarsWithACustomConfig(t *testing.T) {
	t.Parallel()

	// Balanced split throughout. m = 9, 13 have an odd row half (5, 7), m = 11 an
	// even one; m = 10 has an odd row half with an even m.
	for _, m := range []int{9, 10, 11, 13} {
		t.Run(fmt.Sprintf("m=%d", m), func(t *testing.T) {
			t.Parallel()
			_, numCols := matrixShape(m)
			gens := testGenerators(t, numCols)
			_, err := NewFieldSetup(m, gens, testCurve(), FoldConfig{})
			require.ErrorIs(t, err, ErrInvalidFoldConfig, "the canonical field setup is for m divisible by 4 only")

			setup, err := NewFieldSetup(m, gens, testCurve(), customFold(t, DefaultMatrixSplit(m).RowVars()))
			require.NoError(t, err)
			require.Equal(t, DefaultMatrixSplit(m), setup.Split())
			st := FieldStatement{Alpha: randomPoint(t, m)}
			w := FieldWitness{Poly: randomFieldPoly(t, m)}
			p, err := NewFieldProver(setup, st, w)
			require.NoError(t, err)
			prove := func() (*EvalProof, fr.Element) {
				proof, sigma, err := p.Prove()
				require.NoError(t, err)

				return proof, sigma
			}
			v, err := NewFieldVerifier(setup, st, p.Commitment())
			require.NoError(t, err)

			proof, sigma := prove()
			want, err := w.Poly.EvaluatePoint(st.Alpha)
			require.NoError(t, err)
			require.True(t, want.Equal(&sigma), "sigma must be f(alpha)")
			require.NoError(t, v.VerifyErr(proof, sigma))

			one := fr.One()
			var wrong fr.Element
			wrong.Add(&sigma, &one)
			require.Error(t, v.VerifyErr(proof, wrong), "wrong value")

			other, err := NewFieldVerifier(setup, FieldStatement{Alpha: randomPoint(t, m)}, p.Commitment())
			require.NoError(t, err)
			require.Error(t, other.VerifyErr(proof, sigma), "wrong point")

			proof, sigma = prove()
			proof.SigmaPartial = bump(proof.SigmaPartial)
			require.Error(t, v.VerifyErr(proof, sigma), "tampered partial evaluation")

			proof, sigma = prove()
			proof.Fold.Rounds[0][1] = bump(proof.Fold.Rounds[0][1])
			require.Error(t, v.VerifyErr(proof, sigma), "tampered fold round")

			proof, sigma = prove()
			proof.Fold.Reduced[0] = bump(proof.Fold.Reduced[0])
			require.Error(t, v.VerifyErr(proof, sigma), "tampered reduced polynomial")
		})
	}
}

// customFold is a custom configuration for an m-variable polynomial: the canonical
// rate and query count, with the size-optimal Ell, but no canonical size
// restriction. It is what a caller outside the canonical sizes passes.
func customFold(t *testing.T, m int) FoldConfig {
	t.Helper()
	q, err := QueryCount(DefaultSecurityBits, DefaultLogRate, Capacity)
	if err != nil {
		t.Fatal(err)
	}

	return FoldConfig{Ell: DefaultEll(m, q), LogRate: DefaultLogRate, Queries: q, Regime: Capacity}
}

// TestCustomFoldConfigEllAboveHalf pins that the coset dimension may exceed m/2. The
// cap Ell <= m/2 is a proof-size heuristic of the canonical configuration, not a
// correctness condition, and a custom configuration may split the group leg's
// variables between the coset and the reduced polynomial however it likes.
func TestCustomFoldConfigEllAboveHalf(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ m, ell int }{{8, 5}, {9, 6}, {10, 7}} {
		t.Run(fmt.Sprintf("m=%d/ell=%d", tc.m, tc.ell), func(t *testing.T) {
			t.Parallel()
			cfg := customFold(t, tc.m)
			cfg.Ell = tc.ell
			setup, err := NewGroupSetup(tc.m, testCurve(), cfg)
			require.NoError(t, err)
			st := GroupStatement{Alpha: randomPoint(t, tc.m)}
			w := GroupWitness{Poly: randomGroupPoly(t, tc.m)}
			p, err := NewGroupProver(setup, st, w)
			require.NoError(t, err)
			v, err := NewGroupVerifier(setup, st, p.Commitment())
			require.NoError(t, err)

			proof, sigma, err := p.Prove()
			require.NoError(t, err)
			require.Len(t, proof.Fold.Reduced, 1<<(tc.m-tc.ell))
			require.NoError(t, v.VerifyErr(proof, &sigma))

			wrong := bump(sigma)
			require.Error(t, v.VerifyErr(proof, &wrong), "wrong value")
			proof.Fold.Reduced[0] = bump(proof.Fold.Reduced[0])
			require.Error(t, v.VerifyErr(proof, &sigma), "tampered reduced polynomial")
		})
	}
}
