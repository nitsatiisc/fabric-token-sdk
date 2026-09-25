/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/require"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/sumcheck"
)

// scalarOf converts a field element to the big.Int that gnark's
// ScalarMultiplication takes.
func scalarOf(e fr.Element) *big.Int {
	var bi big.Int
	e.BigInt(&bi)
	return &bi
}

// TestEncodeCosetsGivesSemanticCosets is the identity the whole coset layout
// rests on: leaf y entry b must be exactly
//
//	G(b_0, ..., b_(ell-1), y, y^2, y^4, ...)
//
// with b in the FIRST ell variables (the low bits of the table index) and powers
// of the folded-domain point in the rest.
//
// This is what distinguishes the slice-wise construction from regrouping the flat
// codeword, whose entries are power-curve points instead. It cannot be caught by a
// round-trip test, because a wrong-but-consistent layout verifies against itself.
func TestEncodeCosetsGivesSemanticCosets(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ m, ell, logRate int }{
		{4, 1, 3}, {4, 2, 3}, {6, 2, 3}, {6, 3, 3}, {8, 4, 3}, {8, 2, 1},
	} {
		dom, err := NewDomain(tc.m + tc.logRate)
		require.NoError(t, err)

		// Work over the field so the expected value can be computed independently
		// with EvaluatePoint; the group case is covered by the consistency of
		// EncodeGroupOracle/EncodeFieldOracle, tested in encode_test.go.
		f := randomFieldPoly(t, tc.m)
		_, _, gen, _ := bls12381.Generators()
		G := make(sumcheck.GroupPoly, len(f))
		for i := range f {
			G[i].ScalarMultiplication(&gen, scalarOf(f[i]))
		}

		leaves, folded, err := EncodeCosets(G, dom, tc.ell)
		require.NoError(t, err)
		require.Len(t, leaves, folded.Size())
		require.Equal(t, tc.m-tc.ell+tc.logRate, folded.LogSize)

		for y := range folded.Size() {
			require.Len(t, leaves[y], 1<<tc.ell)
			tail := powerCurve(folded.Elements[y], tc.m-tc.ell)

			for b := range 1 << tc.ell {
				pt := make([]fr.Element, 0, tc.m)
				for i := range tc.ell {
					var e fr.Element
					if b>>i&1 == 1 {
						e.SetOne()
					}
					pt = append(pt, e)
				}
				pt = append(pt, tail...)

				want, err := f.EvaluatePoint(pt)
				require.NoError(t, err)

				var wantPt bls12381.G1Affine
				wantPt.ScalarMultiplication(&gen, scalarOf(want))

				require.True(t, wantPt.Equal(&leaves[y][b]),
					"m=%d ell=%d: leaf[%d][%d] != G(b, powers(y))", tc.m, tc.ell, y, b)
			}
		}
	}
}

// TestFoldCosetMatchesReducedCodeword is the other identity, and the one that
// makes a consistency query a single dot product: folding a coset at challenges r
// must give the codeword of the reduced polynomial at that index, where the
// reduced polynomial is G with its first ell variables bound to r.
func TestFoldCosetMatchesReducedCodeword(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ m, ell, logRate int }{
		{4, 1, 3}, {6, 2, 3}, {6, 3, 3}, {8, 3, 3}, {10, 4, 3},
	} {
		dom, err := NewDomain(tc.m + tc.logRate)
		require.NoError(t, err)

		G := randomGroupPoly(t, tc.m)

		leaves, folded, err := EncodeCosets(G, dom, tc.ell)
		require.NoError(t, err)

		r := make([]fr.Element, tc.ell)
		for i := range r {
			_, err := r[i].SetRandom()
			require.NoError(t, err)
		}
		eq := eqTable(r)

		// The reduced polynomial: bind the first ell variables to r. The first
		// variables are the low index bits, so this is foldFirstGroup ell times.
		reduced := G
		for i := range tc.ell {
			reduced, err = foldFirstGroup(reduced, &r[i])
			require.NoError(t, err)
		}
		require.Len(t, reduced, 1<<(tc.m-tc.ell))

		reducedCW, err := EncodeGroupOracle(reduced, folded)
		require.NoError(t, err)

		for y := range folded.Size() {
			got, err := foldCoset(leaves[y], eq)
			require.NoError(t, err)
			require.True(t, got.Equal(&reducedCW[y]),
				"m=%d ell=%d: fold of coset %d != reduced codeword there", tc.m, tc.ell, y)
		}
	}
}

// TestEncodeCosetsIsNotARegroupingOfTheFlatCodeword pins the finding that drove
// the design: the slice-wise oracle is a genuinely different object from the flat
// codeword, not a permutation of it. If someone "optimizes" EncodeCosets into a
// regrouping of EncodeGroupOracle's output, this fails.
func TestEncodeCosetsIsNotARegroupingOfTheFlatCodeword(t *testing.T) {
	t.Parallel()

	const m, ell, logRate = 6, 2, 3
	dom, err := NewDomain(m + logRate)
	require.NoError(t, err)

	G := randomGroupPoly(t, m)

	flat, err := EncodeGroupOracle(G, dom)
	require.NoError(t, err)

	leaves, _, err := EncodeCosets(G, dom, ell)
	require.NoError(t, err)

	// Same number of points either way.
	total := 0
	for _, l := range leaves {
		total += len(l)
	}
	require.Equal(t, len(flat), total)

	// But not the same multiset of points: count how many coset entries appear
	// anywhere in the flat codeword. A regrouping would match everywhere.
	inFlat := make(map[string]struct{}, len(flat))
	for i := range flat {
		inFlat[string(flat[i].Marshal())] = struct{}{}
	}
	matches := 0
	for _, leaf := range leaves {
		for i := range leaf {
			if _, ok := inFlat[string(leaf[i].Marshal())]; ok {
				matches++
			}
		}
	}
	require.Less(t, matches, total,
		"the coset oracle is a permutation of the flat codeword; the two constructions have been conflated")
}

// TestEncodeCosetsStridedSetIsNotTheCoset is the negative form of the same point,
// stated over the specific wrong answer that looked right: the strided set of the
// flat codeword is the fold's dependency closure, but its VALUES are not the
// coset's.
func TestEncodeCosetsStridedSetIsNotTheCoset(t *testing.T) {
	t.Parallel()

	const m, ell, logRate = 6, 2, 3
	dom, err := NewDomain(m + logRate)
	require.NoError(t, err)

	G := randomGroupPoly(t, m)

	flat, err := EncodeGroupOracle(G, dom)
	require.NoError(t, err)
	leaves, folded, err := EncodeCosets(G, dom, ell)
	require.NoError(t, err)

	n := folded.Size()
	require.Equal(t, len(flat)>>ell, n)

	agree := 0
	for y := range n {
		for b := range 1 << ell {
			if flat[y+b*n].Equal(&leaves[y][b]) {
				agree++
			}
		}
	}
	require.Less(t, agree, n<<ell,
		"strided flat-codeword entries coincide with the cosets; see EncodeCosets on why they must not")
}

func TestEncodeCosetsValidation(t *testing.T) {
	t.Parallel()

	dom, err := NewDomain(6 + 3)
	require.NoError(t, err)
	G := randomGroupPoly(t, 6)

	t.Run("nil polynomial", func(t *testing.T) {
		t.Parallel()
		_, _, err := EncodeCosets(nil, dom, 2)
		require.ErrorIs(t, err, ErrNilPolynomial)
	})
	t.Run("nil domain", func(t *testing.T) {
		t.Parallel()
		_, _, err := EncodeCosets(G, nil, 2)
		require.ErrorIs(t, err, ErrNilDomain)
	})
	t.Run("ell out of range", func(t *testing.T) {
		t.Parallel()
		_, _, err := EncodeCosets(G, dom, 0)
		require.ErrorIs(t, err, ErrInvalidCosetDim)
		_, _, err = EncodeCosets(G, dom, 7)
		require.ErrorIs(t, err, ErrInvalidCosetDim)
	})
	t.Run("domain smaller than the polynomial", func(t *testing.T) {
		t.Parallel()
		small, err := NewDomain(4)
		require.NoError(t, err)
		_, _, err = EncodeCosets(G, small, 2)
		require.ErrorIs(t, err, ErrDomainTooSmall)
	})
	t.Run("non power of two table", func(t *testing.T) {
		t.Parallel()
		_, _, err := EncodeCosets(make(sumcheck.GroupPoly, 7), dom, 2)
		require.ErrorIs(t, err, ErrNotPowerOfTwo)
	})
}

func TestFoldCosetRejectsLengthMismatch(t *testing.T) {
	t.Parallel()

	_, err := foldCoset(make([]bls12381.G1Affine, 4), make([]fr.Element, 8))
	require.ErrorIs(t, err, ErrNumVarsMismatch)
}

func TestCommitCosetsRoundTrip(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ m, ell, logRate int }{{4, 2, 3}, {6, 2, 3}, {8, 3, 3}} {
		dom, err := NewDomain(tc.m + tc.logRate)
		require.NoError(t, err)
		G := randomGroupPoly(t, tc.m)

		c, hint, err := CommitCosets(G, dom, tc.ell)
		require.NoError(t, err)
		require.Equal(t, tc.m, c.NumVars)
		require.Equal(t, tc.ell, c.Ell)
		require.Equal(t, tc.m-tc.ell+tc.logRate, c.LogDomain)
		require.Len(t, hint.Leaves, 1<<c.LogDomain)

		// Every coset opens under the root.
		for y := 0; y < len(hint.Leaves); y += max(1, len(hint.Leaves)/8) {
			leaf, proof, err := hint.OpenCoset(y)
			require.NoError(t, err)
			require.Len(t, leaf, 1<<tc.ell)
			require.True(t, VerifyMerkleProof(c.Root, leaf, proof), "coset %d does not open", y)
		}
	}
}

func TestCommitCosetsBindsTheOracle(t *testing.T) {
	t.Parallel()

	const m, ell, logRate = 6, 2, 3
	dom, err := NewDomain(m + logRate)
	require.NoError(t, err)

	c, hint, err := CommitCosets(randomGroupPoly(t, m), dom, ell)
	require.NoError(t, err)

	leaf, proof, err := hint.OpenCoset(3)
	require.NoError(t, err)

	// A tampered coset must not open under the root.
	tampered := append([]bls12381.G1Affine{}, leaf...)
	tampered[0].Add(&tampered[0], &tampered[0])
	require.False(t, VerifyMerkleProof(c.Root, tampered, proof))

	// Nor may a different polynomial's commitment accept this coset.
	other, _, err := CommitCosets(randomGroupPoly(t, m), dom, ell)
	require.NoError(t, err)
	require.False(t, VerifyMerkleProof(other.Root, leaf, proof))
}

func TestOpenCosetValidation(t *testing.T) {
	t.Parallel()

	dom, err := NewDomain(6 + 3)
	require.NoError(t, err)
	_, hint, err := CommitCosets(randomGroupPoly(t, 6), dom, 2)
	require.NoError(t, err)

	_, _, err = hint.OpenCoset(-1)
	require.ErrorIs(t, err, ErrLeafIndexOutOfRange)
	_, _, err = hint.OpenCoset(len(hint.Leaves))
	require.ErrorIs(t, err, ErrLeafIndexOutOfRange)

	var nilHint *CosetOpeningHint
	_, _, err = nilHint.OpenCoset(0)
	require.ErrorIs(t, err, ErrNilTree)
}
