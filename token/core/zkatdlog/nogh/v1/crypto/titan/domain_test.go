/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/fft"
	"github.com/stretchr/testify/require"
)

// NewDomain, reverseBits and bitReversePermutation are covered in encode_test.go,
// next to the butterfly that uses them. This file covers what the WHIR folding
// added: the squaring chain, and the gnark-crypto generator identity it rests on.

// TestGeneratorSquaringIdentity pins an identity of gnark-crypto's generator
// choice that this package depends on but does not control: the generator of the
// order-2^(d-1) subgroup is the square of the generator of the order-2^d one.
//
// Every cross-round index computation in the folding rests on it. gnark does not
// promise it, so if a dependency bump changes the generator selection this test
// fails loudly instead of the folding silently reading the wrong domain element.
func TestGeneratorSquaringIdentity(t *testing.T) {
	t.Parallel()

	for d := 2; d <= 18; d++ {
		large := fft.NewDomain(uint64(1) << d)
		small := fft.NewDomain(uint64(1) << (d - 1))

		var sq fr.Element
		sq.Square(&large.Generator)
		require.True(t, sq.Equal(&small.Generator),
			"g_%d^2 != g_%d: gnark-crypto's generator choice changed", d, d-1)
	}
}

// TestDomainSquaredMatchesNewDomain is the other half of the same dependency:
// squaring a domain elementwise must give exactly the next domain down, with the
// index relation Elements[i]^2 == half.Elements[i mod 2^(d-1)] that the folding
// uses to locate a point's image in the next round's domain.
func TestDomainSquaredMatchesNewDomain(t *testing.T) {
	t.Parallel()

	for d := 1; d <= 12; d++ {
		parent, err := NewDomain(d)
		require.NoError(t, err)

		half, err := parent.Squared()
		require.NoError(t, err)

		want, err := NewDomain(d - 1)
		require.NoError(t, err)

		require.Equal(t, want.LogSize, half.LogSize)
		require.Equal(t, want.Size(), half.Size())
		require.True(t, want.Generator.Equal(&half.Generator), "d=%d generator", d)
		require.Equal(t, want.Elements, half.Elements, "d=%d elements", d)

		for i := range parent.Size() {
			var sq fr.Element
			sq.Square(&parent.Elements[i])
			j := i % half.Size()
			require.True(t, sq.Equal(&half.Elements[j]),
				"d=%d: L_d.Elements[%d]^2 != L_(d-1).Elements[%d]", d, i, j)
		}
	}
}

func TestDomainSquaredEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("nil receiver", func(t *testing.T) {
		t.Parallel()
		var d *Domain
		_, err := d.Squared()
		require.ErrorIs(t, err, ErrNilDomain)
	})

	t.Run("single element domain squares to itself", func(t *testing.T) {
		t.Parallel()
		d, err := NewDomain(0)
		require.NoError(t, err)
		sq, err := d.Squared()
		require.NoError(t, err)
		require.Equal(t, 0, sq.LogSize)
		require.Equal(t, 1, sq.Size())
		require.True(t, sq.Elements[0].IsOne())
	})

	t.Run("does not alias or modify the parent", func(t *testing.T) {
		t.Parallel()
		parent, err := NewDomain(4)
		require.NoError(t, err)
		before := append([]fr.Element{}, parent.Elements...)

		half, err := parent.Squared()
		require.NoError(t, err)
		half.Elements[0].SetUint64(12345)

		require.Equal(t, before, parent.Elements, "Squared must copy, not alias")
	})
}

// TestDomainSquaredRepeatedly walks a domain all the way down, which is the
// access pattern the folding rounds use.
func TestDomainSquaredRepeatedly(t *testing.T) {
	t.Parallel()

	const top = 10
	d, err := NewDomain(top)
	require.NoError(t, err)

	cur := d
	for round := 1; round <= top; round++ {
		next, err := cur.Squared()
		require.NoError(t, err)
		require.Equal(t, top-round, next.LogSize)

		want, err := NewDomain(top - round)
		require.NoError(t, err)
		require.Equal(t, want.Elements, next.Elements, "round=%d", round)

		cur = next
	}
	require.Equal(t, 1, cur.Size())
}

func TestIsPowerOfTwo(t *testing.T) {
	t.Parallel()

	for _, n := range []int{1, 2, 4, 8, 1024} {
		require.True(t, isPowerOfTwo(n), "n=%d", n)
	}
	for _, n := range []int{0, -1, 3, 6, 1023} {
		require.False(t, isPowerOfTwo(n), "n=%d", n)
	}
}
