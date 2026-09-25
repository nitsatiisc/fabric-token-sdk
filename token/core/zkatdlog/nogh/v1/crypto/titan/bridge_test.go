/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	"math/big"
	"testing"

	mathlib "github.com/IBM/mathlib"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/require"
)

// TestBridgeScalarFieldsAreIdentical pins the assumption the whole boundary rests
// on: mathlib's curve and gnark-crypto's fr use the same scalar field order.
//
// If they ever diverged, every conversion below would still *succeed* -- it would
// silently reduce modulo the wrong modulus and produce proofs that fail for
// reasons impossible to trace back here. So this is a regression test, not a
// sanity check.
//
// Note the two libraries print the order differently: mathlib hex-encodes,
// gnark-crypto prints decimal. Comparing the strings suggests a mismatch that is
// not there; compare as big.Int.
func TestBridgeScalarFieldsAreIdentical(t *testing.T) {
	curve := bridgeCurve()
	require.NotNil(t, curve)

	mathOrder, ok := new(big.Int).SetString(curve.GroupOrder.String(), 16)
	require.True(t, ok, "mathlib group order should parse as hex")

	require.Zero(t, mathOrder.Cmp(fr.Modulus()),
		"mathlib group order and fr.Modulus() must be equal\n  mathlib: %s\n  gnark:   %s",
		mathOrder.String(), fr.Modulus().String())
}

func TestToMathG1RoundTrip(t *testing.T) {
	curve := bridgeCurve()
	_, _, g1, _ := bls12381.Generators()

	for _, tc := range []struct {
		name  string
		build func() bls12381.G1Affine
	}{
		{"generator", func() bls12381.G1Affine { return g1 }},
		{"scalar multiple", func() bls12381.G1Affine {
			var p bls12381.G1Affine

			return *p.ScalarMultiplication(&g1, big.NewInt(1234567))
		}},
		{"negated generator", func() bls12381.G1Affine {
			var p bls12381.G1Affine
			p.Neg(&g1)

			return p
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.build()

			mp, err := toMathG1(&p, curve)
			require.NoError(t, err)
			require.NotNil(t, mp)

			// Back through the compressed encoding, which is the only shared
			// representation the two libraries agree on.
			var back bls12381.G1Affine
			_, err = back.SetBytes(mp.Compressed())
			require.NoError(t, err)
			require.True(t, back.Equal(&p), "round trip must be exact")
		})
	}
}

func TestToMathG1RejectsInfinity(t *testing.T) {
	curve := bridgeCurve()

	var inf bls12381.G1Affine // the zero value is the point at infinity
	require.True(t, inf.IsInfinity(), "the zero G1Affine should be the identity")

	_, err := toMathG1(&inf, curve)
	require.ErrorIs(t, err, ErrPointAtInfinity)
}

func TestToMathG1Validation(t *testing.T) {
	curve := bridgeCurve()
	_, _, p, _ := bls12381.Generators()

	t.Run("nil point", func(t *testing.T) {
		_, err := toMathG1(nil, curve)
		require.ErrorIs(t, err, ErrNilElement)
	})

	t.Run("nil curve", func(t *testing.T) {
		_, err := toMathG1(&p, nil)
		require.ErrorIs(t, err, ErrNilCurve)
	})
}

func TestToMathG1Slice(t *testing.T) {
	curve := bridgeCurve()
	_, _, g1, _ := bls12381.Generators()

	pts := make([]bls12381.G1Affine, 8)
	for i := range pts {
		pts[i].ScalarMultiplication(&g1, big.NewInt(int64(i+1)))
	}

	out, err := toMathG1Slice(pts, curve)
	require.NoError(t, err)
	require.Len(t, out, len(pts))
	for i := range pts {
		var back bls12381.G1Affine
		_, err := back.SetBytes(out[i].Compressed())
		require.NoError(t, err)
		require.True(t, back.Equal(&pts[i]), "point %d must round-trip", i)
	}

	t.Run("empty", func(t *testing.T) {
		out, err := toMathG1Slice(nil, curve)
		require.NoError(t, err)
		require.Empty(t, out)
	})

	t.Run("reports the offending index", func(t *testing.T) {
		bad := make([]bls12381.G1Affine, 3)
		copy(bad, pts[:3])
		bad[2].SetInfinity()

		_, err := toMathG1Slice(bad, curve)
		require.ErrorIs(t, err, ErrPointAtInfinity)
		require.Contains(t, err.Error(), "point 2")
	})
}

func TestToMathZrRoundTrip(t *testing.T) {
	curve := bridgeCurve()

	// Small values matter here: big.Int.Bytes() emits a minimal encoding, so a
	// value like 1 is a single byte and must be left-padded to 32 before mathlib
	// reads it. Without the padding it would be interpreted at the wrong
	// significance -- and 0 and 1 are exactly the values eq() produces most.
	values := []fr.Element{}
	for _, n := range []int64{0, 1, 2, 255, 256, 65535, 1 << 40} {
		var e fr.Element
		e.SetInt64(n)
		values = append(values, e)
	}
	// A full-width element, to exercise the top byte.
	var big1 fr.Element
	big1.SetBigInt(new(big.Int).Sub(fr.Modulus(), big.NewInt(1)))
	values = append(values, big1)
	// And a random one.
	var rnd fr.Element
	_, err := rnd.SetRandom()
	require.NoError(t, err)
	values = append(values, rnd)

	for i, want := range values {
		mz, err := toMathZr(&want, curve)
		require.NoError(t, err, "value %d", i)

		got, err := toFieldElement(mz)
		require.NoError(t, err, "value %d", i)
		require.True(t, got.Equal(&want), "value %d must round-trip: got %s want %s", i, got.String(), want.String())
	}
}

func TestToMathZrArithmeticAgrees(t *testing.T) {
	curve := bridgeCurve()

	// The conversion is only useful if arithmetic commutes with it: computing in
	// gnark then converting must equal converting then computing in mathlib.
	// fr.Element is in Montgomery form internally, so this is the property that
	// actually verifies BigInt() is being used correctly rather than raw limbs.
	var a, b fr.Element
	_, err := a.SetRandom()
	require.NoError(t, err)
	_, err = b.SetRandom()
	require.NoError(t, err)

	var sum, prod fr.Element
	sum.Add(&a, &b)
	prod.Mul(&a, &b)

	ma, err := toMathZr(&a, curve)
	require.NoError(t, err)
	mb, err := toMathZr(&b, curve)
	require.NoError(t, err)

	msum, err := toMathZr(&sum, curve)
	require.NoError(t, err)
	mprod, err := toMathZr(&prod, curve)
	require.NoError(t, err)

	require.True(t, ma.Plus(mb).Equals(msum), "addition must agree across the boundary")

	got := ma.Mul(mb)
	got.Mod(curve.GroupOrder)
	require.True(t, got.Equals(mprod), "multiplication must agree across the boundary")
}

func TestToMathZrSlice(t *testing.T) {
	curve := bridgeCurve()

	es := make([]fr.Element, 16)
	for i := range es {
		es[i].SetInt64(int64(i))
	}

	out, err := toMathZrSlice(es, curve)
	require.NoError(t, err)
	require.Len(t, out, len(es))
	for i := range es {
		back, err := toFieldElement(out[i])
		require.NoError(t, err)
		require.True(t, back.Equal(&es[i]), "scalar %d must round-trip", i)
	}

	t.Run("empty", func(t *testing.T) {
		out, err := toMathZrSlice(nil, curve)
		require.NoError(t, err)
		require.Empty(t, out)
	})
}

func TestToMathZrValidation(t *testing.T) {
	curve := bridgeCurve()
	var e fr.Element
	e.SetInt64(7)

	t.Run("nil scalar", func(t *testing.T) {
		_, err := toMathZr(nil, curve)
		require.ErrorIs(t, err, ErrNilElement)
	})

	t.Run("nil curve", func(t *testing.T) {
		_, err := toMathZr(&e, nil)
		require.ErrorIs(t, err, ErrNilCurve)
	})

	t.Run("nil in reverse", func(t *testing.T) {
		_, err := toFieldElement(nil)
		require.ErrorIs(t, err, ErrNilElement)
	})
}

func TestPadTo32(t *testing.T) {
	require.Len(t, padTo32(nil), 32)
	require.Len(t, padTo32([]byte{1}), 32)
	require.Equal(t, byte(1), padTo32([]byte{1})[31], "a short value must land in the low byte")

	full := make([]byte, 32)
	full[0] = 9
	require.Equal(t, full, padTo32(full), "a 32-byte value is returned unchanged")
}

// TestBridgeAcrossCurveVariants pins that conversion tags elements with the
// *caller's* curve, not a fixed one.
//
// mathlib's four BLS12-381 entries share the group and scalar field but have
// distinct curve IDs, and csp rejects a statement whose elements disagree with its
// curve (math.CheckElements against curve.ID()). So a bridge that converted onto a
// hardcoded curve would build statements that fail validation for any caller using
// a different variant -- an error that would read as a soundness failure rather
// than a plumbing one.
func TestBridgeAcrossCurveVariants(t *testing.T) {
	_, _, g1, _ := bls12381.Generators()
	var e fr.Element
	e.SetInt64(42)

	for _, tc := range []struct {
		name string
		id   mathlib.CurveID
	}{
		{"BLS12_381", mathlib.BLS12_381},
		{"BLS12_381_BBS", mathlib.BLS12_381_BBS},
		{"BLS12_381_GURVY", mathlib.BLS12_381_GURVY},
		{"BLS12_381_BBS_GURVY", mathlib.BLS12_381_BBS_GURVY},
	} {
		t.Run(tc.name, func(t *testing.T) {
			curve := mathlib.Curves[tc.id]

			mathOrder, ok := new(big.Int).SetString(curve.GroupOrder.String(), 16)
			require.True(t, ok)
			require.Zero(t, mathOrder.Cmp(fr.Modulus()), "every BLS12-381 variant shares fr")

			mp, err := toMathG1(&g1, curve)
			require.NoError(t, err)
			var back bls12381.G1Affine
			_, err = back.SetBytes(mp.Compressed())
			require.NoError(t, err)
			require.True(t, back.Equal(&g1))

			mz, err := toMathZr(&e, curve)
			require.NoError(t, err)
			got, err := toFieldElement(mz)
			require.NoError(t, err)
			require.True(t, got.Equal(&e))

			// The tag must be the caller's, which is what csp checks.
			require.Equal(t, tc.id, mp.CurveID(), "converted point must carry the caller's curve ID")
			require.Equal(t, tc.id, mz.CurveID(), "converted scalar must carry the caller's curve ID")
		})
	}
}
