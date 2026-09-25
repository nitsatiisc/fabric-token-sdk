/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package csp

import (
	"strconv"
	"testing"

	mathlib "github.com/IBM/mathlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	math2 "github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/math"
)

// lfInstance builds an honest linear-form statement of length n together with its
// witness, so the tests exercise the exported wrapper exactly as an outside caller
// would: statement in hand, witness alongside it, nothing package-private.
func lfInstance(t *testing.T, n int) (*LinearFormStatement, []*mathlib.Zr) {
	t.Helper()
	curve := mathlib.Curves[mathlib.BLS12_381_BBS_GURVY]
	rand, err := curve.Rand()
	require.NoError(t, err)

	generators := make([]*mathlib.G1, n)
	witness := make([]*mathlib.Zr, n)
	linearForm := make([]*mathlib.Zr, n)
	for i := range n {
		generators[i] = curve.HashToG1([]byte("lf-gen-" + strconv.Itoa(i)))
		witness[i] = curve.NewRandomZr(rand)
		linearForm[i] = curve.NewRandomZr(rand)
	}

	return &LinearFormStatement{
		Commitment: curve.MultiScalarMul(generators, witness),
		Generators: generators,
		LinearForm: linearForm,
		Value:      math2.InnerProduct(linearForm, witness, curve),
		Curve:      curve,
	}, witness
}

// TestLinearFormRoundTrip is the decisive check on the wrapper: an honest
// statement must verify at every power-of-two length, which confirms the
// NumberOfRounds derivation agrees with what the prover and verifier expect. A
// wrong log2 would either error or silently fold a different number of times.
func TestLinearFormRoundTrip(t *testing.T) {
	hdr := []byte("titan-linear-form")
	for _, n := range []int{2, 4, 8, 16, 32, 64} {
		st, wit := lfInstance(t, n)
		proof, err := ProveLinearForm(st, wit, hdr)
		require.NoError(t, err, "n=%d", n)
		require.NoError(t, VerifyLinearForm(st, proof, hdr), "n=%d", n)
	}
}

// TestLinearFormRejectsWrongValue is the soundness check that matters: the claimed
// evaluation is the thing being proved, so a wrong one must not verify.
func TestLinearFormRejectsWrongValue(t *testing.T) {
	hdr := []byte("titan-linear-form")
	st, wit := lfInstance(t, 8)
	proof, err := ProveLinearForm(st, wit, hdr)
	require.NoError(t, err)

	bad := *st
	// Zr.Plus returns a new value rather than mutating the receiver, so the
	// result must be captured -- discarding it leaves Value unchanged and the
	// test asserts nothing.
	bad.Value = st.Value.Plus(st.Curve.NewZrFromInt(1))
	require.False(t, bad.Value.Equals(st.Value), "the tampered value must actually differ")
	require.Error(t, VerifyLinearForm(&bad, proof, hdr))
}

func TestLinearFormRejectsTamperedProof(t *testing.T) {
	hdr := []byte("titan-linear-form")
	st, wit := lfInstance(t, 8)

	t.Run("tampered cross-commitment", func(t *testing.T) {
		proof, err := ProveLinearForm(st, wit, hdr)
		require.NoError(t, err)
		proof.Left[0] = st.Curve.GenG1
		require.Error(t, VerifyLinearForm(st, proof, hdr))
	})

	t.Run("tampered cross-scalar", func(t *testing.T) {
		proof, err := ProveLinearForm(st, wit, hdr)
		require.NoError(t, err)
		proof.VLeft[0] = st.Curve.NewZrFromInt(1)
		require.Error(t, VerifyLinearForm(st, proof, hdr))
	})
}

// TestLinearFormTranscriptHeaderIsBound pins that the header is domain
// separation and not decoration: a verifier using different bytes must reject,
// otherwise a proof could be replayed across protocols that share this primitive.
func TestLinearFormTranscriptHeaderIsBound(t *testing.T) {
	st, wit := lfInstance(t, 8)
	proof, err := ProveLinearForm(st, wit, []byte("header-A"))
	require.NoError(t, err)
	require.NoError(t, VerifyLinearForm(st, proof, []byte("header-A")))
	require.Error(t, VerifyLinearForm(st, proof, []byte("header-B")))
}

// TestLinearFormRejectsWrongWitness: a witness that does not open the commitment
// cannot yield a verifying proof.
func TestLinearFormRejectsWrongWitness(t *testing.T) {
	hdr := []byte("titan-linear-form")
	st, _ := lfInstance(t, 8)
	_, other := lfInstance(t, 8)

	proof, err := ProveLinearForm(st, other, hdr)
	if err != nil {
		return // rejected outright is also acceptable
	}
	require.Error(t, VerifyLinearForm(st, proof, hdr))
}

func TestLinearFormValidation(t *testing.T) {
	hdr := []byte("h")
	st, wit := lfInstance(t, 8)

	t.Run("nil statement", func(t *testing.T) {
		_, err := ProveLinearForm(nil, wit, hdr)
		require.Error(t, err)
		require.Error(t, VerifyLinearForm(nil, nil, hdr))
	})

	t.Run("nil proof", func(t *testing.T) {
		require.ErrorIs(t, VerifyLinearForm(st, nil, hdr), ErrNilProof)
	})

	t.Run("length not a power of two", func(t *testing.T) {
		bad, badWit := lfInstance(t, 8)
		bad.Generators = bad.Generators[:5]
		bad.LinearForm = bad.LinearForm[:5]
		_, err := ProveLinearForm(bad, badWit[:5], hdr)
		require.ErrorIs(t, err, ErrInvalidLength)
	})

	t.Run("linear form length mismatch", func(t *testing.T) {
		bad, badWit := lfInstance(t, 8)
		bad.LinearForm = bad.LinearForm[:4]
		_, err := ProveLinearForm(bad, badWit, hdr)
		require.ErrorIs(t, err, ErrInvalidLength)
	})

	t.Run("witness length mismatch", func(t *testing.T) {
		_, err := ProveLinearForm(st, wit[:4], hdr)
		require.ErrorIs(t, err, ErrInvalidLength)
	})

	t.Run("length one is rejected", func(t *testing.T) {
		// Degenerate: zero folding rounds. See the note in rounds().
		one, oneWit := lfInstance(t, 1)
		_, err := ProveLinearForm(one, oneWit, hdr)
		require.ErrorIs(t, err, ErrInvalidLength)
	})

	t.Run("no generators", func(t *testing.T) {
		bad := &LinearFormStatement{Curve: st.Curve}
		_, err := ProveLinearForm(bad, nil, hdr)
		require.ErrorIs(t, err, ErrInvalidLength)
	})

	t.Run("nil curve", func(t *testing.T) {
		bad := &LinearFormStatement{Generators: st.Generators, LinearForm: st.LinearForm}
		_, err := ProveLinearForm(bad, wit, hdr)
		require.ErrorIs(t, err, ErrNilCurve)
	})
}

// TestPadToPowerOfTwo checks the padding leaves the statement's meaning intact:
// the padded instance must still prove and verify, which is the only property
// that matters. Zero coefficients and zero witness entries contribute nothing, so
// both the commitment and the claimed value are unchanged by construction --
// this test is what confirms that reasoning holds against the real protocol.
func TestPadToPowerOfTwo(t *testing.T) {
	curve := mathlib.Curves[mathlib.BLS12_381_BBS_GURVY]
	rand, err := curve.Rand()
	require.NoError(t, err)

	const n = 5 // deliberately not a power of two
	gens := make([]*mathlib.G1, n)
	wit := make([]*mathlib.Zr, n)
	lf := make([]*mathlib.Zr, n)
	for i := range n {
		gens[i] = curve.HashToG1([]byte("pad-gen-" + strconv.Itoa(i)))
		wit[i] = curve.NewRandomZr(rand)
		lf[i] = curve.NewRandomZr(rand)
	}
	com := curve.MultiScalarMul(gens, wit)
	val := math2.InnerProduct(lf, wit, curve)

	pGens, pLF, pWit, err := PadToPowerOfTwo(gens, lf, wit, curve)
	require.NoError(t, err)
	assert.Len(t, pGens, 8)
	assert.Len(t, pLF, 8)
	assert.Len(t, pWit, 8)

	// The padded statement commits to the same value and claims the same result.
	assert.True(t, curve.MultiScalarMul(pGens, pWit).Equals(com), "padding changed the commitment")
	assert.True(t, math2.InnerProduct(pLF, pWit, curve).Equals(val), "padding changed the claimed value")

	st := &LinearFormStatement{
		Commitment: com, Generators: pGens, LinearForm: pLF, Value: val, Curve: curve,
	}
	proof, err := ProveLinearForm(st, pWit, []byte("pad"))
	require.NoError(t, err)
	require.NoError(t, VerifyLinearForm(st, proof, []byte("pad")))
}

func TestPadToPowerOfTwoValidation(t *testing.T) {
	curve := mathlib.Curves[mathlib.BLS12_381_BBS_GURVY]
	g := []*mathlib.G1{curve.GenG1, curve.GenG1}
	z := []*mathlib.Zr{curve.NewZrFromInt(1), curve.NewZrFromInt(2)}

	_, _, _, err := PadToPowerOfTwo(g, z, z, nil)
	require.ErrorIs(t, err, ErrNilCurve)

	_, _, _, err = PadToPowerOfTwo(nil, nil, nil, curve)
	require.ErrorIs(t, err, ErrInvalidLength)

	_, _, _, err = PadToPowerOfTwo(g, z[:1], z, curve)
	require.ErrorIs(t, err, ErrInvalidLength)

	_, _, _, err = PadToPowerOfTwo(g, z, z[:1], curve)
	require.ErrorIs(t, err, ErrInvalidLength)

	// Already a power of two: returned unchanged in length, witness may be nil.
	pg, pl, pw, err := PadToPowerOfTwo(g, z, nil, curve)
	require.NoError(t, err)
	assert.Len(t, pg, 2)
	assert.Len(t, pl, 2)
	assert.Nil(t, pw)
}
