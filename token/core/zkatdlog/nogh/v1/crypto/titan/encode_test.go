/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/sumcheck"
)

// powerCurve returns the point (x, x^2, x^4, ..., x^(2^(m-1))) in *table* order,
// i.e. entry j is x^(2^j), which is the value of variable b_j.
func powerCurve(x fr.Element, m int) []fr.Element {
	at := make([]fr.Element, m)
	cur := x
	for j := range m {
		at[j] = cur
		cur.Square(&cur)
	}

	return at
}

func randomFieldPoly(t *testing.T, m int) sumcheck.FieldPoly {
	t.Helper()
	p := make(sumcheck.FieldPoly, 1<<m)
	for i := range p {
		_, err := p[i].SetRandom()
		require.NoError(t, err)
	}

	return p
}

func randomGroupPoly(t *testing.T, m int) sumcheck.GroupPoly {
	t.Helper()
	_, _, g1Aff, _ := bls12381.Generators()
	p := make(sumcheck.GroupPoly, 1<<m)
	for i := range p {
		s, err := rand.Int(rand.Reader, fr.Modulus())
		require.NoError(t, err)
		p[i].ScalarMultiplication(&g1Aff, s)
	}

	return p
}

// TestEncodeFieldOracleMatchesNaive is the decisive correctness check: the
// butterfly output must equal a direct evaluation of the multilinear along the
// power curve at every domain point. The naive side uses EvaluatePoint from
// crypto/sumcheck, which is independently tested, so the two implementations
// share no code.
func TestEncodeFieldOracleMatchesNaive(t *testing.T) {
	for m := 1; m <= 8; m++ {
		for _, extra := range []int{0, 1, 2} {
			d := m + extra
			dom, err := NewDomain(d)
			require.NoError(t, err)

			p := randomFieldPoly(t, m)
			got, err := EncodeFieldOracle(p, dom)
			require.NoError(t, err)
			require.Len(t, got, 1<<d)

			for i, x := range dom.Elements {
				want, err := p.EvaluatePoint(powerCurve(x, m))
				require.NoError(t, err)
				require.True(t, want.Equal(&got[i]),
					"m=%d d=%d domain index %d: butterfly disagrees with naive evaluation", m, d, i)
			}
		}
	}
}

// TestEncodeGroupOracleMatchesNaive is the group-side counterpart. This is the
// one that matters for Titan, since the oracle committed to is the group
// codeword; the field version exists mainly for the public generator polynomial.
func TestEncodeGroupOracleMatchesNaive(t *testing.T) {
	for m := 1; m <= 6; m++ {
		for _, extra := range []int{0, 1, 2} {
			d := m + extra
			dom, err := NewDomain(d)
			require.NoError(t, err)

			p := randomGroupPoly(t, m)
			got, err := EncodeGroupOracle(p, dom)
			require.NoError(t, err)
			require.Len(t, got, 1<<d)

			for i, x := range dom.Elements {
				want, err := p.EvaluatePoint(powerCurve(x, m))
				require.NoError(t, err)
				require.True(t, want.Equal(&got[i]),
					"m=%d d=%d domain index %d: group butterfly disagrees with naive evaluation", m, d, i)
			}
		}
	}
}

// TestEncodeGroupMatchesFieldScaled cross-checks the two encoders against each
// other: if g(x) = [s(x)]G for a multilinear s, then the group codeword must be
// the field codeword scaled into G1 pointwise. This catches a group-path error
// that a group-only test would reproduce identically on both sides.
func TestEncodeGroupMatchesFieldScaled(t *testing.T) {
	const m = 5
	_, _, g1Aff, _ := bls12381.Generators()

	s := randomFieldPoly(t, m)
	g := make(sumcheck.GroupPoly, len(s))
	for i := range s {
		var bi big.Int
		s[i].BigInt(&bi)
		g[i].ScalarMultiplication(&g1Aff, &bi)
	}

	dom, err := NewDomain(m + 1)
	require.NoError(t, err)

	fieldCode, err := EncodeFieldOracle(s, dom)
	require.NoError(t, err)
	groupCode, err := EncodeGroupOracle(g, dom)
	require.NoError(t, err)

	for i := range fieldCode {
		var bi big.Int
		fieldCode[i].BigInt(&bi)
		var want bls12381.G1Affine
		want.ScalarMultiplication(&g1Aff, &bi)
		require.True(t, want.Equal(&groupCode[i]), "domain index %d: group codeword is not the scaled field codeword", i)
	}
}

// TestEncodeDegreeBound checks the codeword really is a Reed-Solomon codeword of
// the claimed degree: interpolating the 2^d evaluations back to coefficients must
// leave everything above degree 2^m - 1 zero. A butterfly that produced the right
// values on a too-small domain but garbage elsewhere would pass the naive
// cross-check at d == m and fail here.
func TestEncodeDegreeBound(t *testing.T) {
	const m = 4
	const d = m + 2

	dom, err := NewDomain(d)
	require.NoError(t, err)
	p := randomFieldPoly(t, m)
	code, err := EncodeFieldOracle(p, dom)
	require.NoError(t, err)

	coeffs := interpolate(t, code, dom)
	for i := 1 << m; i < len(coeffs); i++ {
		assert.True(t, coeffs[i].IsZero(), "coefficient %d above the degree bound 2^%d-1 is non-zero", i, m)
	}
	// And the bound is tight: some coefficient at or below the bound is non-zero.
	nonZero := false
	for i := range 1 << m {
		if !coeffs[i].IsZero() {
			nonZero = true

			break
		}
	}
	assert.True(t, nonZero, "codeword interpolated to the zero polynomial")
}

// interpolate recovers the coefficients of the unique polynomial of degree < |L|
// agreeing with code on L, by an O(|L|^2) Lagrange-free inverse DFT: it is the
// forward DFT with the inverse generator, scaled by 1/|L|. Quadratic is fine at
// test sizes and keeps the check independent of any FFT in the production path.
func interpolate(t *testing.T, code []fr.Element, dom *Domain) []fr.Element {
	t.Helper()
	n := len(code)
	require.Equal(t, dom.Size(), n)

	var invGen fr.Element
	invGen.Inverse(&dom.Generator)

	coeffs := make([]fr.Element, n)
	for k := range n {
		// coeffs[k] = (1/n) * sum_j code[j] * invGen^(j*k)
		var acc fr.Element
		var power fr.Element
		power.SetOne()
		var step fr.Element
		step.Exp(invGen, big.NewInt(int64(k)))
		for j := range n {
			var term fr.Element
			term.Mul(&code[j], &power)
			acc.Add(&acc, &term)
			power.Mul(&power, &step)
		}
		coeffs[k] = acc
	}
	var nInv fr.Element
	nInv.SetUint64(uint64(n))
	nInv.Inverse(&nInv)
	for k := range coeffs {
		coeffs[k].Mul(&coeffs[k], &nInv)
	}

	return coeffs
}

func TestNewDomain(t *testing.T) {
	t.Run("generator has full order", func(t *testing.T) {
		for _, d := range []int{1, 2, 5, 10} {
			dom, err := NewDomain(d)
			require.NoError(t, err)
			require.Len(t, dom.Elements, 1<<d)

			var full fr.Element
			full.Exp(dom.Generator, big.NewInt(int64(1)<<d))
			assert.True(t, full.IsOne(), "d=%d: generator^(2^d) must be 1", d)

			if d > 0 {
				var half fr.Element
				half.Exp(dom.Generator, big.NewInt(int64(1)<<(d-1)))
				assert.False(t, half.IsOne(), "d=%d: generator must be primitive, not of lower order", d)
			}
		}
	})

	t.Run("elements are the successive powers and are distinct", func(t *testing.T) {
		dom, err := NewDomain(6)
		require.NoError(t, err)
		require.True(t, dom.Elements[0].IsOne())
		seen := make(map[string]struct{}, dom.Size())
		for i, e := range dom.Elements {
			var want fr.Element
			want.Exp(dom.Generator, big.NewInt(int64(i)))
			require.True(t, want.Equal(&e), "element %d is not generator^%d", i, i)
			seen[e.String()] = struct{}{}
		}
		assert.Len(t, seen, dom.Size(), "domain elements must be distinct")
	})

	t.Run("rejects sizes past the two-adicity", func(t *testing.T) {
		_, err := NewDomain(MaxLogDomainSize + 1)
		require.ErrorIs(t, err, ErrDomainTooLarge)
		_, err = NewDomain(-1)
		require.ErrorIs(t, err, ErrDomainTooLarge)
	})
}

func TestReverseBits(t *testing.T) {
	assert.Equal(t, 0, reverseBits(0, 3))
	assert.Equal(t, 4, reverseBits(1, 3))
	assert.Equal(t, 2, reverseBits(2, 3))
	assert.Equal(t, 6, reverseBits(3, 3))
	assert.Equal(t, 1, reverseBits(4, 3))
	assert.Equal(t, 7, reverseBits(7, 3))
	// Reversal is an involution.
	for i := range 16 {
		assert.Equal(t, i, reverseBits(reverseBits(i, 4), 4))
	}
}

func TestBitReversePermutation(t *testing.T) {
	t.Run("relabels variables in reverse", func(t *testing.T) {
		// p = b_0 on 3 variables: entry i is bit 0 of i.
		p := make([]fr.Element, 8)
		for i := range p {
			p[i].SetUint64(uint64(i & 1))
		}
		require.NoError(t, bitReversePermutation(p, 3))
		// After reversal the table must be b_2, i.e. bit 2 of the index.
		for i := range p {
			var want fr.Element
			want.SetUint64(uint64((i >> 2) & 1))
			require.True(t, want.Equal(&p[i]), "index %d", i)
		}
	})

	t.Run("rejects a length that is not 2^m", func(t *testing.T) {
		require.ErrorIs(t, bitReversePermutation(make([]fr.Element, 7), 3), ErrNotPowerOfTwo)
	})
}

func TestEncodeDoesNotModifyInput(t *testing.T) {
	const m = 4
	dom, err := NewDomain(m + 1)
	require.NoError(t, err)

	fp := randomFieldPoly(t, m)
	fpCopy := make(sumcheck.FieldPoly, len(fp))
	copy(fpCopy, fp)
	_, err = EncodeFieldOracle(fp, dom)
	require.NoError(t, err)
	for i := range fp {
		require.True(t, fpCopy[i].Equal(&fp[i]), "EncodeFieldOracle modified entry %d", i)
	}

	gp := randomGroupPoly(t, m)
	gpCopy := make(sumcheck.GroupPoly, len(gp))
	copy(gpCopy, gp)
	_, err = EncodeGroupOracle(gp, dom)
	require.NoError(t, err)
	for i := range gp {
		require.True(t, gpCopy[i].Equal(&gp[i]), "EncodeGroupOracle modified entry %d", i)
	}
}

func TestEncodeValidation(t *testing.T) {
	dom, err := NewDomain(4)
	require.NoError(t, err)

	t.Run("nil polynomial", func(t *testing.T) {
		_, err := EncodeFieldOracle(nil, dom)
		require.ErrorIs(t, err, ErrNilPolynomial)
		_, err = EncodeGroupOracle(nil, dom)
		require.ErrorIs(t, err, ErrNilPolynomial)
	})

	t.Run("nil domain", func(t *testing.T) {
		_, err := EncodeFieldOracle(randomFieldPoly(t, 2), nil)
		require.ErrorIs(t, err, ErrNilDomain)
		_, err = EncodeGroupOracle(randomGroupPoly(t, 2), nil)
		require.ErrorIs(t, err, ErrNilDomain)
	})

	t.Run("length not a power of two", func(t *testing.T) {
		_, err := EncodeFieldOracle(make(sumcheck.FieldPoly, 3), dom)
		require.ErrorIs(t, err, ErrNotPowerOfTwo)
		_, err = EncodeGroupOracle(make(sumcheck.GroupPoly, 3), dom)
		require.ErrorIs(t, err, ErrNotPowerOfTwo)
	})

	t.Run("domain smaller than polynomial", func(t *testing.T) {
		small, err := NewDomain(2)
		require.NoError(t, err)
		_, err = EncodeFieldOracle(randomFieldPoly(t, 3), small)
		require.ErrorIs(t, err, ErrDomainTooSmall)
		_, err = EncodeGroupOracle(randomGroupPoly(t, 3), small)
		require.ErrorIs(t, err, ErrDomainTooSmall)
	})
}
