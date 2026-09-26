/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/sumcheck"
)

// testGenerators returns n distinct generators. These stand in for a real setup;
// commitField takes them from the caller precisely because their provenance is a
// trust question this package does not answer.
func testGenerators(t *testing.T, n int) []bls12381.G1Affine {
	t.Helper()
	_, _, g, _ := bls12381.Generators()
	out := make([]bls12381.G1Affine, n)
	for i := range out {
		out[i].ScalarMultiplication(&g, big.NewInt(int64(3*i+11)))
	}

	return out
}

func TestCommitGroupRoundTrip(t *testing.T) {
	for m := 1; m <= 7; m++ {
		for _, extra := range []int{0, 1, 2} {
			for _, k := range []int{0, 1, 2} {
				d := m + extra
				if (1<<d)>>k == 0 || (1<<d)%(1<<k) != 0 {
					continue
				}
				dom, err := NewDomain(d)
				require.NoError(t, err)
				G := randomGroupPoly(t, m)

				c, hint, err := commitGroup(G, dom, k)
				require.NoError(t, err, "m=%d d=%d k=%d", m, d, k)

				assert.Nil(t, c.Root, "the flat codeword is not committed; see Commitment.Root")
				assert.Equal(t, m, c.NumVars)
				assert.Equal(t, d, c.LogDomain)
				assert.Equal(t, k, c.K)
				assert.Equal(t, (1<<d)/(1<<k), c.NumLeaves)
				require.Len(t, hint.Codeword, 1<<d)
				require.Len(t, hint.Leaves, c.NumLeaves)
				for i, leaf := range hint.Leaves {
					require.Len(t, leaf, 1<<k, "m=%d d=%d k=%d leaf=%d", m, d, k, i)
				}
			}
		}
	}
}

// TestCommitGroupLeavesArePartitionOfCodeword pins that cosets only regroup the
// codeword, never reorder it. A strided chunking would still build a valid tree,
// over a permutation of the same points -- an error no round-trip can see.
func TestCommitGroupLeavesArePartitionOfCodeword(t *testing.T) {
	dom, err := NewDomain(6)
	require.NoError(t, err)
	G := randomGroupPoly(t, 4)

	var reference []bls12381.G1Affine
	for _, k := range []int{0, 1, 2, 3} {
		_, hint, err := commitGroup(G, dom, k)
		require.NoError(t, err)

		if reference == nil {
			reference = hint.Codeword
		} else {
			assert.Equal(t, reference, hint.Codeword, "k must not change the codeword itself")
		}

		flat := make([]bls12381.G1Affine, 0, len(hint.Codeword))
		for _, leaf := range hint.Leaves {
			flat = append(flat, leaf...)
		}
		assert.Equal(t, hint.Codeword, flat,
			"k=%d: concatenating the leaves must reproduce the codeword in order", k)
	}
}

// TestCommitFieldTierOneMatchesDirectMSM is the decisive tier-1 check: the group
// multilinear must be exactly the per-row Pedersen commitment, computed here
// without commitField.
func TestCommitFieldTierOneMatchesDirectMSM(t *testing.T) {
	for m := 1; m <= 8; m++ {
		f := randomFieldPoly(t, m)
		rows, cols := matrixShape(m)
		require.Equal(t, len(f), rows*cols, "m=%d shape must cover the coefficients", m)

		gens := testGenerators(t, cols)
		dom, err := NewDomain(maxInt(logOf(rows), 1) + 1)
		require.NoError(t, err)

		_, hint, err := commitField(f, gens, dom, 0)
		require.NoError(t, err)
		require.Len(t, hint.G, rows)
		assert.Equal(t, rows, hint.NumRows)
		assert.Equal(t, cols, hint.NumCols)

		for j := range rows {
			var want bls12381.G1Jac
			for kk := range cols {
				var bi big.Int
				f[j*cols+kk].BigInt(&bi)
				var term bls12381.G1Jac
				term.FromAffine(&gens[kk])
				term.ScalarMultiplication(&term, &bi)
				want.AddAssign(&term)
			}
			var wantAff bls12381.G1Affine
			wantAff.FromJacobian(&want)
			assert.True(t, wantAff.Equal(&hint.G[j]),
				"m=%d row %d: tier-1 commitment disagrees with a direct MSM", m, j)
		}
	}
}

// TestCommitFieldGroupPolyIsTheEvaluationTable pins the claim in the commitGroup
// docs that no interpolation step is needed: entry j of the table is already the
// value at the bit decomposition of j, so EvaluatePoint on a boolean point must
// return the row commitment.
func TestCommitFieldGroupPolyIsTheEvaluationTable(t *testing.T) {
	m := 6
	f := randomFieldPoly(t, m)
	rows, cols := matrixShape(m)
	gens := testGenerators(t, cols)
	dom, err := NewDomain(logOf(rows) + 1)
	require.NoError(t, err)

	_, hint, err := commitField(f, gens, dom, 0)
	require.NoError(t, err)

	numVars := logOf(rows)
	for j := range rows {
		at := make([]fr.Element, numVars)
		for b := range numVars {
			if (j>>b)&1 == 1 {
				at[b].SetOne()
			}
		}
		got, err := hint.G.EvaluatePoint(at)
		require.NoError(t, err)
		assert.True(t, got.Equal(&hint.G[j]), "row %d", j)
	}
}

func TestCommitFieldOddNumVarsShape(t *testing.T) {
	// For odd m = 2s+1 the extra variable goes to the rows, giving 2^(s+1) rows
	// of 2^s columns. Pinning this because prover and verifier must agree, and a
	// silent floor would produce a shape that does not cover the coefficients.
	cases := []struct{ m, rows, cols int }{
		{1, 2, 1}, {2, 2, 2}, {3, 4, 2}, {4, 4, 4}, {5, 8, 4}, {6, 8, 8}, {7, 16, 8},
	}
	for _, c := range cases {
		rows, cols := matrixShape(c.m)
		assert.Equal(t, c.rows, rows, "m=%d rows", c.m)
		assert.Equal(t, c.cols, cols, "m=%d cols", c.m)
		assert.Equal(t, 1<<c.m, rows*cols, "m=%d shape must cover 2^m", c.m)
	}
}

func TestCommitFieldIsDeterministic(t *testing.T) {
	f := randomFieldPoly(t, 6)
	_, cols := matrixShape(6)
	gens := testGenerators(t, cols)
	dom, err := NewDomain(5)
	require.NoError(t, err)

	_, ha, err := commitField(f, gens, dom, 0)
	require.NoError(t, err)
	_, hb, err := commitField(f, gens, dom, 0)
	require.NoError(t, err)
	// Asserted on the tier-1 group multilinear rather than on a Merkle root. The
	// root used to stand in for "the commitment", but the flat codeword is no
	// longer committed (see Commitment.Root) and G is what the root summarised --
	// and is strictly stronger, since a digest could in principle collide where
	// the coefficients cannot.
	assert.Equal(t, ha.G, hb.G, "committing the same polynomial twice must agree")
	assert.Equal(t, ha.Codeword, hb.Codeword)
}

func TestCommitFieldDistinctPolysGiveDistinctCommitments(t *testing.T) {
	f := randomFieldPoly(t, 6)
	_, cols := matrixShape(6)
	gens := testGenerators(t, cols)
	dom, err := NewDomain(5)
	require.NoError(t, err)

	_, ha, err := commitField(f, gens, dom, 0)
	require.NoError(t, err)

	g := make(sumcheck.FieldPoly, len(f))
	copy(g, f)
	var one fr.Element
	one.SetOne()
	g[len(g)/3].Add(&g[len(g)/3], &one)

	_, hb, err := commitField(g, gens, dom, 0)
	require.NoError(t, err)
	assert.NotEqual(t, ha.G, hb.G, "changing a coefficient must change the commitment")
}

// TestCommitFieldDifferentGeneratorsGiveDifferentCommitments guards against the row MSM
// silently ignoring the generators (for example by using an offset slice).
func TestCommitFieldDifferentGeneratorsGiveDifferentCommitments(t *testing.T) {
	f := randomFieldPoly(t, 6)
	_, cols := matrixShape(6)
	dom, err := NewDomain(5)
	require.NoError(t, err)

	_, ha, err := commitField(f, testGenerators(t, cols), dom, 0)
	require.NoError(t, err)

	other := testGenerators(t, cols+1)[1:]
	_, hb, err := commitField(f, other, dom, 0)
	require.NoError(t, err)
	assert.NotEqual(t, ha.G, hb.G)
}

func TestCommitGroupValidation(t *testing.T) {
	dom, err := NewDomain(4)
	require.NoError(t, err)
	G := randomGroupPoly(t, 3)

	_, _, err = commitGroup(G, nil, 0)
	assert.ErrorIs(t, err, ErrNilDomain)

	_, _, err = commitGroup(nil, dom, 0)
	assert.ErrorIs(t, err, ErrNilPolynomial)

	_, _, err = commitGroup(G, dom, -1)
	assert.ErrorIs(t, err, ErrInvalidCosetDim)

	// k larger than the codeword cannot split it.
	_, _, err = commitGroup(G, dom, 5)
	assert.ErrorIs(t, err, ErrInvalidCosetDim)

	// Domain smaller than the polynomial is rejected by the encoder.
	small, err := NewDomain(2)
	require.NoError(t, err)
	_, _, err = commitGroup(G, small, 0)
	assert.ErrorIs(t, err, ErrDomainTooSmall)
}

func TestCommitFieldValidation(t *testing.T) {
	dom, err := NewDomain(5)
	require.NoError(t, err)
	f := randomFieldPoly(t, 6)
	_, cols := matrixShape(6)

	_, _, err = commitField(nil, testGenerators(t, cols), dom, 0)
	assert.ErrorIs(t, err, ErrNilPolynomial)

	_, _, err = commitField(f, testGenerators(t, cols), nil, 0)
	assert.ErrorIs(t, err, ErrNilDomain)

	_, _, err = commitField(f, testGenerators(t, cols-1), dom, 0)
	assert.ErrorIs(t, err, ErrInsufficientGenerators)

	ragged := make(sumcheck.FieldPoly, 7) // not a power of two
	_, _, err = commitField(ragged, testGenerators(t, cols), dom, 0)
	assert.ErrorIs(t, err, ErrNotPowerOfTwo)
}

func TestNumVarsOf(t *testing.T) {
	for m := range 10 {
		got, err := numVarsOf(1 << m)
		require.NoError(t, err)
		assert.Equal(t, m, got)
	}
	_, err := numVarsOf(3)
	assert.ErrorIs(t, err, ErrNotPowerOfTwo)
	_, err = numVarsOf(0)
	assert.ErrorIs(t, err, ErrNotPowerOfTwo)
}

func logOf(n int) int {
	d := 0
	for 1<<d < n {
		d++
	}

	return d
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}

	return b
}
