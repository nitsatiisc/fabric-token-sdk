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

// The fold path skips the flat encoding. Its commitment must be exactly what the
// staged path -- commitGroup, which does encode, plus CommitCosets -- produces, so
// that skipping the encoding changes cost and nothing else.
func TestCommitGroupWithFoldSkipsOnlyTheFlatEncoding(t *testing.T) {
	for _, m := range []int{4, 6, 8} {
		G := randomGroupPoly(t, m)
		cfg, err := DefaultFoldConfig(m)
		require.NoError(t, err)
		dom, err := NewDomain(m + cfg.LogRate)
		require.NoError(t, err)

		got, hint, err := CommitGroupWithFold(G, dom, 0, cfg)
		require.NoError(t, err)
		assert.Nil(t, hint.Codeword, "the fold path must not encode the flat codeword")
		assert.Nil(t, hint.Leaves)

		want, _, err := commitGroup(G, dom, 0)
		require.NoError(t, err)
		wantCosets, _, err := CommitCosets(G, dom, cfg.Ell)
		require.NoError(t, err)
		wantCosets.Fold = cfg
		want.Cosets = wantCosets
		assert.Equal(t, want, got, "m = %d", m)
	}
}

func TestCommitFieldWithFoldSkipsOnlyTheFlatEncoding(t *testing.T) {
	m := 8
	f := randomFieldPoly(t, m)
	split := DefaultMatrixSplit(m)
	gens := testGenerators(t, split.Cols())
	cfg, err := DefaultFoldConfig(split.RowVars())
	require.NoError(t, err)
	dom, err := NewDomain(split.RowVars() + cfg.LogRate)
	require.NoError(t, err)

	got, hint, err := CommitFieldWithFoldAt(f, gens, dom, 0, cfg, split)
	require.NoError(t, err)
	assert.Nil(t, hint.Codeword)

	want, wantHint, err := commitFieldAt(f, gens, dom, 0, split, true)
	require.NoError(t, err)
	wantCosets, _, err := CommitCosets(wantHint.G, dom, cfg.Ell)
	require.NoError(t, err)
	wantCosets.Fold = cfg
	want.Cosets = wantCosets
	assert.Equal(t, want, got)
}

func TestGroupShapeValidation(t *testing.T) {
	G := randomGroupPoly(t, 4)
	dom, err := NewDomain(6)
	require.NoError(t, err)
	small, err := NewDomain(3)
	require.NoError(t, err)

	_, _, err = groupShape(G, nil, 0)
	require.ErrorIs(t, err, ErrNilDomain)
	_, _, err = groupShape(nil, dom, 0)
	require.ErrorIs(t, err, ErrNilPolynomial)
	_, _, err = groupShape(G, small, 0)
	require.ErrorIs(t, err, ErrDomainTooSmall)
	_, _, err = groupShape(G, dom, -1)
	require.ErrorIs(t, err, ErrInvalidCosetDim)
	_, _, err = groupShape(G, dom, 7)
	require.ErrorIs(t, err, ErrInvalidCosetDim)
}
