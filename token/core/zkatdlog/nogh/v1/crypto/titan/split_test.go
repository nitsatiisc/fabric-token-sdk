/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSplitShapeMultipliesBack is the one invariant every split must satisfy: the two
// halves have to cover the polynomial exactly. A split whose Rows()*Cols() is not 2^M
// would commit a matrix that does not hold f.
func TestSplitShapeMultipliesBack(t *testing.T) {
	t.Parallel()

	for m := 1; m <= 20; m++ {
		for m1 := range m {
			s := Split{M: m, M1: m1}
			if s.Validate() != nil {
				continue
			}
			require.Equal(t, 1<<m, s.Rows()*s.Cols(),
				"M=%d M1=%d: %d rows x %d cols does not cover 2^%d coefficients",
				m, m1, s.Rows(), s.Cols(), m)
			require.Equal(t, m, s.RowVars()+s.ColVars(),
				"M=%d M1=%d: the halves must account for every variable", m, m1)
		}
	}
}

// TestSplitValidateIsWeakerThanValidateForFold pins the separation between the two
// checks, which is the part of this type most likely to be "simplified" into one.
//
// Committing a field polynomial needs only that the halves multiply back. Folding
// additionally needs an EVEN row half, because the coset layout halves it exactly.
// These are different contracts and they belong to different phases: commitFieldAt
// calls Validate, CommitFieldWithFoldAt calls ValidateForFold.
//
// Collapsing them is not hypothetical. An earlier draft of this type put the
// even-row-half rule in Validate, and it broke every odd-m and m=2 test in the
// package at once -- because those sizes commit and open perfectly well through the
// non-folding stages, which is exactly what those tests check.
func TestSplitValidateIsWeakerThanValidateForFold(t *testing.T) {
	t.Parallel()

	// Legal to commit, illegal to fold: the row half is odd.
	for _, s := range []Split{
		{M: 2, M1: 1},  // rowVars 1
		{M: 6, M1: 3},  // rowVars 3 -- the balanced split of m=6
		{M: 10, M1: 5}, // rowVars 5 -- the balanced split of m=10
		{M: 9, M1: 4},  // rowVars 5
	} {
		require.NoError(t, s.Validate(),
			"M=%d M1=%d must be committable: the halves multiply back", s.M, s.M1)
		require.ErrorIs(t, s.ValidateForFold(), ErrInvalidMatrixSplit,
			"M=%d M1=%d has an odd row half (%d) and must not be foldable", s.M, s.M1, s.RowVars())
	}

	// Legal for both.
	for _, s := range []Split{
		{M: 4, M1: 2},
		{M: 8, M1: 4},
		{M: 9, M1: 3},  // odd M, even row half -- impossible under a hardcoded m/2
		{M: 10, M1: 4}, // m=10, which the balanced split cannot fold
		{M: 18, M1: 8}, // the Rust reference's own value for m=18
	} {
		require.NoError(t, s.Validate(), "M=%d M1=%d", s.M, s.M1)
		require.NoError(t, s.ValidateForFold(), "M=%d M1=%d", s.M, s.M1)
	}
}

// TestSplitValidateRejectsDegenerate covers the boundaries of the commit-time
// contract.
func TestSplitValidateRejectsDegenerate(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		s    Split
	}{
		{"zero variables", Split{M: 0, M1: 0}},
		{"negative variables", Split{M: -4, M1: 1}},
		{"negative column half", Split{M: 8, M1: -1}},
		{"empty column half", Split{M: 8, M1: 0}},
		{"column half takes every variable", Split{M: 8, M1: 8}},
		{"column half exceeds the polynomial", Split{M: 8, M1: 9}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.ErrorIs(t, tc.s.Validate(), ErrInvalidMatrixSplit)
		})
	}

	// M=1, M1=0 is the one degenerate shape that IS accepted, because matrixShape(1)
	// produced it before the split became a parameter and rejecting it now would be a
	// behaviour change rather than a threading change. Nothing can fold it.
	deg := Split{M: 1, M1: 0}
	require.NoError(t, deg.Validate(), "the legacy 2x1 shape must stay committable")
	require.Error(t, deg.ValidateForFold(), "but it must never be foldable")
}

// TestDefaultMatrixSplitIsTheBalancedCut pins the default, which is a compatibility
// guarantee and not merely a convenience: every commitment made before the split was a
// parameter used m/2, so changing this default would silently stop such commitments
// from verifying.
//
// It is also the value matrixShape returns, and the two must not drift -- matrixShape
// is what the non-split call sites and most tests still go through.
func TestDefaultMatrixSplitIsTheBalancedCut(t *testing.T) {
	t.Parallel()

	for m := 1; m <= 24; m++ {
		s := DefaultMatrixSplit(m)
		require.Equal(t, m, s.M)
		require.Equal(t, m/2, s.M1, "m=%d: the default cut must stay at m/2", m)

		rows, cols := matrixShape(m)
		require.Equal(t, rows, s.Rows(), "m=%d: matrixShape and the default split must agree on rows", m)
		require.Equal(t, cols, s.Cols(), "m=%d: matrixShape and the default split must agree on columns", m)
	}

	// When is the balanced cut foldable? The rule is that RowVars = m - m/2 is even,
	// and it is worth writing out because the familiar "m must be a multiple of 4" is
	// only half of it:
	//
	//	m  % 4 == 0  ->  rowVars = m/2, even            foldable  (4, 8, 12, ...)
	//	m  % 4 == 3  ->  rowVars = (m+1)/2, even        foldable  (3, 7, 11, ...)
	//	m  % 4 == 1  ->  rowVars = (m+1)/2, odd         not foldable
	//	m  % 4 == 2  ->  rowVars = m/2, odd             not foldable
	//
	// So the odd sizes m = 3, 7, 11, ... were never blocked by the SPLIT; the field
	// path rejected them only because of the separate drawability floor (the default
	// 43 queries must come from 2^(rowVars-Ell+LogRate) cosets, which needs rowVars
	// >= 4). Conflating the two is easy: an earlier version of this very assertion
	// claimed "foldable iff m %% 4 == 0" and failed at m = 3.
	for m := 1; m <= 24; m++ {
		foldable := DefaultMatrixSplit(m).ValidateForFold() == nil
		require.Equal(t, (m-m/2)%2 == 0, foldable,
			"m=%d: the balanced split is foldable iff its row half (%d) is even",
			m, m-m/2)
		require.Equal(t, m%4 == 0 || m%4 == 3, foldable,
			"m=%d: equivalently, iff m %% 4 is 0 or 3", m)
	}
}

// TestSplitRowVarsIsWhatSizesTheDomain guards the asymmetry that
// TestPCSSetupSizesTheDomainByTheFoldedHalf tests at the setup level: the fold, and
// therefore the evaluation domain, runs over the ROW half only. Sizing anything by M
// where RowVars belongs costs a factor of 2^M1 and nothing functional notices.
func TestSplitRowVarsIsWhatSizesTheDomain(t *testing.T) {
	t.Parallel()

	s := Split{M: 18, M1: 8}
	require.Equal(t, 10, s.RowVars())
	require.Equal(t, 8, s.ColVars())
	require.Equal(t, 1<<10, s.Rows())
	require.Equal(t, 1<<8, s.Cols())

	// A smaller column half moves work onto the fold: fewer generators, bigger domain.
	small := Split{M: 18, M1: 2}
	require.Less(t, small.Cols(), s.Cols(), "a smaller M1 needs fewer generators")
	require.Greater(t, small.Rows(), s.Rows(), "and a correspondingly larger row half to fold")
}
