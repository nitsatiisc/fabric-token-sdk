/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestQueryCount pins the soundness arithmetic. The default (128 bits, rho=1/8,
// capacity) is 43 queries -- 42 would give only 126 bits, so the boundary case
// matters and is asserted explicitly.
func TestQueryCount(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		lambda  int
		logRate int
		regime  SoundnessRegime
		want    int
	}{
		{"default: 128 bits at rho=1/8 under capacity", 128, 3, Capacity, 43},
		{"johnson needs about double", 128, 3, Johnson, 86},
		{"rho=1/4 capacity", 128, 2, Capacity, 64},
		{"rho=1/4 johnson", 128, 2, Johnson, 128},
		{"rho=1/16 capacity", 128, 4, Capacity, 32},
		{"rho=1/16 johnson", 128, 4, Johnson, 64},
		{"80 bits at rho=1/8 capacity", 80, 3, Capacity, 27},
		{"exact division does not round up", 129, 3, Capacity, 43},
		{"one bit more rounds up", 130, 3, Capacity, 44},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := QueryCount(tc.lambda, tc.logRate, tc.regime)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestQueryCountMeetsTarget is the property behind the table: Q queries must
// actually reach lambda bits, and Q-1 must not. This is what would catch an
// off-by-one in the ceiling.
func TestQueryCountMeetsTarget(t *testing.T) {
	t.Parallel()

	for _, regime := range []SoundnessRegime{Capacity, Johnson} {
		for logRate := 1; logRate <= 5; logRate++ {
			for _, lambda := range []int{80, 100, 128, 192, 256} {
				q, err := QueryCount(lambda, logRate, regime)
				require.NoError(t, err)

				num, den := regime.bitsPerQuery(logRate)
				require.GreaterOrEqual(t, q*num, lambda*den,
					"%s logRate=%d lambda=%d: %d queries fall short", regime, logRate, lambda, q)
				require.Less(t, (q-1)*num, lambda*den,
					"%s logRate=%d lambda=%d: %d queries would already do", regime, logRate, lambda, q-1)
			}
		}
	}
}

func TestQueryCountRejectsBadParameters(t *testing.T) {
	t.Parallel()

	_, err := QueryCount(0, 3, Capacity)
	require.ErrorIs(t, err, ErrInvalidFoldConfig)
	_, err = QueryCount(-1, 3, Capacity)
	require.ErrorIs(t, err, ErrInvalidFoldConfig)
	_, err = QueryCount(128, 0, Capacity)
	require.ErrorIs(t, err, ErrInvalidFoldConfig)
	_, err = QueryCount(128, -2, Capacity)
	require.ErrorIs(t, err, ErrInvalidFoldConfig)
}

// TestDefaultEllIsSizeOptimal checks the claim in DefaultEll's godoc against a
// brute-force minimum, and pins the two values quoted there.
func TestDefaultEllIsSizeOptimal(t *testing.T) {
	t.Parallel()

	q, err := QueryCount(DefaultSecurityBits, DefaultLogRate, Capacity)
	require.NoError(t, err)

	for m := 2; m <= 24; m += 2 {
		got := DefaultEll(m, q)
		require.GreaterOrEqual(t, got, 1)
		require.LessOrEqual(t, got, m/2)

		size := func(ell int) int { return q<<ell + 1<<(m-ell) }
		for ell := 1; ell <= m/2; ell++ {
			require.LessOrEqual(t, size(got), size(ell),
				"m=%d: ell=%d (size %d) beats the chosen ell=%d (size %d)", m, ell, size(ell), got, size(got))
		}
	}

	// The two examples DefaultEll's godoc and the plan quote.
	require.Equal(t, 3, DefaultEll(12, q), "m=12 optimum")
	require.Equal(t, 5, DefaultEll(16, q), "m=16 optimum")

	// And the point of the exercise: the optimum is below the paper's m/2 - 1.
	require.Less(t, DefaultEll(12, q), 12/2-1)
	require.Less(t, DefaultEll(16, q), 16/2-1)
}

// TestDefaultFoldConfig checks the recommended configuration at every size it is
// defined for.
//
// m starts at 4, not 2. At m=2 the folded domain holds 2^(2-1+3) = 16 cosets and the
// default 43 queries cannot be drawn distinctly from it, so DefaultFoldConfig
// reports an error rather than returning a configuration that fails at prove time;
// TestDefaultFoldConfigHasAFloor pins that boundary. m=2 is the only even count
// affected -- m=4 already has 64 cosets.
func TestDefaultFoldConfig(t *testing.T) {
	t.Parallel()

	for m := 4; m <= 20; m += 2 {
		cfg, err := DefaultFoldConfig(m)
		require.NoError(t, err)
		require.NoError(t, cfg.Validate(m))
		require.Equal(t, DefaultLogRate, cfg.LogRate)
		require.Equal(t, 43, cfg.Queries)
		require.Equal(t, Capacity, cfg.Regime)
		require.GreaterOrEqual(t, cfg.SecurityBits(), DefaultSecurityBits)
	}
}

// TestDefaultFoldConfigHasAFloor pins the smallest polynomial the recommended
// configuration is defined for, and that the failure is reported at configuration
// time rather than deep inside proveFold.
//
// The constraint is that the Q consistency queries are DISTINCT indices into the
// folded domain, so Q <= 2^(m-Ell+LogRate). Nothing else in the package notices: the
// commit step builds the oracle happily, and it is sampleQueryIndices -- called after
// the folding rounds have already been absorbed -- that would otherwise fail.
func TestDefaultFoldConfigHasAFloor(t *testing.T) {
	t.Parallel()

	_, err := DefaultFoldConfig(2)
	require.ErrorIs(t, err, ErrInvalidFoldConfig,
		"m=2 has only 16 cosets and cannot supply 43 distinct queries")

	_, err = DefaultFoldConfig(4)
	require.NoError(t, err, "m=4 has 64 cosets, which is enough")

	// The check is on drawability, not on m: a smaller query count is fine at m=2.
	small := FoldConfig{Ell: 1, LogRate: 3, Queries: 16, Regime: Capacity}
	require.NoError(t, small.Validate(2))

	small.Queries = 17
	require.ErrorIs(t, small.Validate(2), ErrInvalidFoldConfig,
		"17 distinct queries cannot come from 16 cosets")
}

func TestFoldConfigValidate(t *testing.T) {
	t.Parallel()

	good := FoldConfig{Ell: 3, LogRate: 3, Queries: 43, Regime: Capacity}
	require.NoError(t, good.Validate(12))

	t.Run("m must be even", func(t *testing.T) {
		t.Parallel()
		require.ErrorIs(t, good.Validate(11), ErrInvalidFoldConfig)
	})
	t.Run("m must be positive", func(t *testing.T) {
		t.Parallel()
		require.ErrorIs(t, good.Validate(0), ErrInvalidFoldConfig)
		require.ErrorIs(t, good.Validate(-2), ErrInvalidFoldConfig)
	})
	t.Run("ell at the boundaries", func(t *testing.T) {
		t.Parallel()
		lo := good
		lo.Ell = 1
		require.NoError(t, lo.Validate(12))

		hi := good
		hi.Ell = 6 // m/2
		require.NoError(t, hi.Validate(12))

		tooLow := good
		tooLow.Ell = 0
		require.ErrorIs(t, tooLow.Validate(12), ErrInvalidFoldConfig)

		tooHigh := good
		tooHigh.Ell = 7 // m/2 + 1
		require.ErrorIs(t, tooHigh.Validate(12), ErrInvalidFoldConfig)
	})
	t.Run("rate and queries must be positive", func(t *testing.T) {
		t.Parallel()
		badRate := good
		badRate.LogRate = 0
		require.ErrorIs(t, badRate.Validate(12), ErrInvalidFoldConfig)

		badQ := good
		badQ.Queries = 0
		require.ErrorIs(t, badQ.Validate(12), ErrInvalidFoldConfig)
	})
	t.Run("regime must be known", func(t *testing.T) {
		t.Parallel()
		bad := good
		bad.Regime = SoundnessRegime(99)
		require.ErrorIs(t, bad.Validate(12), ErrInvalidFoldConfig)
	})
}

func TestFoldConfigDerivedSizes(t *testing.T) {
	t.Parallel()

	cfg := FoldConfig{Ell: 3, LogRate: 3, Queries: 43, Regime: Capacity}
	require.Equal(t, 8, cfg.CosetSize())
	// m=12: folded domain is 2^(12-3+3) = 2^12 leaves.
	require.Equal(t, 1<<12, cfg.NumCosets(12))

	// The oracle has NumCosets leaves of CosetSize points, covering the whole
	// encoded domain 2^(m+LogRate).
	require.Equal(t, 1<<(12+3), cfg.NumCosets(12)*cfg.CosetSize())
}

func TestSoundnessRegimeString(t *testing.T) {
	t.Parallel()

	require.Equal(t, "capacity", Capacity.String())
	require.Equal(t, "johnson", Johnson.String())
	require.Equal(t, "unknown", SoundnessRegime(42).String())
}

func TestFoldConfigSecurityBits(t *testing.T) {
	t.Parallel()

	require.Equal(t, 129, FoldConfig{LogRate: 3, Queries: 43, Regime: Capacity}.SecurityBits())
	require.Equal(t, 129, FoldConfig{LogRate: 3, Queries: 86, Regime: Johnson}.SecurityBits())
	// Half the queries under Johnson buys half the bits.
	require.Equal(t, 64, FoldConfig{LogRate: 3, Queries: 43, Regime: Johnson}.SecurityBits())
}
