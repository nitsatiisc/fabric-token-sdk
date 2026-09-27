/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/rp/csp"
)

func queryTranscript(t *testing.T, domain string) *csp.Transcript {
	t.Helper()

	tr := &csp.Transcript{Curve: testCurve()}
	tr.InitHasherWithDomain(domain)

	return tr
}

// TestSampleQueryIndicesIsDeterministic pins that the two sides of the protocol
// agree. Fiat-Shamir soundness rests on the verifier recomputing exactly the
// prover's indices, so identical transcripts must yield identical draws.
func TestSampleQueryIndicesIsDeterministic(t *testing.T) {
	t.Parallel()

	a, err := sampleQueryIndices(queryTranscript(t, "q"), 256, 20)
	require.NoError(t, err)
	b, err := sampleQueryIndices(queryTranscript(t, "q"), 256, 20)
	require.NoError(t, err)

	require.Equal(t, a, b)
}

// TestSampleQueryIndicesDependsOnTheTranscript pins the other half: a different
// transcript must give different indices, or the "random" queries would be a fixed
// set a prover could prepare for.
func TestSampleQueryIndicesDependsOnTheTranscript(t *testing.T) {
	t.Parallel()

	a, err := sampleQueryIndices(queryTranscript(t, "one"), 1024, 30)
	require.NoError(t, err)
	b, err := sampleQueryIndices(queryTranscript(t, "two"), 1024, 30)
	require.NoError(t, err)

	require.NotEqual(t, a, b)
}

// TestSampleQueryIndicesAreInRangeAndDeduplicated checks what the verifier relies
// on: every index is a valid leaf, and each distinct index appears once, so every
// sampled coset is opened exactly once. The count is at most q and at most n.
func TestSampleQueryIndicesAreInRangeAndDeduplicated(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ n, q int }{
		{2, 1}, {2, 2}, {2, 43}, {16, 8}, {16, 16}, {16, 43}, {256, 43}, {1024, 100},
	} {
		got, err := sampleQueryIndices(queryTranscript(t, "q"), tc.n, tc.q)
		require.NoError(t, err)
		require.NotEmpty(t, got)
		require.LessOrEqual(t, len(got), min(tc.n, tc.q), "n=%d q=%d", tc.n, tc.q)

		seen := make(map[int]struct{}, len(got))
		for _, idx := range got {
			require.GreaterOrEqual(t, idx, 0)
			require.Less(t, idx, tc.n)
			_, dup := seen[idx]
			require.False(t, dup, "index %d returned twice (n=%d q=%d)", idx, tc.n, tc.q)
			seen[idx] = struct{}{}
		}
	}
}

// TestSampleQueryIndicesAreIndependentDraws pins that the q draws are independent:
// the distinct indices are exactly the first appearances among q squeezes, so a
// larger q extends a smaller one's list rather than reshuffling it, and there are
// no redraws. Both sides depend on this to derive the same list.
func TestSampleQueryIndicesAreIndependentDraws(t *testing.T) {
	t.Parallel()

	const n = 16
	short, err := sampleQueryIndices(queryTranscript(t, "prefix"), n, 10)
	require.NoError(t, err)
	long, err := sampleQueryIndices(queryTranscript(t, "prefix"), n, 40)
	require.NoError(t, err)

	require.Equal(t, short, long[:len(short)], "the first 10 draws must give the same distinct indices")
}

// TestSampleQueryIndicesCoversTheDomain sanity-checks that the draws are spread
// rather than clustered in a prefix -- the failure a truncated or mis-masked
// reduction would produce.
func TestSampleQueryIndicesCoversTheDomain(t *testing.T) {
	t.Parallel()

	const n, q = 1024, 200
	got, err := sampleQueryIndices(queryTranscript(t, "spread"), n, q)
	require.NoError(t, err)

	var high int
	for _, idx := range got {
		if idx >= n/2 {
			high++
		}
	}
	// With q=200 uniform draws the upper half should hold roughly 100. A mask bug
	// that dropped the top bit would give exactly zero.
	require.Greater(t, high, q/4, "draws look confined to the low half: %d of %d", high, q)
}

// TestSampleQueryIndicesCanExceedTheDomain pins that q > n is allowed: many draws
// over a small domain cover most or all of it, which is at least as sound.
func TestSampleQueryIndicesCanExceedTheDomain(t *testing.T) {
	t.Parallel()

	const n = 8
	got, err := sampleQueryIndices(queryTranscript(t, "all"), n, 256)
	require.NoError(t, err)
	require.Len(t, got, n, "256 independent draws over 8 leaves should hit every leaf")
}

// TestSampleQueryIndicesValidation covers the argument guards.
func TestSampleQueryIndicesValidation(t *testing.T) {
	t.Parallel()

	t.Run("nil transcript", func(t *testing.T) {
		t.Parallel()
		_, err := sampleQueryIndices(nil, 16, 2)
		require.Error(t, err)
	})

	for _, tc := range []struct {
		name string
		n, q int
	}{
		{"zero domain", 0, 1},
		{"negative domain", -8, 1},
		{"domain not a power of two", 12, 1},
		{"zero queries", 16, 0},
		{"negative queries", 16, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := sampleQueryIndices(queryTranscript(t, "q"), tc.n, tc.q)
			require.Error(t, err)
		})
	}
}
