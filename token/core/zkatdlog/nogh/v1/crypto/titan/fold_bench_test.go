/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	"strconv"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/stretchr/testify/require"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/rp/csp"
)

// benchFoldTranscript opens a transcript for the folding phase in isolation, using
// the same construction on both sides so the challenges agree.
func benchFoldTranscript() *csp.Transcript {
	tr := &csp.Transcript{Curve: testCurve()}
	tr.InitHasherWithDomain("TitanFoldBench")

	return tr
}

// foldProofBytes is the wire size of a fold proof, counting compressed group
// elements and Merkle digests.
//
// It counts real serialized sizes rather than estimating, because DefaultEll's
// size model is what these benchmarks exist to check: an estimate that agreed with
// the model it is meant to validate would prove nothing.
func foldProofBytes(p *FoldProof) int {
	const pointBytes = bls12381.SizeOfG1AffineCompressed

	total := len(p.Rounds) * numRoundEvals * pointBytes
	total += len(p.Reduced) * pointBytes
	for _, q := range p.Queries {
		total += len(q.Leaf) * pointBytes
		total += 8 // Index
		if q.Path != nil {
			total += len(q.Path.Siblings) * DigestSize
		}
	}

	return total
}

// BenchmarkFoldProofSize reports proof size against ell, so DefaultEll's choice can
// be checked against measured bytes.
//
// The size model is Q*2^ell (the cosets) + 2^(m-ell) (the reduced polynomial), and
// the coset term carries the Q factor -- which is why the optimum sits well below
// m/2. These cases print the real numbers for that curve.
func BenchmarkFoldProofSize(b *testing.B) {
	const m = 12

	cfg0, err := DefaultFoldConfig(m)
	require.NoError(b, err)

	for ell := 1; ell <= m/2; ell++ {
		cfg := cfg0
		cfg.Ell = ell

		b.Run(varName(m)+"/ell="+strconv.Itoa(ell), func(b *testing.B) {
			dom, err := NewDomain(m + cfg.LogRate)
			require.NoError(b, err)

			G := randomGroupPolyB(b, m)
			_, hint, err := CommitGroupWithFold(G, dom, 0, cfg)
			require.NoError(b, err)

			alpha := randomPointB(b, m)
			claim, err := msm(G, eqTable(alpha))
			require.NoError(b, err)

			p, err := proveFold(benchFoldTranscript(), G, hint.Cosets, cfg, alpha, &claim)
			require.NoError(b, err)

			for b.Loop() {
				_ = foldProofBytes(p)
			}
			b.StopTimer()

			// Reported after the loop: ResetTimer clears custom metrics, so
			// reporting before it silently drops them.
			b.ReportMetric(0, "ns/op")
			b.ReportMetric(float64(foldProofBytes(p)), "proof-bytes")
			b.ReportMetric(float64(cfg.Queries*(1<<uint(ell))), "coset-pts")
			b.ReportMetric(float64(int(1)<<uint(m-ell)), "reduced-pts")
		})
	}
}

// BenchmarkFoldProve measures the prover against m at the default configuration.
func BenchmarkFoldProve(b *testing.B) {
	for _, m := range []int{8, 10, 12} {
		cfg, err := DefaultFoldConfig(m)
		require.NoError(b, err)

		b.Run(varName(m)+"/ell="+strconv.Itoa(cfg.Ell), func(b *testing.B) {
			dom, err := NewDomain(m + cfg.LogRate)
			require.NoError(b, err)

			G := randomGroupPolyB(b, m)
			_, hint, err := CommitGroupWithFold(G, dom, 0, cfg)
			require.NoError(b, err)

			alpha := randomPointB(b, m)
			claim, err := msm(G, eqTable(alpha))
			require.NoError(b, err)

			b.ResetTimer()
			for b.Loop() {
				_, err := proveFold(benchFoldTranscript(), G, hint.Cosets, cfg, alpha, &claim)
				require.NoError(b, err)
			}
		})
	}
}

// BenchmarkFoldVerify measures the verifier, which is the side that matters for a
// PCS: it is what every party runs.
func BenchmarkFoldVerify(b *testing.B) {
	for _, m := range []int{8, 10, 12} {
		cfg, err := DefaultFoldConfig(m)
		require.NoError(b, err)

		b.Run(varName(m)+"/ell="+strconv.Itoa(cfg.Ell), func(b *testing.B) {
			dom, err := NewDomain(m + cfg.LogRate)
			require.NoError(b, err)

			G := randomGroupPolyB(b, m)
			com, hint, err := CommitGroupWithFold(G, dom, 0, cfg)
			require.NoError(b, err)

			alpha := randomPointB(b, m)
			claim, err := msm(G, eqTable(alpha))
			require.NoError(b, err)

			p, err := proveFold(benchFoldTranscript(), G, hint.Cosets, cfg, alpha, &claim)
			require.NoError(b, err)

			b.ResetTimer()
			for b.Loop() {
				require.NoError(b, verifyFold(benchFoldTranscript(), com.Cosets, cfg, alpha, &claim, p))
			}
		})
	}
}
