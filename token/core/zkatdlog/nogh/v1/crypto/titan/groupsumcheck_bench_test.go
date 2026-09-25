/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	"crypto/rand"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/sumcheck"
)

// randomGroupPolyB and randomPointB mirror the test helpers for *testing.B.
func randomGroupPolyB(b *testing.B, m int) sumcheck.GroupPoly {
	b.Helper()
	_, _, g1Aff, _ := bls12381.Generators()
	p := make(sumcheck.GroupPoly, 1<<m)
	for i := range p {
		s, err := rand.Int(rand.Reader, fr.Modulus())
		if err != nil {
			b.Fatal(err)
		}
		p[i].ScalarMultiplication(&g1Aff, s)
	}

	return p
}

func randomPointB(b *testing.B, m int) []fr.Element {
	b.Helper()
	at := make([]fr.Element, m)
	for i := range at {
		if _, err := at[i].SetRandom(); err != nil {
			b.Fatal(err)
		}
	}

	return at
}

// BenchmarkProveGroupEval measures the prover at the default split, ell = m/2,
// which is the regime the cost analysis targets: sqrt(n) MSMs of size sqrt(n).
func BenchmarkProveGroupEval(b *testing.B) {
	curve := testCurve()
	for _, m := range []int{8, 10, 12} {
		f := randomGroupPolyB(b, m)
		alpha := randomPointB(b, m)
		b.Run("m="+itoa(m), func(b *testing.B) {
			for b.Loop() {
				if _, _, _, err := ProveGroupEval(curve, f, alpha, DefaultSplit(m)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkProveGroupEvalSplit sweeps ell at a fixed m. The proof is the same for
// every ell, so this isolates what the partial-sum machinery actually buys: ell=0
// is the folklore prover, and the minimum should sit near m/2.
func BenchmarkProveGroupEvalSplit(b *testing.B) {
	curve := testCurve()
	m := 12
	f := randomGroupPolyB(b, m)
	alpha := randomPointB(b, m)
	for ell := 0; ell <= m; ell += 2 {
		b.Run("ell="+itoa(ell), func(b *testing.B) {
			for b.Loop() {
				if _, _, _, err := ProveGroupEval(curve, f, alpha, ell); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkVerifyGroupEval measures the verifier, which is O(m) group operations
// and holds no polynomial.
func BenchmarkVerifyGroupEval(b *testing.B) {
	curve := testCurve()
	m := 12
	f := randomGroupPolyB(b, m)
	alpha := randomPointB(b, m)
	proof, _, sigma, err := ProveGroupEval(curve, f, alpha, DefaultSplit(m))
	if err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		if _, err := VerifyGroupEval(curve, proof, alpha, &sigma, DefaultSplit(m)); err != nil {
			b.Fatal(err)
		}
	}
}
