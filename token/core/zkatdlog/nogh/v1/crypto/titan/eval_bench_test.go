/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	"crypto/rand"
	"math/big"
	"testing"

	mathlib "github.com/IBM/mathlib"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/sumcheck"
)

// benchEvalSetup commits a random m-variable polynomial, outside the timed region.
func benchEvalSetup(b *testing.B, m int) (*mathlib.Curve, *Commitment, *FieldOpeningHint, []bls12381.G1Affine, *Generators, []fr.Element) {
	b.Helper()

	f := make(sumcheck.FieldPoly, 1<<m)
	for i := range f {
		if _, err := f[i].SetRandom(); err != nil {
			b.Fatal(err)
		}
	}
	_, numCols := matrixShape(m)

	_, _, g, _ := bls12381.Generators()
	gens := make([]bls12381.G1Affine, numCols)
	for i := range gens {
		s, err := rand.Int(rand.Reader, fr.Modulus())
		if err != nil {
			b.Fatal(err)
		}
		gens[i].ScalarMultiplication(&g, s)
	}

	dom, err := NewDomain(m - m/2 + 1)
	if err != nil {
		b.Fatal(err)
	}
	c, hint, err := CommitField(f, gens, dom, 0)
	if err != nil {
		b.Fatal(err)
	}

	alpha := make([]fr.Element, m)
	for i := range alpha {
		if _, err := alpha[i].SetRandom(); err != nil {
			b.Fatal(err)
		}
	}

	curve := mathlib.Curves[mathlib.BLS12_381_BBS]
	cg, err := NewGenerators(curve, gens)
	if err != nil {
		b.Fatal(err)
	}

	return curve, c, hint, gens, cg, alpha
}

func BenchmarkEval(b *testing.B) {
	for _, m := range []int{8, 10, 12, 14} {
		b.Run(varName(m), func(b *testing.B) {
			curve, _, hint, _, cg, alpha := benchEvalSetup(b, m)
			b.ResetTimer()
			for b.Loop() {
				if _, _, err := hint.Eval(curve, cg, alpha); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkVerifyEval(b *testing.B) {
	for _, m := range []int{8, 10, 12, 14} {
		b.Run(varName(m), func(b *testing.B) {
			curve, c, hint, _, cg, alpha := benchEvalSetup(b, m)
			proof, sigma, err := hint.Eval(curve, cg, alpha)
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for b.Loop() {
				if _, err := VerifyEval(curve, c, cg, alpha, sigma, proof); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkEvalGroup(b *testing.B) {
	for _, m := range []int{8, 10, 12} {
		b.Run(varName(m), func(b *testing.B) {
			curve := mathlib.Curves[mathlib.BLS12_381_BBS]
			_, _, g, _ := bls12381.Generators()
			G := make(sumcheck.GroupPoly, 1<<m)
			for i := range G {
				s, err := rand.Int(rand.Reader, fr.Modulus())
				if err != nil {
					b.Fatal(err)
				}
				G[i].ScalarMultiplication(&g, s)
			}
			dom, err := NewDomain(m + 1)
			if err != nil {
				b.Fatal(err)
			}
			_, hint, err := CommitGroup(G, dom, 0)
			if err != nil {
				b.Fatal(err)
			}
			alpha := make([]fr.Element, m)
			for i := range alpha {
				if _, err := alpha[i].SetRandom(); err != nil {
					b.Fatal(err)
				}
			}
			b.ResetTimer()
			for b.Loop() {
				if _, _, err := hint.EvalGroup(curve, alpha); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// The mathlib boundary, measured
//
// These are the benchmarks the caching decision rests on, and they are written to
// be read together:
//
//	BenchmarkBoundaryGenerators   what converting the generators costs (per Eval,
//	                              if not cached)
//	BenchmarkBoundaryScalars      what converting the per-proof scalars costs
//	BenchmarkEval                 the whole proof, for scale
//
// The generators are fixed setup parameters, so a caller proving many evaluations
// against one commitment converts them once; the scalars are genuinely per-proof.
// If the first number is a large fraction of BenchmarkEval and the second is not,
// hoisting the generator conversion out of Eval is worth the API change, and the
// numbers say by how much.

func BenchmarkBoundaryGenerators(b *testing.B) {
	curve := mathlib.Curves[mathlib.BLS12_381_BBS]
	_, _, g, _ := bls12381.Generators()

	for _, n := range []int{16, 64, 128, 256} {
		pts := make([]bls12381.G1Affine, n)
		for i := range pts {
			pts[i].ScalarMultiplication(&g, big.NewInt(int64(3*i+11)))
		}
		b.Run("n="+varNameRaw(n), func(b *testing.B) {
			for b.Loop() {
				if _, err := toMathG1Slice(pts, curve); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkBoundaryScalars(b *testing.B) {
	curve := mathlib.Curves[mathlib.BLS12_381_BBS]

	for _, n := range []int{16, 64, 128, 256} {
		es := make([]fr.Element, n)
		for i := range es {
			if _, err := es[i].SetRandom(); err != nil {
				b.Fatal(err)
			}
		}
		b.Run("n="+varNameRaw(n), func(b *testing.B) {
			for b.Loop() {
				if _, err := toMathZrSlice(es, curve); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func varNameRaw(n int) string { return varName(n)[2:] }

// BenchmarkEvalCachedVsUncached is the measurement the Generators type exists for:
// the same proof and the same verification, with and without the cached mathlib
// generators.
//
// The gap is the boundary cost, and on the verify side it is the majority of the
// work -- which is why Eval and VerifyEval take a *Generators and the affine forms
// are documented as the one-off path rather than the default.
func BenchmarkEvalCachedVsUncached(b *testing.B) {
	for _, m := range []int{10, 12, 14} {
		curve, c, hint, gens, cg, alpha := benchEvalSetup(b, m)
		proof, sigma, err := hint.Eval(curve, cg, alpha)
		if err != nil {
			b.Fatal(err)
		}

		b.Run("prove/cached/"+varName(m), func(b *testing.B) {
			for b.Loop() {
				if _, _, err := hint.Eval(curve, cg, alpha); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("prove/uncached/"+varName(m), func(b *testing.B) {
			for b.Loop() {
				if _, _, err := hint.EvalAffine(curve, gens, alpha); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("verify/cached/"+varName(m), func(b *testing.B) {
			for b.Loop() {
				if _, err := VerifyEval(curve, c, cg, alpha, sigma, proof); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("verify/uncached/"+varName(m), func(b *testing.B) {
			for b.Loop() {
				if _, err := VerifyEvalAffine(curve, c, gens, alpha, sigma, proof); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
