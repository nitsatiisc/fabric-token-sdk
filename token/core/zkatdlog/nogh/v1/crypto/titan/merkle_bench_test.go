/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	"math/big"
	"strconv"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/sumcheck"
)

func benchLeaves(b *testing.B, numLeaves, k int) [][]bls12381.G1Affine {
	b.Helper()
	_, _, g, _ := bls12381.Generators()
	size := 1 << k
	out := make([][]bls12381.G1Affine, numLeaves)
	for i := range out {
		out[i] = make([]bls12381.G1Affine, size)
		for j := range out[i] {
			out[i][j].ScalarMultiplication(&g, big.NewInt(int64(7*(i*size+j)+3)))
		}
	}

	return out
}

func BenchmarkBuildTree(b *testing.B) {
	for _, logN := range []int{8, 10, 12, 14} {
		leaves := benchLeaves(b, 1<<logN, 0)
		b.Run("logN="+strconv.Itoa(logN), func(b *testing.B) {
			for b.Loop() {
				if _, err := BuildTree(leaves); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkProveMany is the measurement that motivated writing this tree rather
// than adapting gnark-crypto's streaming one: there, each opening needs a full
// rebuild, so t openings cost t*n leaf hashes. Here every level is retained, so an
// opening is a walk over stored digests and the cost is t*log(n) slice copies.
func BenchmarkProveMany(b *testing.B) {
	const logN = 14
	leaves := benchLeaves(b, 1<<logN, 0)
	tree, err := BuildTree(leaves)
	if err != nil {
		b.Fatal(err)
	}
	for _, t := range []int{1, 10, 100} {
		b.Run("openings="+strconv.Itoa(t), func(b *testing.B) {
			idx := make([]int, t)
			for i := range idx {
				idx[i] = (i * 97) % (1 << logN)
			}
			for b.Loop() {
				if _, err := tree.ProveBatch(idx); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkVerifyMerkleProof(b *testing.B) {
	for _, logN := range []int{10, 14} {
		leaves := benchLeaves(b, 1<<logN, 0)
		tree, err := BuildTree(leaves)
		if err != nil {
			b.Fatal(err)
		}
		root := tree.Root()
		proof, err := tree.Prove(42)
		if err != nil {
			b.Fatal(err)
		}
		b.Run("logN="+strconv.Itoa(logN), func(b *testing.B) {
			for b.Loop() {
				if !VerifyMerkleProof(root, leaves[42], proof) {
					b.Fatal("proof should verify")
				}
			}
		})
	}
}

func BenchmarkCommitField(b *testing.B) {
	_, _, g, _ := bls12381.Generators()
	for _, m := range []int{10, 12, 14} {
		rows, cols := matrixShape(m)
		gens := make([]bls12381.G1Affine, cols)
		for i := range gens {
			gens[i].ScalarMultiplication(&g, big.NewInt(int64(3*i+11)))
		}
		poly := make(sumcheck.FieldPoly, 1<<m)
		for i := range poly {
			poly[i].SetInt64(int64(i*31 + 7))
		}
		dom, err := NewDomain(logOfB(rows) + 1)
		if err != nil {
			b.Fatal(err)
		}
		b.Run("m="+strconv.Itoa(m), func(b *testing.B) {
			for b.Loop() {
				if _, _, err := commitField(poly, gens, dom, 0); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func logOfB(n int) int {
	d := 0
	for 1<<d < n {
		d++
	}

	return d
}
