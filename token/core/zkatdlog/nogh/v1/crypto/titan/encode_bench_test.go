/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	"crypto/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/sumcheck"
)

func benchGroupPoly(b *testing.B, m int) sumcheck.GroupPoly {
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

// BenchmarkEncodeGroupOracle measures the butterfly at the O(sqrt(n)) sizes Titan
// actually encodes: for a 2^20-coefficient witness the matrix side is 2^10, so
// m = 10 with a rate-1/2 domain is the realistic shape.
func BenchmarkEncodeGroupOracle(b *testing.B) {
	for _, m := range []int{6, 8, 10} {
		p := benchGroupPoly(b, m)
		dom, err := NewDomain(m + 1)
		if err != nil {
			b.Fatal(err)
		}
		b.Run("m="+itoa(m), func(b *testing.B) {
			for b.Loop() {
				if _, err := EncodeGroupOracle(p, dom); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkEncodeGroupOracleNaive is the baseline the butterfly replaces: one
// full multilinear evaluation per domain point. The ratio against
// BenchmarkEncodeGroupOracle is the speedup claimed in docs/crypto/titan.md.
func BenchmarkEncodeGroupOracleNaive(b *testing.B) {
	for _, m := range []int{6, 8} {
		p := benchGroupPoly(b, m)
		dom, err := NewDomain(m + 1)
		if err != nil {
			b.Fatal(err)
		}
		b.Run("m="+itoa(m), func(b *testing.B) {
			for b.Loop() {
				for _, x := range dom.Elements {
					at := make([]fr.Element, m)
					cur := x
					for j := range m {
						at[j] = cur
						cur.Square(&cur)
					}
					if _, err := p.EvaluatePoint(at); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}

// itoa avoids pulling strconv in for a benchmark label.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}

	return string(buf[i:])
}
