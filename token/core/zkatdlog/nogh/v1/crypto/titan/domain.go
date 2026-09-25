/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	"math/bits"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/fft"
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"
)

// MaxLogDomainSize is the two-adicity of BLS12-381's scalar field: r-1 is
// divisible by 2^32 but not 2^33, so the largest smooth multiplicative subgroup
// of Fr has order 2^32 and no root of unity of higher 2-power order exists.
//
// This matters for portability: the Rust reference implementation uses the Pasta
// curves, whose Fq has two-adicity 32 as well, so a domain that is expressible
// there is expressible here and the encoding carries over unchanged.
const MaxLogDomainSize = 32

// Domain is a smooth multiplicative subgroup L of Fr of order 2^LogSize,
// materialized as the full list of its elements in generator order:
// Elements[i] = Generator^i.
//
// The butterfly in EncodeGroupOracle indexes this slice at strides that are
// powers of two, so it wants the elements laid out rather than recomputed; the
// slice costs 32 bytes per element, which is negligible at the O(sqrt(n)) sizes
// Titan encodes.
type Domain struct {
	// LogSize is d, so the domain has 2^d elements.
	LogSize int

	// Generator is a primitive 2^LogSize-th root of unity in Fr.
	Generator fr.Element

	// Elements holds the 2^LogSize domain elements, Elements[i] = Generator^i.
	Elements []fr.Element
}

// NewDomain returns the multiplicative subgroup of Fr of order 2^logSize.
//
// logSize must be in [0, MaxLogDomainSize]; a larger value returns
// ErrDomainTooLarge, because no root of unity of that order exists in Fr.
func NewDomain(logSize int) (*Domain, error) {
	if logSize < 0 || logSize > MaxLogDomainSize {
		return nil, errors.Wrapf(ErrDomainTooLarge, "requested 2^%d elements, limit is 2^%d", logSize, MaxLogDomainSize)
	}

	size := uint64(1) << logSize
	// fft.NewDomain panics rather than erroring when the root of unity does not
	// exist; the bound check above is what keeps us on the supported side of it.
	gnarkDomain := fft.NewDomain(size)

	elements := make([]fr.Element, size)
	elements[0] = fr.One()
	for i := uint64(1); i < size; i++ {
		elements[i].Mul(&elements[i-1], &gnarkDomain.Generator)
	}

	return &Domain{
		LogSize:   logSize,
		Generator: gnarkDomain.Generator,
		Elements:  elements,
	}, nil
}

// Size returns the number of domain elements, 2^LogSize.
func (d *Domain) Size() int { return len(d.Elements) }

// reverseBits reverses the low numBits bits of x.
func reverseBits(x, numBits int) int {
	result := 0
	for range numBits {
		result = (result << 1) | (x & 1)
		x >>= 1
	}

	return result
}

// bitReversePermutation reorders data in place so that the element at index i
// moves to index reverseBits(i, m).
//
// Applied to a multilinear evaluation table in the little-endian layout this
// repository uses — entry i holds p(b_0, ..., b_(m-1)) with b_j the j-th bit of
// i — it relabels the variables in reverse, mapping p(b_0, ..., b_(m-1)) to
// p(b_(m-1), ..., b_0). The butterfly needs that relabelling; see
// EncodeGroupOracle.
//
// data must have length 2^m.
func bitReversePermutation[T any](data []T, m int) error {
	n := 1 << m
	if len(data) != n {
		return errors.Wrapf(ErrNotPowerOfTwo, "expected 2^%d = %d elements, got %d", m, n, len(data))
	}
	for i := range n {
		j := reverseBits(i, m)
		if i < j {
			data[i], data[j] = data[j], data[i]
		}
	}

	return nil
}

// isPowerOfTwo reports whether n is a positive power of two.
func isPowerOfTwo(n int) bool { return n > 0 && bits.OnesCount(uint(n)) == 1 }
