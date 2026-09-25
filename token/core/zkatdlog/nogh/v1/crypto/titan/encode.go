/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	"math/big"
	"math/bits"

	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/sumcheck"
)

// The univariate-multilinear correspondence
//
// Titan's IOPP works on a univariate Reed-Solomon codeword, but the committed
// object is a multilinear polynomial. The two are tied together by evaluating the
// multilinear along the "power curve":
//
//	fhat(X) := ftilde(X, X^2, X^4, ..., X^(2^(m-1)))
//
// fhat is a univariate polynomial of degree at most 2^m - 1, and the map from
// ftilde to fhat is injective: the 2^m monomials of a multilinear polynomial map
// to the 2^m distinct powers X^0 .. X^(2^m - 1), so no two coefficients collide.
// Encoding therefore means evaluating fhat on every point of the domain L, and
// that is what EncodeGroupOracle and EncodeFieldOracle return.
//
// Evaluating naively costs one multi-exponentiation per domain point. The
// butterfly below does it in m passes over the domain instead, using the
// multilinear identity in the first variable
//
//	ftilde(x, x^2, ...) = (1-x)*ftilde(0, x^2, ...) + x*ftilde(1, x^2, ...)
//	                    = ftilde(0, x^2, ...) + x*(ftilde(1, x^2, ...) - ftilde(0, x^2, ...))
//
// and the fact that the domain is closed under squaring: x and -x square to the
// same value, so one pass computes the pair of outputs at x and -x from one
// scalar multiplication. That is (n/2)*log n scalar multiplications in total,
// against roughly n*log n for forming the coefficients of fhat explicitly.

// EncodeGroupOracle evaluates the group multilinear p along the power curve at
// every point of dom, returning the Reed-Solomon codeword
//
//	out[i] = ptilde(w^i, w^(2i), w^(4i), ..., w^(2^(m-1) * i))
//
// where w = dom.Generator and m = p.NumVars(). This codeword is what the Titan
// oracle commits to: the Merkle tree is built over out, and the IOPP queries it.
//
// dom must be at least as large as p; a strictly larger domain gives the code its
// rate, which is what buys the IOPP its distance. p is not modified.
func EncodeGroupOracle(p sumcheck.GroupPoly, dom *Domain) ([]bls12381.G1Affine, error) {
	m, err := encodeParams(len(p), p == nil, dom)
	if err != nil {
		return nil, err
	}

	// Relabel the variables in reverse. The butterfly consumes variables from the
	// high bit of the index downwards, pairing it with the highest power of the
	// domain element, but the table's index puts b_0 at the low bit. After the
	// bit reversal bit 0 holds b_(m-1), so the first pass handles b_(m-1) with
	// x^(2^(m-1)) and the passes come out in the order the power curve needs.
	cur := make([]bls12381.G1Affine, len(p))
	copy(cur, p)
	if err := bitReversePermutation(cur, m); err != nil {
		return nil, err
	}

	// Blow the message up to the domain size by repeating each coefficient
	// 2^(d-m) times. Repetition — rather than zero padding — is what makes the
	// first pass see a constant on each block, which is the degree-0 case of the
	// recursion.
	d := dom.LogSize
	blowup := 1 << (d - m)
	size := dom.Size()
	in := make([]bls12381.G1Jac, size)
	for i := range cur {
		var j bls12381.G1Jac
		j.FromAffine(&cur[i])
		for k := range blowup {
			in[i*blowup+k] = j
		}
	}
	out := make([]bls12381.G1Jac, size)

	for pass := range m {
		chunkSize := 1 << (d - (m - 1 - pass))
		stepSize := chunkSize >> 1
		stride := 1 << (m - 1 - pass)
		for chunkStart := 0; chunkStart < size; chunkStart += chunkSize {
			for i := range stepSize {
				root := &dom.Elements[(stride*i)%size]

				lo := &in[chunkStart+i]
				hi := &in[chunkStart+stepSize+i]

				// factor = (hi - lo) * root
				var factor bls12381.G1Jac
				factor.Set(hi)
				factor.SubAssign(lo)
				var rootBig big.Int
				root.BigInt(&rootBig)
				factor.ScalarMultiplication(&factor, &rootBig)

				// The pair of outputs at x and -x: x gives lo+factor, and -x
				// gives lo-factor because -x negates the root.
				out[chunkStart+i].Set(lo)
				out[chunkStart+i].AddAssign(&factor)

				out[chunkStart+stepSize+i].Set(lo)
				out[chunkStart+stepSize+i].SubAssign(&factor)
			}
		}
		in, out = out, in
	}

	res := make([]bls12381.G1Affine, size)
	for i := range res {
		res[i].FromJacobian(&in[i])
	}

	return res, nil
}

// EncodeFieldOracle evaluates the field multilinear p along the power curve at
// every point of dom, returning
//
//	out[i] = ptilde(w^i, w^(2i), ..., w^(2^(m-1) * i))
//
// It is the scalar analogue of EncodeGroupOracle and follows the same butterfly.
// Titan needs it for the public generator polynomial gtilde, whose codeword the
// verifier recomputes rather than receives.
//
// dom must be at least as large as p. p is not modified.
func EncodeFieldOracle(p sumcheck.FieldPoly, dom *Domain) ([]fr.Element, error) {
	m, err := encodeParams(len(p), p == nil, dom)
	if err != nil {
		return nil, err
	}

	cur := make([]fr.Element, len(p))
	copy(cur, p)
	if err := bitReversePermutation(cur, m); err != nil {
		return nil, err
	}

	d := dom.LogSize
	blowup := 1 << (d - m)
	size := dom.Size()
	in := make([]fr.Element, size)
	for i := range cur {
		for k := range blowup {
			in[i*blowup+k] = cur[i]
		}
	}
	out := make([]fr.Element, size)

	for pass := range m {
		chunkSize := 1 << (d - (m - 1 - pass))
		stepSize := chunkSize >> 1
		stride := 1 << (m - 1 - pass)
		for chunkStart := 0; chunkStart < size; chunkStart += chunkSize {
			for i := range stepSize {
				root := &dom.Elements[(stride*i)%size]

				var factor fr.Element
				factor.Sub(&in[chunkStart+stepSize+i], &in[chunkStart+i])
				factor.Mul(&factor, root)

				out[chunkStart+i].Add(&in[chunkStart+i], &factor)
				out[chunkStart+stepSize+i].Sub(&in[chunkStart+i], &factor)
			}
		}
		in, out = out, in
	}

	return in, nil
}

// encodeParams validates a polynomial length against a domain and returns the
// polynomial's number of variables.
func encodeParams(length int, isNil bool, dom *Domain) (int, error) {
	if isNil || length == 0 {
		return 0, ErrNilPolynomial
	}
	if dom == nil {
		return 0, ErrNilDomain
	}
	if !isPowerOfTwo(length) {
		return 0, errors.Wrapf(ErrNotPowerOfTwo, "evaluation table has %d entries", length)
	}
	m := bits.Len(uint(length)) - 1
	if dom.LogSize < m {
		return 0, errors.Wrapf(ErrDomainTooSmall, "domain has 2^%d elements, polynomial needs at least 2^%d", dom.LogSize, m)
	}

	return m, nil
}
