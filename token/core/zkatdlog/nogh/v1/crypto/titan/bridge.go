/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	"math/big"

	mathlib "github.com/IBM/mathlib"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"
)

// The mathlib boundary
//
// This package computes in gnark-crypto (bls12381.G1Affine, fr.Element), while
// crypto/rp/csp -- whose linear-form proof closes the column leg of an evaluation
// proof -- computes in mathlib (*mathlib.G1, *mathlib.Zr). Both sit on the same
// curve, so the conversion is lossless; the cost is not.
//
// # It is the same curve, verified rather than assumed
//
// mathlib's BLS12_381_BBS_GURVY scalar field order is bit-identical to
// fr.Modulus(). TestBridgeScalarFieldsAreIdentical pins that, because every
// conversion below depends on it and a silent divergence would corrupt proofs
// rather than fail loudly. (Comparing the two as printed strings looks like a
// mismatch -- mathlib prints hex, gnark prints decimal. Compare as big.Int.)
//
// # Cost: convert generators once, at commit time
//
// mathlib routes every G1 constructor through SetBytes, which performs a subgroup
// check (mathlib@v0.3.0/driver/gurvy/bls12381/bls12-381.go:531-559). There is no
// cheaper entry point, so a point costs ~33us to convert -- 4.3ms for 128 points,
// measured on an M4 Max. A proof on the column leg is only 2*log2(n) group
// elements, so paying that per proof would make the boundary cost more than the
// protocol it serves.
//
// The generators, though, are fixed setup parameters. They convert ONCE, when the
// commitment is made, and are held on the opening hint for every later Eval; only
// the scalars (the folded polynomial and the eq coefficients) are per-proof, and
// those cost ~72ns each. Per-proof boundary cost is therefore tens of
// microseconds, not milliseconds.
//
// This is the access-pattern rule crypto/sumcheck follows for the same reason:
// convert once at the edge, hold the converted form, never rebuild per call.
//
// # Why there is no reverse direction for points
//
// Nothing needs one. The column leg hands mathlib a statement and gets back a
// csp.Proof that only mathlib verifies, so points cross in one direction only.
// Scalars come back (toFieldElement) because a claimed evaluation is compared
// against a gnark-side value.

// bridgeCurve is the default mathlib curve for this package, used when a caller
// passes nil.
//
// It is a function rather than a package-level variable so that no global state is
// introduced; mathlib.Curves is a fixed table, so the lookup is cheap.
//
// # The choice of variant matters, but only for consistency
//
// mathlib has four BLS12-381 entries. All four share the same group and scalar
// field, so any of them converts correctly, and the conversions below take the
// curve as a parameter rather than reaching for this one -- a caller passing
// BLS12_381_BBS gets elements tagged BLS12_381_BBS.
//
// That tagging is load-bearing downstream: csp's validateG1Slice checks every
// element's curve ID against curve.ID() (via math.CheckElements), so a statement
// mixing variants is rejected even though the arithmetic would be fine. Hence the
// rule here is to convert onto the caller's curve and never onto a fixed one; this
// default exists only so the nil case has an answer.
//
// BLS12_381_BBS_GURVY matches the gurvy backend the rest of this package's
// measurements were taken against.
func bridgeCurve() *mathlib.Curve { return mathlib.Curves[mathlib.BLS12_381_BBS_GURVY] }

// toMathG1 converts a gnark-crypto G1 point to its mathlib equivalent, via the
// 48-byte compressed encoding both libraries agree on.
//
// The point at infinity is rejected. Every caller here is building CSP generators
// or a CSP commitment, and CSP rejects an identity generator outright because it
// collapses the commitment scheme (csp/validation.go validateG1Slice). Catching
// it at the boundary gives a named error instead of a failure from inside mathlib.
func toMathG1(p *bls12381.G1Affine, curve *mathlib.Curve) (*mathlib.G1, error) {
	if p == nil {
		return nil, errors.Wrap(ErrNilElement, "cannot convert a nil point")
	}
	if curve == nil {
		return nil, ErrNilCurve
	}
	if p.IsInfinity() {
		return nil, errors.Wrap(ErrPointAtInfinity, "cannot convert the point at infinity")
	}

	compressed := p.Bytes()
	out, err := curve.NewG1FromCompressed(compressed[:])
	if err != nil {
		return nil, errors.Wrap(err, "mathlib rejected a gnark-crypto G1 encoding")
	}

	return out, nil
}

// toMathG1Slice converts a slice of gnark-crypto points, reporting the index of
// the first one that fails.
//
// This is the expensive call -- see the cost note above. Call it once per
// commitment, not once per proof.
func toMathG1Slice(pts []bls12381.G1Affine, curve *mathlib.Curve) ([]*mathlib.G1, error) {
	out := make([]*mathlib.G1, len(pts))
	for i := range pts {
		converted, err := toMathG1(&pts[i], curve)
		if err != nil {
			return nil, errors.Wrapf(err, "converting point %d", i)
		}
		out[i] = converted
	}

	return out, nil
}

// toMathZr converts a gnark-crypto field element to a mathlib scalar.
//
// fr.Element is in Montgomery form internally, so the value must go through
// BigInt, which reduces out of Montgomery form, rather than through any direct
// limb access. The 32-byte big-endian encoding is what mathlib expects.
func toMathZr(e *fr.Element, curve *mathlib.Curve) (*mathlib.Zr, error) {
	if e == nil {
		return nil, errors.Wrap(ErrNilElement, "cannot convert a nil scalar")
	}
	if curve == nil {
		return nil, ErrNilCurve
	}

	var bi big.Int
	e.BigInt(&bi)

	return curve.NewZrFromBytes(padTo32(bi.Bytes())), nil
}

// toMathZrSlice converts a slice of gnark-crypto field elements.
func toMathZrSlice(es []fr.Element, curve *mathlib.Curve) ([]*mathlib.Zr, error) {
	out := make([]*mathlib.Zr, len(es))
	for i := range es {
		converted, err := toMathZr(&es[i], curve)
		if err != nil {
			return nil, errors.Wrapf(err, "converting scalar %d", i)
		}
		out[i] = converted
	}

	return out, nil
}

// toFieldElement converts a mathlib scalar back to a gnark-crypto field element.
//
// mathlib's Zr.Bytes is 32-byte big-endian, which fr.Element.SetBytes reduces
// modulo r, so the round trip is exact for any canonical input.
func toFieldElement(z *mathlib.Zr) (fr.Element, error) {
	var out fr.Element
	if z == nil {
		return out, errors.Wrap(ErrNilElement, "cannot convert a nil scalar")
	}
	out.SetBytes(z.Bytes())

	return out, nil
}

// padTo32 left-pads a big-endian byte slice to 32 bytes.
//
// big.Int.Bytes() emits the minimal encoding, so a small scalar is shorter than
// 32 bytes and mathlib would otherwise interpret the bytes at the wrong
// significance.
func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)

	return out
}
