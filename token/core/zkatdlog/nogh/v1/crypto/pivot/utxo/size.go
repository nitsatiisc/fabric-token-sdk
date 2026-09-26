/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package utxo

import (
	"reflect"

	mathlib "github.com/IBM/mathlib"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// Sizes of the wire encodings used to account for a proof: compressed points and
// canonical scalars.
const (
	frSize = 32
	g1Size = 48
	g2Size = 96
)

var (
	typeFr        = reflect.TypeOf(fr.Element{})
	typeG1        = reflect.TypeOf(bls12381.G1Affine{})
	typeG2        = reflect.TypeOf(bls12381.G2Affine{})
	typeMathlibZr = reflect.TypeOf(mathlib.Zr{})
	typeMathlibG1 = reflect.TypeOf(mathlib.G1{})
)

// proverOnlyFields are fields of the PCS proofs that the prover fills for its own
// convenience and the verifier never reads, so they are not part of the proof.
var proverOnlyFields = map[string]bool{"RowOpening": true}

// Size returns the number of bytes the proof occupies with compressed points and
// 32-byte scalars: the published A', the two commitments, the pivot proof including
// both PCS openings, and the Schnorr proofs. Integers count 8 bytes and byte slices
// their length.
func (p *Proof) Size() int { return sizeOf(reflect.ValueOf(p)) }

func sizeOf(v reflect.Value) int {
	switch v.Type() {
	case typeFr, typeMathlibZr:
		return frSize
	case typeG1, typeMathlibG1:
		return g1Size
	case typeG2:
		return g2Size
	}
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return 0
		}

		return sizeOf(v.Elem())
	case reflect.Struct:
		n := 0
		for i := range v.NumField() {
			if proverOnlyFields[v.Type().Field(i).Name] {
				continue
			}
			n += sizeOf(v.Field(i))
		}

		return n
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return v.Len()
		}
		n := 0
		for i := range v.Len() {
			n += sizeOf(v.Index(i))
		}

		return n
	case reflect.Map:
		n := 0
		it := v.MapRange()
		for it.Next() {
			n += sizeOf(it.Key()) + sizeOf(it.Value())
		}

		return n
	case reflect.Int, reflect.Int64, reflect.Uint, reflect.Uint64:
		return 8
	case reflect.Int32, reflect.Uint32:
		return 4
	case reflect.Bool, reflect.Uint8, reflect.Int8:
		return 1
	default:
		return 0
	}
}
