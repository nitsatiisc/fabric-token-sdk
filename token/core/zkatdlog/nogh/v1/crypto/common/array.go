/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"bytes"
	"encoding/hex"

	math "github.com/IBM/mathlib"
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"
)

// Separator is used to delimit to end an array of bytes.
// The bytes are the bytes of hex-encoded string.
const Separator = "||"

// G1Array is an array of G1 elements
type G1Array []*math.G1

// Bytes serialize an array of G1 elements
func (a *G1Array) Bytes() ([]byte, error) {
	raw := make([][]byte, len([]*math.G1(*a)))
	for i, e := range []*math.G1(*a) {
		if e == nil {
			return nil, errors.Errorf("failed to marshal array of G1")
		}
		st := hex.EncodeToString(e.Bytes())
		raw[i] = []byte(st)
	}
	// join the serialization of the group elements with the predefined separator.
	return bytes.Join(raw, []byte(Separator)), nil
}

// The function is added to compute hash of G1 vector with pure byte representation.
// This is intended to be used to compute Fiat-Shamir challenges, and so we need a
// method which is easily portable to other environments such as Solidity, Rust etc.
// For serialization/deserializaton of proofs, we should use Bytes(), while this function
// should be used for computing RO queries.
func (a *G1Array) RawBytes() ([]byte, error) {
	raw := make([][]byte, len([]*math.G1(*a)))
	for i, e := range []*math.G1(*a) {
		if e == nil {
			return nil, errors.Errorf("failed to marshal array of G1")
		}
		raw[i] = e.Bytes()
	}
	// join the serialization of the group elements
	return bytes.Join(raw, nil), nil
}

// GetG1Array takes a series of G1 elements and returns the corresponding array
func GetG1Array(elements ...[]*math.G1) *G1Array {
	var array []*math.G1
	for _, e := range elements {
		array = append(array, e...)
	}
	a := G1Array(array)
	return &a
}
