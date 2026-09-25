/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import "errors"

// Sentinel errors for the Titan polynomial commitment scheme. As in
// crypto/sumcheck/errors.go these are declared with the standard library's
// errors.New, while everything that *constructs* or *wraps* an error at a call
// site uses github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors.
var (
	// ErrNilPolynomial indicates that a required polynomial is nil.
	ErrNilPolynomial = errors.New("polynomial cannot be nil")

	// ErrNilDomain indicates that a required evaluation domain is nil.
	ErrNilDomain = errors.New("domain cannot be nil")

	// ErrNotPowerOfTwo indicates that an evaluation table's length is not a
	// power of two, so it does not describe a multilinear polynomial on a
	// boolean hypercube.
	ErrNotPowerOfTwo = errors.New("evaluation table length must be a power of two")

	// ErrDomainTooLarge indicates that the requested domain exceeds the
	// two-adicity of the scalar field, so no root of unity of that order
	// exists. For BLS12-381's Fr the limit is 2^32.
	ErrDomainTooLarge = errors.New("domain size exceeds the two-adicity of the scalar field")

	// ErrDomainTooSmall indicates that the evaluation domain is smaller than
	// the polynomial being encoded. Reed-Solomon encoding needs a domain at
	// least as large as the message, and a rate below 1 needs it strictly
	// larger.
	ErrDomainTooSmall = errors.New("domain must be at least as large as the polynomial")
)
