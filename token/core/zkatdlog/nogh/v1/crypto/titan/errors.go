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

	// ErrNumVarsMismatch indicates that two inputs disagree on the number of
	// variables, or that a slice length does not match what the caller declared.
	ErrNumVarsMismatch = errors.New("inputs must agree on the number of variables")

	// ErrZeroDenominator indicates that a value that must be inverted is zero.
	//
	// In the group sum-check this arises only if a coordinate of alpha is exactly
	// 0 or 1, which makes eq(alpha_i, b) vanish for some b. On the honest path
	// alpha is derived from the transcript, so this has negligible probability;
	// see the note on ProveGroupEval.
	ErrZeroDenominator = errors.New("cannot invert zero")

	// ErrInvalidSplit indicates that the MSM/folklore split point ell is outside
	// the valid range [0, m].
	ErrInvalidSplit = errors.New("split point must be between 0 and the number of variables")

	// ErrNilCurve indicates that a required curve parameter is nil.
	ErrNilCurve = errors.New("curve cannot be nil")

	// ErrNilElement indicates that a required curve point or scalar is nil.
	ErrNilElement = errors.New("element cannot be nil")

	// ErrNilProof indicates that a proof parameter is nil.
	ErrNilProof = errors.New("proof cannot be nil")

	// ErrRoundCountMismatch indicates that the proof does not carry exactly one
	// round message per variable.
	ErrRoundCountMismatch = errors.New("proof round count does not match number of variables")

	// ErrRoundCheckFailed indicates that a round message is inconsistent with the
	// sum claimed by the previous round. The proof is well formed but does not
	// verify.
	ErrRoundCheckFailed = errors.New("round consistency check failed")

	// ErrSumMismatch indicates that the first round message does not sum to the
	// asserted value sigma.
	ErrSumMismatch = errors.New("claimed sum does not match first round message")

	// ErrDomainTooSmall indicates that the evaluation domain is smaller than
	// the polynomial being encoded. Reed-Solomon encoding needs a domain at
	// least as large as the message, and a rate below 1 needs it strictly
	// larger.
	ErrDomainTooSmall = errors.New("domain must be at least as large as the polynomial")
)
