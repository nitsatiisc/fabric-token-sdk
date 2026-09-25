/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package sumcheck

import "errors"

// Sentinel errors for sum-check operations. These typed errors let callers
// distinguish failure causes with errors.Is, which matters in particular for
// telling a malformed proof (a caller or encoding bug) apart from a proof that
// is well formed but simply does not verify (a soundness failure).
//
// Following the convention in rp/csp/errors.go, these are declared with the
// standard library's errors.New. Everything that *constructs* or *wraps* an
// error at a call site uses
// github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors instead.
var (
	// ErrNilCurve indicates that a required curve parameter is nil.
	ErrNilCurve = errors.New("curve cannot be nil")

	// ErrWrongCurveID indicates that an element belongs to a different curve
	// than the one the sum-check instance was created with.
	ErrWrongCurveID = errors.New("wrong curve ID")

	// ErrNilPolynomial indicates that a required polynomial is nil.
	ErrNilPolynomial = errors.New("polynomial cannot be nil")

	// ErrNilElement indicates that a polynomial's evaluation table contains a
	// nil element.
	ErrNilElement = errors.New("element cannot be nil")

	// ErrNoFactors indicates that a claim has neither field nor group factors,
	// so there is no polynomial to run the protocol on.
	ErrNoFactors = errors.New("claim must have at least one factor")

	// ErrNotPowerOfTwo indicates that an evaluation table's length is not a
	// power of two, so it does not describe a multilinear polynomial on a
	// boolean hypercube.
	ErrNotPowerOfTwo = errors.New("evaluation table length must be a power of two")

	// ErrNumVarsMismatch indicates that the factors of a product do not all
	// have the same number of variables.
	ErrNumVarsMismatch = errors.New("all factors must have the same number of variables")

	// ErrTooManyGroupPolynomials indicates that more than one group factor was
	// supplied. A product of two group elements is not defined here, so a claim
	// may contain at most one group polynomial.
	ErrTooManyGroupPolynomials = errors.New("at most one group polynomial is allowed")

	// ErrNilProof indicates that a proof parameter is nil.
	ErrNilProof = errors.New("proof cannot be nil")

	// ErrRoundCountMismatch indicates that the proof does not carry exactly one
	// round polynomial per variable.
	ErrRoundCountMismatch = errors.New("proof round count does not match number of variables")

	// ErrRoundDegreeMismatch indicates that a round polynomial does not carry
	// the expected number of evaluations for the claim's degree.
	ErrRoundDegreeMismatch = errors.New("round polynomial has unexpected degree")

	// ErrRoundCheckFailed indicates that a round polynomial is inconsistent with
	// the sum claimed by the previous round. The proof is well formed but does
	// not verify.
	ErrRoundCheckFailed = errors.New("round consistency check failed")

	// ErrSumMismatch indicates that the first round polynomial does not sum to
	// the asserted value.
	ErrSumMismatch = errors.New("claimed sum does not match round polynomial")

	// ErrMixedProofKind indicates that a proof's field/group shape does not match
	// the claim being verified, for example a group proof checked against a
	// field-only claim.
	ErrMixedProofKind = errors.New("proof kind does not match claim")
)
