/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pivot

import "errors"

// Sentinel errors. As in the sumcheck and titan packages these are declared with
// the standard library, and every call site wraps them with the fabric-smart-client
// errors package.
var (
	// ErrInvalidSizes indicates sizes that the protocol or the underlying PCSes
	// cannot run at.
	ErrInvalidSizes = errors.New("invalid sizes")

	// ErrInvalidRelation indicates a malformed relation: wrong vector lengths or a
	// sparse entry, affine form or monomial that refers outside its bounds.
	ErrInvalidRelation = errors.New("invalid relation")

	// ErrInvalidStatement indicates a malformed statement.
	ErrInvalidStatement = errors.New("invalid statement")

	// ErrInvalidWitness indicates a witness whose dimensions do not match the setup.
	ErrInvalidWitness = errors.New("invalid witness")

	// ErrMalformedProof indicates a proof that is missing parts or has parts of the
	// wrong size. It is a structural failure, distinct from a proof that is well
	// formed but does not verify.
	ErrMalformedProof = errors.New("malformed proof")

	// ErrVerificationFailed indicates a well-formed proof that does not verify.
	ErrVerificationFailed = errors.New("verification failed")

	// ErrInternal indicates an inconsistency in the prover's own computation, which
	// is a bug rather than a property of the witness.
	ErrInternal = errors.New("internal prover inconsistency")
)
