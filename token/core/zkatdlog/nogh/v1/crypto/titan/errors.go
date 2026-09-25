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

	// ErrNilTree indicates that a required Merkle tree is nil.
	ErrNilTree = errors.New("merkle tree cannot be nil")

	// ErrEmptyLeaves indicates that a Merkle tree was requested over no leaves.
	// A tree needs at least one leaf to have a root.
	ErrEmptyLeaves = errors.New("merkle tree needs at least one leaf")

	// ErrRaggedLeaves indicates that the leaves of a Merkle tree do not all hold
	// the same number of group elements. Every leaf must be a coset of the same
	// size, or the root would commit to inconsistently shaped data.
	ErrRaggedLeaves = errors.New("all merkle leaves must hold the same number of points")

	// ErrLeafIndexOutOfRange indicates that a requested opening names a leaf that
	// does not exist in the tree.
	ErrLeafIndexOutOfRange = errors.New("merkle leaf index out of range")

	// ErrProofLengthMismatch indicates that a Merkle proof does not carry one
	// sibling per level of the tree it claims to open.
	ErrProofLengthMismatch = errors.New("merkle proof length does not match tree depth")

	// ErrInvalidCosetDim indicates that the coset dimension k is negative, or is
	// large enough that the codeword cannot be split into whole cosets.
	ErrInvalidCosetDim = errors.New("invalid coset dimension")

	// ErrInsufficientGenerators indicates that fewer Pedersen generators were
	// supplied than the row length of the matrix form of the polynomial.
	ErrInsufficientGenerators = errors.New("not enough generators to commit a row")

	// ErrInvalidFoldConfig indicates that a FoldConfig is not usable: ell outside
	// [1, m/2], a non-positive rate or query count, or an odd number of variables.
	ErrInvalidFoldConfig = errors.New("invalid fold configuration")

	// ErrFoldRoundMismatch indicates that a fold proof does not carry exactly one
	// round message per folding round, or that a round message is inconsistent
	// with the claim the previous round left.
	ErrFoldRoundMismatch = errors.New("fold proof round count or round check failed")

	// ErrReducedPolyMismatch indicates that the reduced polynomial sent in plain
	// does not have the 2^(m-ell) coefficients the configuration implies.
	ErrReducedPolyMismatch = errors.New("reduced polynomial has the wrong length")

	// ErrReducedClaimMismatch indicates that the dot product of the reduced
	// polynomial with the eq table does not equal the claim the folding rounds
	// left. The folding is internally consistent but opens to the wrong value.
	ErrReducedClaimMismatch = errors.New("reduced claim does not match the folded claim")

	// ErrCosetOpeningInvalid indicates that a consistency query failed: the coset
	// does not lie under the committed Merkle root, or the coset folds to a value
	// other than the reduced polynomial's codeword at that index.
	//
	// This is the error that catches a prover who committed to one polynomial and
	// ran the folding over another.
	ErrCosetOpeningInvalid = errors.New("coset consistency query failed")

	// ErrQueryCountMismatch indicates that a fold proof does not carry the number
	// of consistency queries the configuration requires. Accepting fewer would
	// lower the soundness of the proof below its stated level.
	ErrQueryCountMismatch = errors.New("fold proof query count does not match configuration")

	// ErrPointAtInfinity indicates that the point at infinity was supplied where
	// a non-identity point is required. Crossing into mathlib for the CSP linear
	// form, an identity generator would collapse the commitment scheme, and CSP
	// rejects it; this reports it at the boundary instead.
	ErrPointAtInfinity = errors.New("point at infinity is not a valid group element here")
)
