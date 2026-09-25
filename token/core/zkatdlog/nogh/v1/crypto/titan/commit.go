/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/sumcheck"
)

// Titan commitment: two tiers, two entry points
//
// Titan commits a *field* multilinear f in two tiers, and the inner tier is by
// itself a commitment to a *group* multilinear. That is why one scheme serves both
// cases: the group case simply skips the outer tier.
//
//	Tier 1 (field only)  rows of the matrix form of f -> Pedersen -> G, a group
//	                     multilinear whose coefficients are group elements
//	Tier 2 (both)        G -> Reed-Solomon codeword over L -> cosets -> Merkle root
//
// So:
//
//	CommitGroup(G)  = tier 2                 a group polynomial commitment
//	CommitField(f)  = tier 1 then tier 2     a field polynomial commitment
//
// Note the direction of tier 1: Pedersen does not commit *to* G, it *produces* G.
// G is already a commitment to f, row by row, binding under discrete log. Tier 2
// then makes G queryable, binding under the random oracle. Two assumptions doing
// two different jobs.
//
// What this does not do
//
// A commitment here is binding and queryable by *position* of the codeword. It is
// not yet an evaluation proof: nothing here shows that f(z) = v for a claimed v.
// That needs the WHIR folding rounds plus the group sum-check of groupsumcheck.go,
// and is the next step. Commit and Eval are separate for that reason.

// Commitment is the public commitment to a polynomial: a Merkle root plus the
// parameters needed to interpret an opening against it.
//
// The root alone would be ambiguous -- the same bytes could be a tree over a
// different number of variables, a different rate, or a different coset size --
// so the shape travels with it and a verifier must check it against what it
// expects.
type Commitment struct {
	// Root is the Merkle root of the codeword of the group multilinear.
	Root []byte
	// NumVars is the number of variables of the committed group multilinear G.
	// For a field commitment this is log2 of the matrix row count, not the
	// number of variables of f.
	NumVars int
	// LogDomain is log2 of the evaluation domain size |L|.
	LogDomain int
	// K is the coset dimension: each Merkle leaf holds 2^K group elements.
	K int
	// NumLeaves is the leaf count of the tree, |L| / 2^K.
	NumLeaves int
}

// GroupOpeningHint is the prover's retained state for a group commitment. It is
// not part of the commitment and must not be sent to a verifier.
type GroupOpeningHint struct {
	// G is the committed group multilinear, in evaluation form.
	G sumcheck.GroupPoly
	// Codeword is the Reed-Solomon encoding of G over the domain.
	Codeword []bls12381.G1Affine
	// Leaves is the codeword grouped into cosets, one per Merkle leaf.
	Leaves [][]bls12381.G1Affine
	// Tree retains every level, so any number of openings are slice reads.
	Tree *Tree
}

// FieldOpeningHint is the prover's retained state for a field commitment: the
// group-side state plus the tier-1 data that produced it.
type FieldOpeningHint struct {
	GroupOpeningHint
	// Rows is the original field polynomial, read as a Rows x Cols matrix.
	Rows sumcheck.FieldPoly
	// NumRows and NumCols are the matrix dimensions, with NumRows*NumCols = len(Rows).
	NumRows, NumCols int
}

// CommitGroup commits a group multilinear: encode it over the domain, group the
// codeword into cosets of 2^k points, and Merkle-commit the cosets.
//
// This is the group polynomial commitment, and it is also tier 2 of the field
// commitment. k = 0 gives one codeword point per leaf; k > 0 is the coset-wise
// structure the O(n^(1/4)) variant needs, and is supported here only in the sense
// that the leaf format allows it -- the folding that exploits it is not yet
// implemented.
//
// The returned hint is prover state and must not be given to a verifier.
func CommitGroup(G sumcheck.GroupPoly, dom *Domain, k int) (*Commitment, *GroupOpeningHint, error) {
	if dom == nil {
		return nil, nil, errors.WithMessage(ErrNilDomain, "cannot commit a group polynomial")
	}

	codeword, err := EncodeGroupOracle(G, dom)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to encode the group oracle")
	}

	leaves, err := chunkIntoCosets(codeword, k)
	if err != nil {
		return nil, nil, err
	}

	tree, err := BuildTree(leaves)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to build the merkle tree over the codeword")
	}

	numVars, err := numVarsOf(len(G))
	if err != nil {
		return nil, nil, err
	}

	c := &Commitment{
		Root:      tree.Root(),
		NumVars:   numVars,
		LogDomain: dom.LogSize,
		K:         k,
		NumLeaves: len(leaves),
	}
	hint := &GroupOpeningHint{G: G, Codeword: codeword, Leaves: leaves, Tree: tree}

	return c, hint, nil
}

// CommitField commits a field multilinear through both tiers.
//
// Tier 1 reads f as a NumRows x NumCols matrix and Pedersen-commits each row
// against gens, giving one group element per row. Those elements *are* the
// evaluation table of the group multilinear G -- in the little-endian convention
// this package and sumcheck share, table entry j already holds the value at the
// bit decomposition of j, so there is no interpolation step to perform despite
// what the word "interpolate" in the protocol description suggests.
//
// Tier 2 is then CommitGroup on G.
//
// gens must hold at least NumCols generators; their provenance is the caller's
// responsibility, as no trusted setup is performed here.
func CommitField(f sumcheck.FieldPoly, gens []bls12381.G1Affine, dom *Domain, k int) (*Commitment, *FieldOpeningHint, error) {
	if f == nil {
		return nil, nil, errors.WithMessage(ErrNilPolynomial, "cannot commit a field polynomial")
	}
	if dom == nil {
		return nil, nil, errors.WithMessage(ErrNilDomain, "cannot commit a field polynomial")
	}
	m, err := numVarsOf(len(f))
	if err != nil {
		return nil, nil, err
	}

	numRows, numCols := matrixShape(m)
	if numRows*numCols != len(f) {
		return nil, nil, errors.Wrapf(ErrNumVarsMismatch, "matrix shape %dx%d does not cover %d coefficients", numRows, numCols, len(f))
	}
	if len(gens) < numCols {
		return nil, nil, errors.Wrapf(ErrInsufficientGenerators, "need %d generators for a row, got %d", numCols, len(gens))
	}

	// Tier 1: one MSM of length numCols per row. Row j spans a contiguous block,
	// so no transpose is needed.
	G := make(sumcheck.GroupPoly, numRows)
	for j := range numRows {
		v, err := msm(gens[:numCols], f[j*numCols:(j+1)*numCols])
		if err != nil {
			return nil, nil, errors.Wrapf(err, "failed to commit row %d", j)
		}
		G[j] = v
	}

	c, gh, err := CommitGroup(G, dom, k)
	if err != nil {
		return nil, nil, err
	}

	hint := &FieldOpeningHint{
		GroupOpeningHint: *gh,
		Rows:             f,
		NumRows:          numRows,
		NumCols:          numCols,
	}

	return c, hint, nil
}

// OpenLeaf returns the coset at the given leaf index together with its
// authentication path, which is how a verifier's query on the oracle is answered.
func (h *GroupOpeningHint) OpenLeaf(index int) ([]bls12381.G1Affine, *MerkleProof, error) {
	if h == nil || h.Tree == nil {
		return nil, nil, errors.WithMessage(ErrNilTree, "cannot open a leaf")
	}
	if index < 0 || index >= len(h.Leaves) {
		return nil, nil, errors.Wrapf(ErrLeafIndexOutOfRange, "index %d is outside [0, %d)", index, len(h.Leaves))
	}
	proof, err := h.Tree.Prove(index)
	if err != nil {
		return nil, nil, err
	}

	return h.Leaves[index], proof, nil
}

// chunkIntoCosets groups a codeword into contiguous blocks of 2^k points, one per
// Merkle leaf.
//
// Contiguous, not strided: a coset must be the block of codeword positions that a
// single folding step consumes together, and with the codeword laid out in the
// domain order EncodeGroupOracle produces, that block is contiguous. Striding here
// would still build a valid-looking tree over a reordering of the same points,
// which is exactly the kind of error no round-trip test can see.
func chunkIntoCosets(codeword []bls12381.G1Affine, k int) ([][]bls12381.G1Affine, error) {
	if k < 0 {
		return nil, errors.Wrapf(ErrInvalidCosetDim, "coset dimension %d is negative", k)
	}
	size := 1 << k
	if size > len(codeword) || len(codeword)%size != 0 {
		return nil, errors.Wrapf(ErrInvalidCosetDim, "cannot split %d codeword points into cosets of %d", len(codeword), size)
	}

	n := len(codeword) / size
	leaves := make([][]bls12381.G1Affine, n)
	for i := range n {
		leaves[i] = codeword[i*size : (i+1)*size]
	}

	return leaves, nil
}

// matrixShape returns the row and column counts for the matrix form of a
// multilinear in m variables.
//
// For even m this is the square 2^(m/2) x 2^(m/2) split. For odd m = 2s+1 a square
// split does not exist, so the extra variable goes to the *rows*: 2^(s+1) rows of
// 2^s columns. Putting it on the rows rather than the columns keeps the row MSMs
// shorter and gives the group multilinear one more variable, which is the cheaper
// side to grow -- group operations dominate. The choice is arbitrary but must be
// fixed, since prover and verifier have to agree on the shape.
func matrixShape(m int) (rows, cols int) {
	cols = 1 << (m / 2)
	rows = 1 << (m - m/2)

	return rows, cols
}

// numVarsOf returns log2 of a power-of-two evaluation table length.
func numVarsOf(length int) (int, error) {
	if !isPowerOfTwo(length) {
		return 0, errors.Wrapf(ErrNotPowerOfTwo, "evaluation table length %d is not a power of two", length)
	}
	m := 0
	for 1<<m < length {
		m++
	}

	return m, nil
}
