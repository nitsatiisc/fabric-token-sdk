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
//	commitGroup(G)  = tier 2                 a group polynomial commitment
//	commitField(f)  = tier 1 then tier 2     a field polynomial commitment
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

	// Cosets is the commitment to the coset-wise oracle the folding phase
	// queries, or nil if the polynomial was committed without one.
	//
	// It is a second root rather than a reuse of Root because the two commit
	// genuinely different values: Root covers the flat codeword, whose entries
	// are full power-curve points, while Cosets covers the slice-wise oracle
	// whose leaves are { G(b, powers(y)) }. See EncodeCosets. A verifier that
	// checked fold openings against Root would reject every honest proof.
	//
	// A nil Cosets means Eval/EvalGroup can still reduce a claim but cannot
	// close it: without the coset oracle there is nothing for the consistency
	// queries to open. CommitGroupWithFold is the constructor that populates it.
	Cosets *CosetCommitment
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

	// Cosets is the prover state for the coset-wise oracle, or nil if the
	// polynomial was committed without one. See Commitment.Cosets.
	Cosets *CosetOpeningHint

	// Fold is the folding configuration the coset oracle was built for. It is
	// retained because Ell determines the coset shape, so prover and verifier
	// must agree on it, and the oracle cannot be reinterpreted at another Ell.
	Fold FoldConfig
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

// commitGroup encodes a group multilinear over the domain, groups the codeword into
// cosets of 2^k points, and Merkle-commits them.
//
// This is an internal STAGE, not a usable commitment on its own: it commits the flat
// codeword, which is enough to *reduce* an evaluation claim but not to close it.
// CommitGroupWithFold calls it and adds the coset oracle the consistency queries
// need. It is unexported for that reason -- a commitment produced here has a nil
// Cosets, and its openings do not bind (see CommitGroupWithFold, and section 13.3
// of docs/crypto/titan.md for which check closes the gap).
//
// k = 0 gives one codeword point per leaf, which is what every caller passes.
//
// k > 0 groups the flat codeword into contiguous blocks. That is a storage
// convention only -- see chunkIntoCosets -- and it is NOT the coset structure the
// folding phase queries: the folding commits to a separately built oracle, see
// CommitCosets and EncodeCosets.
//
// The returned hint is prover state and must not be given to a verifier.
func commitGroup(G sumcheck.GroupPoly, dom *Domain, k int) (*Commitment, *GroupOpeningHint, error) {
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

// CommitGroupWithFold commits a group multilinear together with the coset-wise
// oracle the folding phase queries, giving an opening that can be *closed* rather
// than only reduced.
//
// The commitGroup stage alone commits the flat codeword. That is enough to reduce an
// evaluation claim, but not to close it: the folding phase's consistency queries
// open cosets, and the cosets are a different object from the flat codeword (see
// EncodeCosets). This constructor builds both, so Eval and EvalGroup can produce a
// sound proof.
//
// cfg fixes the coset dimension Ell, and Ell is baked into the oracle's shape --
// the same polynomial committed at a different Ell is a different commitment. Pass
// DefaultFoldConfig(m) unless there is a reason not to.
//
// The two roots are kept separate rather than combined into one tree. Combining
// them would save a hash but would let a verifier that confused the two accept
// openings of the wrong oracle, and the failure would look like a soundness bug
// rather than a plumbing one.
func CommitGroupWithFold(G sumcheck.GroupPoly, dom *Domain, k int, cfg FoldConfig) (*Commitment, *GroupOpeningHint, error) {
	m, err := numVarsOf(len(G))
	if err != nil {
		return nil, nil, err
	}
	if err := cfg.Validate(m); err != nil {
		return nil, nil, err
	}

	c, hint, err := commitGroup(G, dom, k)
	if err != nil {
		return nil, nil, err
	}

	cosetCom, cosetHint, err := CommitCosets(G, dom, cfg.Ell)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to commit the coset oracle")
	}

	cosetCom.Fold = cfg
	c.Cosets = cosetCom
	hint.Cosets = cosetHint
	hint.Fold = cfg

	return c, hint, nil
}

// commitField commits a field multilinear through both tiers.
//
// Like commitGroup this is an internal STAGE whose result does not bind on its own;
// CommitFieldWithFold calls it and adds the coset oracle. Unexported for the same
// reason.
//
// Tier 1 reads f as a NumRows x NumCols matrix and Pedersen-commits each row
// against gens, giving one group element per row. Those elements *are* the
// evaluation table of the group multilinear G -- in the little-endian convention
// this package and sumcheck share, table entry j already holds the value at the
// bit decomposition of j, so there is no interpolation step to perform despite
// what the word "interpolate" in the protocol description suggests.
//
// Tier 2 is then commitGroup on G.
//
// gens must hold at least NumCols generators; their provenance is the caller's
// responsibility, as no trusted setup is performed here.
func commitField(f sumcheck.FieldPoly, gens []bls12381.G1Affine, dom *Domain, k int) (*Commitment, *FieldOpeningHint, error) {
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

	c, gh, err := commitGroup(G, dom, k)
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

// CommitFieldWithFold is CommitField with the coset oracle of tier 2's group
// polynomial, so the resulting commitment can be opened soundly.
//
// The coset oracle is built over G -- the tier-1 row commitments -- not over f,
// because the folding phase operates on the group polynomial. See
// CommitGroupWithFold, and note that cfg's Ell is relative to G's variable count
// (log2 of the row count), not f's.
func CommitFieldWithFold(f sumcheck.FieldPoly, gens []bls12381.G1Affine, dom *Domain, k int, cfg FoldConfig) (*Commitment, *FieldOpeningHint, error) {
	c, hint, err := commitField(f, gens, dom, k)
	if err != nil {
		return nil, nil, err
	}

	if err := cfg.Validate(hint.GroupOpeningHint.numVars()); err != nil {
		return nil, nil, err
	}

	cosetCom, cosetHint, err := CommitCosets(hint.G, dom, cfg.Ell)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to commit the coset oracle")
	}

	cosetCom.Fold = cfg
	c.Cosets = cosetCom
	hint.Cosets = cosetHint
	hint.Fold = cfg

	return c, hint, nil
}

// numVars is the number of variables of the committed group polynomial.
func (h *GroupOpeningHint) numVars() int {
	n, err := numVarsOf(len(h.G))
	if err != nil {
		return 0
	}

	return n
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

// chunkIntoCosets groups a flat codeword into contiguous blocks of 2^k points,
// one per Merkle leaf.
//
// Contiguity here is a storage convention, nothing more. An earlier version of
// this comment claimed contiguous blocks were the set a folding step consumes
// together; that is FALSE, and it is worth recording because the claim looked
// plausible. For the flat codeword EncodeGroupOracle produces, the 2^k points a
// k-round fold depends on are the roots of x^(2^k) = y, which sit at the STRIDED
// positions {y, y + N/2^k, ...}: taking a 2^k-th root divides the exponent, so
// the set is closed under multiplication by w^(N/2^k) rather than by w. At d=4,
// k=2 the coset of w^1 is {1, 5, 9, 13}, while the contiguous block {4,5,6,7}
// contains just one of its members. (Contiguous WOULD be right for bit-reversed
// storage, which is the usual WHIR convention; encode.go deliberately returns
// natural order.)
//
// Nothing is broken by that, because this function is only used for k = 0, where
// every grouping coincides and each leaf is a single codeword point. The folding
// phase does not regroup this array at all -- it commits to a different oracle
// built slice-wise by EncodeCosets, whose leaves hold G(b, powers(y)) rather than
// power-curve points. See EncodeCosets for why the two are not reorderings of
// each other.
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
