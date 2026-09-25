/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	"bytes"
	"crypto/sha256"

	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"
)

// Merkle commitment over group-element leaves
//
// The Titan oracle [[G]] is the Merkle root of the Reed-Solomon codeword of a
// group multilinear: EncodeGroupOracle produces |L| group elements, those are
// grouped into cosets, and each coset is one leaf. The root is the commitment; a
// query is answered by the coset plus its authentication path.
//
// Why this is not gnark-crypto's accumulator/merkletree
//
// Two independent reasons, both checked against v0.20.1 rather than assumed.
//
// First, it is a *streaming* tree (from NebulousLabs/Sia) that does not retain
// leaves: Push keeps "only the log(n) elements necessary to build the Merkle root
// and ... a proof that a piece of data is in the tree". SetIndex must therefore
// name, in advance, the single leaf a proof will later be wanted for, and must be
// called on an empty tree, because after any Push the data for every other index
// is already discarded. So t openings would mean t full rebuilds: n*t leaf hashes
// instead of n. At |L| = 2^16 with 100 queries that is ~6.5M leaf hashes against
// ~65k, each leaf a serialized G1 point. WHIR opens many positions of a small
// tree, which is the opposite trade from the one that library is built for.
//
// Second, its hash format has no leaf/node domain separation. leafSum and nodeSum
// (tree.go:92-106) have the RFC 6962 prefixes commented out and return plain
// sum(h, data) and sum(h, a, b); no leafHashPrefix or nodeHashPrefix is declared
// anywhere in the package. Without separation a leaf hash and an internal node
// hash are drawn from the same space, so the root of a two-leaf tree collides with
// that of a one-leaf tree whose leaf is the concatenation of the two children.
// TestSecondPreimageSeparation pins that this implementation does not share that
// property.
//
// Hence both the builder and the verifier are ours. The tree here retains every
// level, so any number of openings are slice reads, and the prefixes are actually
// applied.
//
// Leaves are cosets from the start
//
// A leaf holds 2^k group elements, not one. The O(n^(1/4)) variant of Titan needs
// coset-wise leaves (the Rust reference's Merkle config is Leaf = Vec<G>), and the
// leaf *shape* determines every root and every proof in the scheme. Fixing it now
// at k = 0 (one point per leaf) costs nothing and means enabling k > 0 later does
// not invalidate the format. See CommitGroup for the k parameter.

// Domain separation prefixes, as in RFC 6962. Without these a leaf hash and an
// internal node hash would be drawn from the same space; see the note above.
var (
	leafHashPrefix = []byte{0x00}
	nodeHashPrefix = []byte{0x01}
)

// DigestSize is the length in bytes of a Merkle node digest (SHA-256).
const DigestSize = sha256.Size

// Tree is an in-memory Merkle tree over cosets of group elements.
//
// Every level is retained, so producing an opening is a walk over stored digests
// rather than a rebuild. levels[0] holds the leaf hashes and the last level holds
// the single root digest.
type Tree struct {
	// levels[i] holds the digests at height i; levels[0] are the leaf hashes.
	levels [][][]byte
	// cosetSize is the number of group elements in each leaf.
	cosetSize int
}

// MerkleProof is an authentication path for a single leaf: one sibling digest per
// level, ordered from the leaf upwards.
type MerkleProof struct {
	// Index is the position of the opened leaf among the tree's leaves.
	Index int
	// Siblings holds one sibling digest per level, leaf level first.
	Siblings [][]byte
	// NumLeaves is the leaf count of the tree this proof was produced from.
	NumLeaves int
}

// BatchProof is a set of openings at distinct leaf indices.
//
// The first cut carries one independent path per index. It is a struct rather than
// a []*MerkleProof so that path compression -- deduplicating the upper nodes that
// sibling paths share, which the reference implementation does -- can be added
// without changing any call site.
type BatchProof struct {
	// Proofs holds one path per requested index, in the order requested.
	Proofs []*MerkleProof
}

// BuildTree builds a Merkle tree over the given leaves, each of which is a coset
// of group elements.
//
// The number of leaves must be a power of two. Titan always satisfies this (the
// leaf count is |L| / 2^k, both powers of two), so a ragged count signals a caller
// error; padding it silently would change what the root commits to.
func BuildTree(leaves [][]bls12381.G1Affine) (*Tree, error) {
	if len(leaves) == 0 {
		return nil, errors.WithMessage(ErrEmptyLeaves, "cannot build a merkle tree")
	}
	if !isPowerOfTwo(len(leaves)) {
		return nil, errors.Wrapf(ErrNotPowerOfTwo, "leaf count %d is not a power of two", len(leaves))
	}

	cosetSize := len(leaves[0])
	if cosetSize == 0 {
		return nil, errors.WithMessage(ErrEmptyLeaves, "leaves cannot be empty cosets")
	}
	for i, leaf := range leaves {
		if len(leaf) != cosetSize {
			return nil, errors.Wrapf(ErrRaggedLeaves, "leaf %d holds %d points, leaf 0 holds %d", i, len(leaf), cosetSize)
		}
	}

	level := make([][]byte, len(leaves))
	for i, leaf := range leaves {
		level[i] = hashLeaf(leaf)
	}

	t := &Tree{levels: [][][]byte{level}, cosetSize: cosetSize}
	for len(level) > 1 {
		next := make([][]byte, len(level)/2)
		for i := range next {
			next[i] = hashNode(level[2*i], level[2*i+1])
		}
		t.levels = append(t.levels, next)
		level = next
	}

	return t, nil
}

// Root returns the Merkle root, which is the commitment to the leaves. The
// returned slice is a copy, so a caller cannot mutate the tree through it.
func (t *Tree) Root() []byte {
	if t == nil || len(t.levels) == 0 {
		return nil
	}
	top := t.levels[len(t.levels)-1]

	return bytes.Clone(top[0])
}

// NumLeaves returns the number of leaves in the tree.
func (t *Tree) NumLeaves() int {
	if t == nil || len(t.levels) == 0 {
		return 0
	}

	return len(t.levels[0])
}

// Depth returns the number of levels above the leaves, so a proof carries exactly
// Depth() sibling digests.
func (t *Tree) Depth() int {
	if t == nil || len(t.levels) == 0 {
		return 0
	}

	return len(t.levels) - 1
}

// Prove returns the authentication path for the leaf at the given index.
//
// Because every level is retained this is a walk over stored digests; no hashing
// and no rebuild is needed, which is what makes many openings of one tree cheap.
func (t *Tree) Prove(index int) (*MerkleProof, error) {
	if t == nil || len(t.levels) == 0 {
		return nil, errors.WithMessage(ErrNilTree, "cannot open a leaf")
	}
	n := len(t.levels[0])
	if index < 0 || index >= n {
		return nil, errors.Wrapf(ErrLeafIndexOutOfRange, "index %d is outside [0, %d)", index, n)
	}

	siblings := make([][]byte, 0, t.Depth())
	idx := index
	for h := 0; h < t.Depth(); h++ {
		siblings = append(siblings, bytes.Clone(t.levels[h][idx^1]))
		idx >>= 1
	}

	return &MerkleProof{Index: index, Siblings: siblings, NumLeaves: n}, nil
}

// ProveBatch returns one authentication path per requested index.
func (t *Tree) ProveBatch(indices []int) (*BatchProof, error) {
	if t == nil || len(t.levels) == 0 {
		return nil, errors.WithMessage(ErrNilTree, "cannot open leaves")
	}
	proofs := make([]*MerkleProof, len(indices))
	for i, idx := range indices {
		p, err := t.Prove(idx)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to open leaf %d of %d", i, len(indices))
		}
		proofs[i] = p
	}

	return &BatchProof{Proofs: proofs}, nil
}

// VerifyMerkleProof reports whether leaf sits at proof.Index in the tree with the
// given root.
//
// It returns a bool rather than an error because every failure is the same
// verdict -- this proof does not open this root -- and distinguishing malformed
// input from a mismatch would hand an adversary a distinguisher. It must never
// panic on attacker-supplied input; FuzzVerifyMerkleProof pins that.
func VerifyMerkleProof(root []byte, leaf []bls12381.G1Affine, proof *MerkleProof) bool {
	if len(root) != DigestSize || proof == nil || len(leaf) == 0 {
		return false
	}
	if proof.NumLeaves <= 0 || !isPowerOfTwo(proof.NumLeaves) {
		return false
	}
	if proof.Index < 0 || proof.Index >= proof.NumLeaves {
		return false
	}
	// The path must have exactly one sibling per level, no more and no fewer:
	// a short path would leave the walk below the root, and a long one would let
	// a prover keep hashing past it.
	if len(proof.Siblings) != treeDepth(proof.NumLeaves) {
		return false
	}

	acc := hashLeaf(leaf)
	idx := proof.Index
	for _, sib := range proof.Siblings {
		if len(sib) != DigestSize {
			return false
		}
		if idx&1 == 0 {
			acc = hashNode(acc, sib)
		} else {
			acc = hashNode(sib, acc)
		}
		idx >>= 1
	}

	return bytes.Equal(acc, root)
}

// hashLeaf hashes one coset of group elements into a leaf digest, over the
// compressed encoding of each point.
//
// Compressed (48 bytes) rather than uncompressed (96) halves the hashed volume,
// and leaves dominate the hashing. The encoding is part of the commitment, so
// TestLeafHashKnownAnswer pins it. The point at infinity encodes distinctly
// (0xc0 followed by zeros), so it does not collide with any finite point.
func hashLeaf(points []bls12381.G1Affine) []byte {
	h := sha256.New()
	h.Write(leafHashPrefix)
	for i := range points {
		b := points[i].Bytes()
		h.Write(b[:])
	}

	return h.Sum(nil)
}

// hashNode hashes two child digests into their parent.
func hashNode(left, right []byte) []byte {
	h := sha256.New()
	h.Write(nodeHashPrefix)
	h.Write(left)
	h.Write(right)

	return h.Sum(nil)
}

// treeDepth returns the number of levels above the leaves for a power-of-two leaf
// count, so that 1 leaf has depth 0 and 2^d leaves have depth d.
func treeDepth(numLeaves int) int {
	d := 0
	for 1<<d < numLeaves {
		d++
	}

	return d
}
