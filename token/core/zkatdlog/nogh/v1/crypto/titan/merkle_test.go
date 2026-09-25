/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// randomLeaves returns numLeaves cosets of 2^k random points, deterministically
// derived from the index so a failure is reproducible.
func randomLeaves(t *testing.T, numLeaves, k int) [][]bls12381.G1Affine {
	t.Helper()
	_, _, g, _ := bls12381.Generators()
	size := 1 << k
	out := make([][]bls12381.G1Affine, numLeaves)
	for i := range out {
		out[i] = make([]bls12381.G1Affine, size)
		for j := range out[i] {
			// Deterministic, distinct, and non-trivial scalars, so a failure
			// reproduces exactly.
			s := big.NewInt(int64(7*(i*size+j) + 3))
			out[i][j].ScalarMultiplication(&g, s)
		}
	}

	return out
}

// naiveRoot recomputes a Merkle root straight from the definition, recursively,
// with no shared code with BuildTree beyond the two hash helpers. An independent
// implementation is the point: it catches level-ordering and child-ordering errors
// that a round-trip against BuildTree itself cannot see.
func naiveRoot(leaves [][]bls12381.G1Affine) []byte {
	if len(leaves) == 1 {
		return hashLeaf(leaves[0])
	}
	half := len(leaves) / 2

	return hashNode(naiveRoot(leaves[:half]), naiveRoot(leaves[half:]))
}

func TestBuildTreeRoundTripAllIndices(t *testing.T) {
	for logN := 0; logN <= 10; logN++ {
		for _, k := range []int{0, 1, 2} {
			numLeaves := 1 << logN
			leaves := randomLeaves(t, numLeaves, k)
			tree, err := BuildTree(leaves)
			require.NoError(t, err)
			require.Equal(t, numLeaves, tree.NumLeaves())
			require.Equal(t, logN, tree.Depth())

			root := tree.Root()
			for i := range numLeaves {
				proof, err := tree.Prove(i)
				require.NoError(t, err, "logN=%d k=%d i=%d", logN, k, i)
				require.Len(t, proof.Siblings, logN)
				assert.True(t, VerifyMerkleProof(root, leaves[i], proof),
					"logN=%d k=%d i=%d should verify", logN, k, i)
			}
		}
	}
}

func TestBuildTreeMatchesNaiveRoot(t *testing.T) {
	for logN := 0; logN <= 8; logN++ {
		for _, k := range []int{0, 1, 3} {
			leaves := randomLeaves(t, 1<<logN, k)
			tree, err := BuildTree(leaves)
			require.NoError(t, err)
			assert.Equal(t, naiveRoot(leaves), tree.Root(),
				"logN=%d k=%d: BuildTree disagrees with the naive definition", logN, k)
		}
	}
}

// TestSecondPreimageSeparation is the test that justifies not adopting
// gnark-crypto's hash format. Its leafSum/nodeSum have the RFC 6962 prefixes
// commented out, so a leaf hash and a node hash are drawn from the same space and
// this equality would hold. Here it must not.
func TestSecondPreimageSeparation(t *testing.T) {
	leaves := randomLeaves(t, 2, 0)
	two, err := BuildTree(leaves)
	require.NoError(t, err)

	// The root of the two-leaf tree is hashNode(H(l0), H(l1)). Without domain
	// separation that is indistinguishable from a leaf hash over the same bytes.
	l0 := hashLeaf(leaves[0])
	l1 := hashLeaf(leaves[1])

	withPrefix := sha256.Sum256(append(append(append([]byte{}, nodeHashPrefix...), l0...), l1...))
	require.Equal(t, withPrefix[:], two.Root(), "root should be the prefixed node hash")

	noPrefix := sha256.Sum256(append(append([]byte{}, l0...), l1...))
	assert.NotEqual(t, noPrefix[:], two.Root(),
		"root must not equal the unprefixed concatenation hash; domain separation is missing")

	// And a leaf hash must never coincide with a node hash over the same payload.
	assert.NotEqual(t, hashNode(l0, l1), hashLeafRaw(append(append([]byte{}, l0...), l1...)),
		"leaf and node hashes must be domain separated")
}

// hashLeafRaw applies the leaf prefix to arbitrary bytes, so the test can compare
// the two hash domains directly over one payload.
func hashLeafRaw(b []byte) []byte {
	h := sha256.New()
	h.Write(leafHashPrefix)
	h.Write(b)

	return h.Sum(nil)
}

// TestLeafHashKnownAnswer pins the exact serialization: the leaf prefix, the
// 48-byte compressed point encoding, and the order of points within a coset. A
// change to any of these changes every commitment, so it must not happen silently.
func TestLeafHashKnownAnswer(t *testing.T) {
	_, _, g, _ := bls12381.Generators()
	b := g.Bytes()
	require.Len(t, b, 48, "compressed G1 encoding must be 48 bytes")

	got := hex.EncodeToString(hashLeaf([]bls12381.G1Affine{g}))
	want := hex.EncodeToString(hashLeafRaw(b[:]))
	assert.Equal(t, want, got)

	// The point at infinity must encode distinctly, or it could be substituted.
	var inf bls12381.G1Affine
	ib := inf.Bytes()
	assert.NotEqual(t, b, ib, "infinity must not encode as the generator")
	assert.Equal(t, byte(0xc0), ib[0], "infinity encoding is the compressed-infinity flag")
}

func TestVerifyRejectsWrongLeaf(t *testing.T) {
	leaves := randomLeaves(t, 8, 1)
	tree, err := BuildTree(leaves)
	require.NoError(t, err)
	root := tree.Root()

	proof, err := tree.Prove(3)
	require.NoError(t, err)

	assert.True(t, VerifyMerkleProof(root, leaves[3], proof))
	assert.False(t, VerifyMerkleProof(root, leaves[4], proof), "a different leaf must not verify")
}

func TestVerifyRejectsWrongIndex(t *testing.T) {
	leaves := randomLeaves(t, 8, 0)
	tree, err := BuildTree(leaves)
	require.NoError(t, err)
	root := tree.Root()

	proof, err := tree.Prove(3)
	require.NoError(t, err)
	proof.Index = 2
	assert.False(t, VerifyMerkleProof(root, leaves[3], proof), "a relabelled index must not verify")
}

func TestVerifyRejectsTamperedSibling(t *testing.T) {
	leaves := randomLeaves(t, 16, 0)
	tree, err := BuildTree(leaves)
	require.NoError(t, err)
	root := tree.Root()

	for level := range tree.Depth() {
		proof, err := tree.Prove(5)
		require.NoError(t, err)
		proof.Siblings[level][0] ^= 0xff
		assert.False(t, VerifyMerkleProof(root, leaves[5], proof),
			"tampering at level %d must be caught", level)
	}
}

// TestVerifyRejectsSwappedSiblingOrder catches left/right inversion, which a
// round-trip test cannot see because prover and verifier would invert together.
func TestVerifyRejectsSwappedSiblingOrder(t *testing.T) {
	leaves := randomLeaves(t, 8, 0)
	tree, err := BuildTree(leaves)
	require.NoError(t, err)
	root := tree.Root()

	// Leaf 0 is a left child at every level, leaf 7 a right child at every level.
	// Presenting 0's path as if it were at index 7 inverts every combination.
	proof, err := tree.Prove(0)
	require.NoError(t, err)
	proof.Index = 7
	assert.False(t, VerifyMerkleProof(root, leaves[0], proof))
}

func TestVerifyRejectsWrongProofLength(t *testing.T) {
	leaves := randomLeaves(t, 8, 0)
	tree, err := BuildTree(leaves)
	require.NoError(t, err)
	root := tree.Root()

	short, err := tree.Prove(1)
	require.NoError(t, err)
	short.Siblings = short.Siblings[:len(short.Siblings)-1]
	assert.False(t, VerifyMerkleProof(root, leaves[1], short), "a short path must not verify")

	long, err := tree.Prove(1)
	require.NoError(t, err)
	long.Siblings = append(long.Siblings, make([]byte, DigestSize))
	assert.False(t, VerifyMerkleProof(root, leaves[1], long), "an over-long path must not verify")
}

// TestVerifyRejectsEmptyPathAgainstDeepTree is the case the proof-length check
// exists for, and it is a genuine forgery rather than a hygiene check.
//
// A one-leaf tree has depth 0, so its root IS its leaf hash. A prover can take
// such a leaf and claim it sits at index 0 of a tree with many leaves, supplying
// an empty path: the accumulator never leaves the leaf hash, so it equals the
// root. Only comparing the path length against treeDepth(NumLeaves) rejects it.
//
// Found by mutation testing -- removing the length check left the rest of the
// suite green, because the short and over-long paths in
// TestVerifyRejectsWrongProofLength are both caught incidentally by the digest
// comparison. This one is not.
func TestVerifyRejectsEmptyPathAgainstDeepTree(t *testing.T) {
	leaves := randomLeaves(t, 1, 0)
	tree, err := BuildTree(leaves)
	require.NoError(t, err)
	root := tree.Root()

	require.Equal(t, 0, tree.Depth())
	require.Equal(t, hashLeaf(leaves[0]), root, "a one-leaf root is its leaf hash")

	// The honest opening of the one-leaf tree.
	honest, err := tree.Prove(0)
	require.NoError(t, err)
	assert.True(t, VerifyMerkleProof(root, leaves[0], honest))

	// The same leaf, claimed to sit in a deeper tree with no path at all.
	for _, claimed := range []int{2, 4, 8, 1024} {
		forged := &MerkleProof{Index: 0, Siblings: nil, NumLeaves: claimed}
		assert.False(t, VerifyMerkleProof(root, leaves[0], forged),
			"an empty path must not open a tree claimed to hold %d leaves", claimed)
	}
}

// TestVerifyRejectsTruncatedPathAtEveryLength complements the above: for a real
// tree, every proper prefix and every extension of the honest path must fail.
func TestVerifyRejectsTruncatedPathAtEveryLength(t *testing.T) {
	leaves := randomLeaves(t, 16, 0)
	tree, err := BuildTree(leaves)
	require.NoError(t, err)
	root := tree.Root()

	honest, err := tree.Prove(9)
	require.NoError(t, err)

	for n := 0; n < len(honest.Siblings); n++ {
		truncated := &MerkleProof{Index: 9, Siblings: honest.Siblings[:n], NumLeaves: 16}
		assert.False(t, VerifyMerkleProof(root, leaves[9], truncated),
			"a path of %d siblings must not open a depth-%d tree", n, tree.Depth())
	}
	for extra := 1; extra <= 3; extra++ {
		long := append([][]byte{}, honest.Siblings...)
		for range extra {
			long = append(long, make([]byte, DigestSize))
		}
		extended := &MerkleProof{Index: 9, Siblings: long, NumLeaves: 16}
		assert.False(t, VerifyMerkleProof(root, leaves[9], extended),
			"a path with %d extra siblings must not verify", extra)
	}
}

func TestVerifyRejectsMalformedInput(t *testing.T) {
	leaves := randomLeaves(t, 4, 0)
	tree, err := BuildTree(leaves)
	require.NoError(t, err)
	root := tree.Root()
	good, err := tree.Prove(1)
	require.NoError(t, err)

	assert.False(t, VerifyMerkleProof(nil, leaves[1], good), "nil root")
	assert.False(t, VerifyMerkleProof(root[:10], leaves[1], good), "short root")
	assert.False(t, VerifyMerkleProof(root, leaves[1], nil), "nil proof")
	assert.False(t, VerifyMerkleProof(root, nil, good), "nil leaf")
	assert.False(t, VerifyMerkleProof(root, []bls12381.G1Affine{}, good), "empty leaf")

	bad, err := tree.Prove(1)
	require.NoError(t, err)
	bad.NumLeaves = 3 // not a power of two
	assert.False(t, VerifyMerkleProof(root, leaves[1], bad))

	bad2, err := tree.Prove(1)
	require.NoError(t, err)
	bad2.NumLeaves = 0
	assert.False(t, VerifyMerkleProof(root, leaves[1], bad2))

	bad3, err := tree.Prove(1)
	require.NoError(t, err)
	bad3.Index = -1
	assert.False(t, VerifyMerkleProof(root, leaves[1], bad3))

	bad4, err := tree.Prove(1)
	require.NoError(t, err)
	bad4.Siblings[0] = bad4.Siblings[0][:5] // wrong digest length
	assert.False(t, VerifyMerkleProof(root, leaves[1], bad4))
}

// TestHashNodeHasNoLengthFraming documents a property of hashNode that is worth
// knowing even though it is not currently exploitable.
//
// hashNode writes prefix || left || right with no length framing, so the
// concatenation is ambiguous: splitting the same 64 bytes as 20+44 hashes
// identically to the honest 32+32.
//
// This is NOT reachable through VerifyMerkleProof. The accumulator there is always
// a 32-byte hash output, so only the sibling side of each concatenation is
// attacker-controlled and its length is the only free parameter; changing it
// changes the concatenation, which would need a SHA-256 collision to still reach
// the root. A brute-force sweep over sibling lengths 0..40 at every level of
// 2-, 4- and 8-leaf trees accepts nothing, with or without the explicit length
// check -- so that check is defence-in-depth, not load-bearing.
//
// It is pinned here because the property becomes load-bearing the moment anything
// feeds hashNode a variable-length input: batch-proof compression, or a coset
// digest fed in as a node. A future change of that kind must add length framing.
func TestHashNodeHasNoLengthFraming(t *testing.T) {
	a := make([]byte, DigestSize)
	b := make([]byte, DigestSize)
	for i := range a {
		a[i] = byte(i)
		b[i] = byte(100 + i)
	}
	cat := append(append([]byte{}, a...), b...)
	assert.Equal(t, hashNode(a, b), hashNode(cat[:20], cat[20:]),
		"hashNode is unframed, so these concatenations collide by construction")

	// The verifier must nonetheless reject every mis-sized sibling, at every
	// level, because it checks the length explicitly.
	leaves := randomLeaves(t, 8, 0)
	tree, err := BuildTree(leaves)
	require.NoError(t, err)
	root := tree.Root()
	honest, err := tree.Prove(0)
	require.NoError(t, err)
	require.True(t, VerifyMerkleProof(root, leaves[0], honest))

	for level := range tree.Depth() {
		for _, l := range []int{0, 1, 20, 31, 33, 40, 64} {
			sibs := make([][]byte, len(honest.Siblings))
			copy(sibs, honest.Siblings)
			bad := make([]byte, l)
			copy(bad, honest.Siblings[level])
			sibs[level] = bad
			forged := &MerkleProof{Index: 0, Siblings: sibs, NumLeaves: 8}
			assert.False(t, VerifyMerkleProof(root, leaves[0], forged),
				"level %d with a %d-byte sibling must not verify", level, l)
		}
	}
}

func TestBuildTreeValidation(t *testing.T) {
	_, err := BuildTree(nil)
	assert.ErrorIs(t, err, ErrEmptyLeaves)

	_, err = BuildTree([][]bls12381.G1Affine{})
	assert.ErrorIs(t, err, ErrEmptyLeaves)

	three := randomLeaves(t, 4, 0)[:3]
	_, err = BuildTree(three)
	assert.ErrorIs(t, err, ErrNotPowerOfTwo, "leaf count must be a power of two, not padded")

	ragged := randomLeaves(t, 2, 1)
	ragged[1] = ragged[1][:1]
	_, err = BuildTree(ragged)
	assert.ErrorIs(t, err, ErrRaggedLeaves)

	empty := [][]bls12381.G1Affine{{}, {}}
	_, err = BuildTree(empty)
	assert.ErrorIs(t, err, ErrEmptyLeaves)
}

func TestProveValidation(t *testing.T) {
	leaves := randomLeaves(t, 4, 0)
	tree, err := BuildTree(leaves)
	require.NoError(t, err)

	_, err = tree.Prove(-1)
	assert.ErrorIs(t, err, ErrLeafIndexOutOfRange)
	_, err = tree.Prove(4)
	assert.ErrorIs(t, err, ErrLeafIndexOutOfRange)

	var nilTree *Tree
	_, err = nilTree.Prove(0)
	assert.ErrorIs(t, err, ErrNilTree)
	assert.Nil(t, nilTree.Root())
	assert.Zero(t, nilTree.NumLeaves())
	assert.Zero(t, nilTree.Depth())

	_, err = nilTree.ProveBatch([]int{0})
	assert.ErrorIs(t, err, ErrNilTree)
}

func TestProveBatch(t *testing.T) {
	leaves := randomLeaves(t, 16, 2)
	tree, err := BuildTree(leaves)
	require.NoError(t, err)
	root := tree.Root()

	indices := []int{0, 5, 15, 5}
	batch, err := tree.ProveBatch(indices)
	require.NoError(t, err)
	require.Len(t, batch.Proofs, len(indices))
	for i, idx := range indices {
		assert.True(t, VerifyMerkleProof(root, leaves[idx], batch.Proofs[i]),
			"batch proof %d (leaf %d) should verify", i, idx)
	}

	_, err = tree.ProveBatch([]int{0, 99})
	assert.ErrorIs(t, err, ErrLeafIndexOutOfRange)
}

func TestRootIsACopy(t *testing.T) {
	leaves := randomLeaves(t, 4, 0)
	tree, err := BuildTree(leaves)
	require.NoError(t, err)

	r1 := tree.Root()
	r1[0] ^= 0xff
	r2 := tree.Root()
	assert.NotEqual(t, r1, r2, "mutating a returned root must not affect the tree")
}

func TestBuildTreeIsDeterministic(t *testing.T) {
	leaves := randomLeaves(t, 8, 1)
	a, err := BuildTree(leaves)
	require.NoError(t, err)
	b, err := BuildTree(leaves)
	require.NoError(t, err)
	assert.Equal(t, a.Root(), b.Root())
}

func TestDistinctLeavesGiveDistinctRoots(t *testing.T) {
	leaves := randomLeaves(t, 8, 0)
	a, err := BuildTree(leaves)
	require.NoError(t, err)

	_, _, g, _ := bls12381.Generators()
	modified := make([][]bls12381.G1Affine, len(leaves))
	copy(modified, leaves)
	modified[3] = []bls12381.G1Affine{g}
	b, err := BuildTree(modified)
	require.NoError(t, err)

	assert.NotEqual(t, a.Root(), b.Root())
}

func TestTreeDepth(t *testing.T) {
	for logN := range 12 {
		assert.Equal(t, logN, treeDepth(1<<logN), "treeDepth(2^%d)", logN)
	}
}
