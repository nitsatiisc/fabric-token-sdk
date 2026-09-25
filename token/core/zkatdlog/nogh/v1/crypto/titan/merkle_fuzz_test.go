/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// FuzzVerifyMerkleProof drives the verifier with attacker-controlled proof bytes.
//
// Two properties, both soundness-relevant:
//
//   - It must never panic. VerifyMerkleProof consumes a proof supplied by whoever
//     produced it, so a panic on malformed input is a denial of service on any
//     verifier.
//   - It must never accept. The root here is built from known leaves, and the fuzzer
//     supplies the path; since it cannot find a SHA-256 collision, any acceptance
//     means the verifier is not actually checking the path -- for example ignoring
//     a length mismatch, or short-circuiting on an empty sibling list.
//
// Wired into .github/workflows/nightly-fuzz.yml so it runs under extended
// -fuzztime rather than only over its seed corpus.
func FuzzVerifyMerkleProof(f *testing.F) {
	_, _, g, _ := bls12381.Generators()

	// A fixed 8-leaf tree, so the root is a real one and the only variable is the
	// proof the fuzzer builds.
	leaves := make([][]bls12381.G1Affine, 8)
	for i := range leaves {
		var p bls12381.G1Affine
		p.ScalarMultiplication(&g, big.NewInt(int64(i+1)))
		leaves[i] = []bls12381.G1Affine{p}
	}
	tree, err := BuildTree(leaves)
	if err != nil {
		f.Fatalf("failed to build the seed tree: %v", err)
	}
	root := tree.Root()

	// Seed with a genuine proof flattened, plus degenerate shapes.
	good, err := tree.Prove(3)
	if err != nil {
		f.Fatalf("failed to build the seed proof: %v", err)
	}
	var flat []byte
	for _, s := range good.Siblings {
		flat = append(flat, s...)
	}
	f.Add(3, 8, flat)
	f.Add(0, 8, []byte{})
	f.Add(0, 1, []byte{})
	f.Add(-1, 8, flat)
	f.Add(3, 0, flat)
	f.Add(3, 7, flat)
	f.Add(1<<30, 1<<30, flat)
	f.Add(3, 8, append(flat, 0xff))

	f.Fuzz(func(t *testing.T, index, numLeaves int, raw []byte) {
		// Carve the raw bytes into digest-sized siblings; a trailing partial
		// chunk is kept deliberately, since a wrong-length digest is exactly the
		// kind of input the verifier must reject rather than mis-slice.
		var siblings [][]byte
		for off := 0; off < len(raw); off += DigestSize {
			end := off + DigestSize
			if end > len(raw) {
				end = len(raw)
			}
			siblings = append(siblings, raw[off:end])
		}

		proof := &MerkleProof{Index: index, Siblings: siblings, NumLeaves: numLeaves}

		// Must not panic.
		if VerifyMerkleProof(root, leaves[0], proof) {
			// Acceptance is only legitimate if this really is leaf 0's path.
			legit, err := tree.Prove(0)
			if err != nil {
				t.Fatalf("failed to rebuild the reference proof: %v", err)
			}
			if index != 0 || numLeaves != 8 || len(siblings) != len(legit.Siblings) {
				t.Fatalf("verifier accepted a proof of the wrong shape: index=%d numLeaves=%d siblings=%d",
					index, numLeaves, len(siblings))
			}
			for i := range legit.Siblings {
				if string(siblings[i]) != string(legit.Siblings[i]) {
					t.Fatalf("verifier accepted a forged sibling at level %d", i)
				}
			}
		}
	})
}
