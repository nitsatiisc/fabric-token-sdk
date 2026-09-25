/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	"encoding/binary"

	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/rp/csp"
)

// sampleQueryIndices draws q distinct indices in [0, n) from the transcript.
//
// The indices must be unpredictable to the prover before it has committed to the
// folding rounds, which is what makes the consistency queries bind: a prover who
// knew them could fold honestly at those positions and arbitrarily elsewhere. They
// are therefore squeezed from the same transcript the folding rounds were absorbed
// into, after the last of them.
//
// # Distinctness
//
// Duplicates are rejected and redrawn rather than accepted. q duplicate-free
// queries are what the soundness count assumes; accepting a repeat would silently
// lower the security level, since the second copy tests nothing new. MerkleProof's
// documentation calls for distinct indices too, and ProveBatch does not enforce it.
//
// # Why bytes are taken from the squeezed scalar rather than its residue
//
// Each squeeze gives a field element; the low 8 bytes are read as a uint64 and
// reduced mod n. n is a power of two here (it is a domain size), so the reduction
// is a mask and introduces no modulo bias. The function nevertheless rejects a
// non-power-of-two n rather than silently biasing, because a future caller with an
// arbitrary n would otherwise get a subtly skewed sample.
//
// Drawing q distinct values from n slots needs more than q squeezes when collisions
// occur; the loop is bounded so a pathological transcript cannot hang it.
func sampleQueryIndices(tr *csp.Transcript, n, q int) ([]int, error) {
	if tr == nil {
		return nil, errors.New("cannot sample query indices without a transcript")
	}
	if n <= 0 {
		return nil, errors.Wrapf(ErrInvalidFoldConfig, "domain size must be positive, got %d", n)
	}
	if !isPowerOfTwo(n) {
		return nil, errors.Wrapf(ErrInvalidFoldConfig, "domain size must be a power of two, got %d", n)
	}
	if q <= 0 {
		return nil, errors.Wrapf(ErrInvalidFoldConfig, "query count must be positive, got %d", q)
	}
	if q > n {
		return nil, errors.Wrapf(ErrInvalidFoldConfig, "cannot draw %d distinct indices from %d", q, n)
	}

	mask := uint64(n - 1)
	seen := make(map[int]struct{}, q)
	out := make([]int, 0, q)

	// Each squeeze yields one candidate. The bound is generous: drawing q <= n
	// distinct values needs about n*ln(n/(n-q)) draws in expectation, and 64*q + 64
	// exceeds that by a wide margin for every (n, q) this package uses.
	maxDraws := 64*q + 64
	for draws := 0; len(out) < q; draws++ {
		if draws >= maxDraws {
			return nil, errors.Wrapf(ErrInvalidFoldConfig,
				"could not draw %d distinct indices from %d in %d attempts", q, n, maxDraws)
		}

		z, err := tr.Squeeze()
		if err != nil {
			return nil, errors.Wrap(err, "failed to squeeze a query index")
		}

		b := z.Bytes()
		// Zr.Bytes is big-endian and fixed width; take the low 8 bytes.
		var buf [8]byte
		if len(b) >= 8 {
			copy(buf[:], b[len(b)-8:])
		} else {
			copy(buf[8-len(b):], b)
		}

		idx := int(binary.BigEndian.Uint64(buf[:]) & mask)
		if _, dup := seen[idx]; dup {
			continue
		}
		seen[idx] = struct{}{}
		out = append(out, idx)
	}

	return out, nil
}
