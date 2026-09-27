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

// sampleQueryIndices draws q independent indices in [0, n) from the transcript
// and returns the distinct ones, in order of first appearance.
//
// The indices must be unpredictable to the prover before it has committed to the
// folding rounds, which is what makes the consistency queries bind: a prover who
// knew them could fold honestly at those positions and arbitrarily elsewhere. They
// are therefore squeezed from the same transcript the folding rounds were absorbed
// into, after the last of them.
//
// # Independent draws, duplicates opened once
//
// The soundness bound is for q INDEPENDENT uniform queries: a prover whose oracle
// disagrees with the reduced polynomial on a delta fraction of cosets escapes all of
// them with probability at most (1 - delta)^q. That event depends only on the set
// of cosets hit, so a repeated index adds nothing and is opened once. Nothing
// requires q <= n either: when q approaches or exceeds n the draws simply cover
// most or all of the oracle, which is at least as sound. So the result may hold
// fewer than q indices, and prover and verifier derive the same list.
//
// # Why bytes are taken from the squeezed scalar rather than its residue
//
// Each squeeze gives a field element; the low 8 bytes are read as a uint64 and
// reduced mod n. n is a power of two here (it is a domain size), so the reduction
// is a mask and introduces no modulo bias. The function nevertheless rejects a
// non-power-of-two n rather than silently biasing, because a future caller with an
// arbitrary n would otherwise get a subtly skewed sample.
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

	mask := uint64(n - 1)
	seen := make(map[int]struct{}, q)
	out := make([]int, 0, min(q, n))

	for range q {
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
