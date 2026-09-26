/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pivot

import (
	"encoding/binary"

	mathlib "github.com/IBM/mathlib"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/rp/csp"
	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/titan"
)

// DomainSeparator is the Fiat-Shamir domain separator of the protocol, distinct
// from sum-check's and CSP's so that no transcript of one can be replayed as
// another.
const DomainSeparator = "PivotAgg-v1"

// NewTranscript returns a transcript initialised with the protocol's domain
// separator. Prover and verifier must start from transcripts in the same state; a
// caller that binds its own context first (a transaction payload, say) does so on
// both sides before Commit and AbsorbCommitments.
func NewTranscript(curve *mathlib.Curve) *csp.Transcript {
	tr := &csp.Transcript{Curve: curve}
	tr.InitHasherWithDomain(DomainSeparator)

	return tr
}

// absorbInt absorbs a non-negative integer as 8 big-endian bytes.
func absorbInt(tr *csp.Transcript, v int) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(v))
	tr.Absorb(b[:])
}

// absorbFr absorbs a field element in its canonical 32-byte form.
func absorbFr(tr *csp.Transcript, e *fr.Element) {
	b := e.Bytes()
	tr.Absorb(b[:])
}

// absorbFrs absorbs a length-prefixed vector of field elements.
func absorbFrs(tr *csp.Transcript, es []fr.Element) {
	absorbInt(tr, len(es))
	for i := range es {
		absorbFr(tr, &es[i])
	}
}

// absorbG1 absorbs a point in its compressed form.
func absorbG1(tr *csp.Transcript, p *bls12381.G1Affine) {
	b := p.Bytes()
	tr.Absorb(b[:])
}

// absorbG1s absorbs a length-prefixed vector of points.
func absorbG1s(tr *csp.Transcript, ps []bls12381.G1Affine) {
	absorbInt(tr, len(ps))
	for i := range ps {
		absorbG1(tr, &ps[i])
	}
}

// squeezeFr draws one challenge.
func squeezeFr(tr *csp.Transcript) (fr.Element, error) {
	z, err := tr.Squeeze()
	if err != nil {
		return fr.Element{}, errors.Wrap(err, "failed to squeeze challenge")
	}

	return fromZr(z), nil
}

// squeezeFrs draws n challenges.
func squeezeFrs(tr *csp.Transcript, n int) ([]fr.Element, error) {
	out := make([]fr.Element, n)
	for i := range out {
		var err error
		if out[i], err = squeezeFr(tr); err != nil {
			return nil, err
		}
	}

	return out, nil
}

// absorbCommitment binds a Titan commitment into the transcript: its shape and the
// root of the coset oracle, which is the part every opening is checked against.
func absorbCommitment(tr *csp.Transcript, com *titan.Commitment) error {
	if com == nil || com.Cosets == nil {
		return errors.Wrap(ErrMalformedProof, "commitment with a coset oracle is required")
	}
	absorbInt(tr, com.NumVars)
	absorbInt(tr, com.LogDomain)
	absorbInt(tr, com.K)
	absorbInt(tr, com.NumLeaves)
	absorbInt(tr, com.ColVars)
	absorbInt(tr, com.Cosets.NumVars)
	absorbInt(tr, com.Cosets.Ell)
	absorbInt(tr, com.Cosets.LogDomain)
	tr.Absorb(com.Cosets.Root)

	return nil
}

// absorbSetupAndCommitments is the common opening of the transcript: the sizes and
// both commitments. It must precede every challenge.
func absorbSetupAndCommitments(tr *csp.Transcript, s Sizes, coms Commitments) error {
	absorbInt(tr, s.LogN)
	absorbInt(tr, s.LogC)
	absorbInt(tr, s.LogL)
	absorbInt(tr, s.LogK)
	if err := absorbCommitment(tr, coms.W); err != nil {
		return errors.WithMessage(err, "field commitment")
	}
	if err := absorbCommitment(tr, coms.G); err != nil {
		return errors.WithMessage(err, "group commitment")
	}

	return nil
}

// absorbRelation binds the public relation. A relation derived from challenges is
// already determined by the transcript, but absorbing it anyway makes the protocol
// safe for relations that are not.
func absorbRelation(tr *csp.Transcript, r *Relation) {
	absorbFrs(tr, r.Alpha)
	absorbSparse(tr, r.B)
	absorbFrs(tr, r.AlphaPub)
	absorbSparse(tr, r.BPub)
	absorbSparse(tr, r.Gamma)
	absorbG1s(tr, r.G)
	absorbG1(tr, &r.G0)
	absorbInt(tr, len(r.Forms))
	for _, f := range r.Forms {
		absorbInt(tr, len(f.Coeffs))
		for i := range f.Coeffs {
			absorbInt(tr, f.Coeffs[i].Col)
			absorbFr(tr, &f.Coeffs[i].Val)
		}
		absorbFr(tr, &f.Const)
	}
	absorbInt(tr, len(r.Phi))
	for _, m := range r.Phi {
		absorbFr(tr, &m.Coeff)
		absorbInt(tr, len(m.Vars))
		for _, v := range m.Vars {
			absorbInt(tr, v)
		}
	}
}

// absorbSparse absorbs a length-prefixed list of sparse entries.
func absorbSparse(tr *csp.Transcript, entries []SparseEntry) {
	absorbInt(tr, len(entries))
	for i := range entries {
		absorbInt(tr, entries[i].Row)
		absorbInt(tr, entries[i].Col)
		absorbFr(tr, &entries[i].Val)
	}
}

// absorbStatement binds the public statement.
func absorbStatement(tr *csp.Transcript, st *Statement) {
	absorbInt(tr, len(st.Public))
	for _, row := range st.Public {
		absorbG1s(tr, row)
	}
	absorbInt(tr, len(st.RevealCols))
	for _, col := range st.RevealCols {
		absorbInt(tr, col)
	}
}
