/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package utxo aggregates K naive 2-input, 2-output zkatdlog transfers into one
// proof of the relation R_utxo, using the pivot meta-protocol.
//
// A naive transfer proves, separately, that its values balance and share a type
// (type-and-sum proof), that its outputs are in range (one range proof per output),
// and that each input is owned (a BBS+ proof of knowledge of the owner's credential
// plus a pseudonym signature). R_utxo states all of this for one transfer as
// sixteen group equations and a field constraint over one mixed witness, and the
// pivot protocol proves K instances of it at once.
//
// The aggregated proof consumes the same public data as the K naive transfers --
// the input and output token commitments and the input owners' enrollment-ID
// pseudonyms (StatementFromAction reads them off a naive action) -- and the same
// public parameters (NewParams reads them from the token public parameters). It
// additionally publishes, per input, the randomised signature element A', as a naive
// ownership proof does.
//
// The checks that are not part of the pivot relation run in aggregate:
//
//   - the BBS+ pairing e(A', w) = e(A-bar, g_2) once per input slot, on the
//     eq(., tau)-weighted aggregates of A' and A-bar;
//   - A' != 0 for every transfer, directly on the published A';
//   - one Schnorr proof per input slot of the aggregated pseudonym's opening, bound
//     to the message M the aggregated transaction signs.
package utxo

import (
	"encoding/binary"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/pivot"
	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/rp/csp"
)

// DomainSeparator binds a transcript to this relation, on top of the pivot one.
const DomainSeparator = "PivotUTXO-v1"

// ErrVerificationFailed is returned by Verify for a well-formed proof that does not
// verify, beyond the pivot protocol's own errors.
var ErrVerificationFailed = errors.New("aggregated UTXO proof does not verify")

// SchnorrProof proves knowledge of (sk, r) with Nym = sk h_1 + r h_0.
type SchnorrProof struct {
	T      bls12381.G1Affine
	Z1, Z2 fr.Element
}

// Proof is an aggregated proof for K transfers.
type Proof struct {
	// APrime[k][i] is the randomised credential element of input i of transfer k,
	// published in the clear.
	APrime [][2]bls12381.G1Affine
	// Commitments are the pivot commitments to the field and group witnesses.
	Commitments pivot.Commitments
	// Pivot is the proof of the K collapsed instances of R_utxo.
	Pivot *pivot.Proof
	// Schnorr[i] proves knowledge of the key behind the aggregated Nym of input i.
	Schnorr [2]SchnorrProof
}

// Prove aggregates K transfers. sts[k] is the public statement of transfer k, as
// read from its naive action, and wits[k] its witness. msg is the message the
// aggregated transaction signs, which the Schnorr proofs are bound to.
func Prove(s *Setup, msg []byte, sts []*TransferStatement, wits []*TransferWitness) (*Proof, error) {
	if s == nil {
		return nil, errors.New("setup is required")
	}
	if len(sts) != s.K() || len(wits) != s.K() {
		return nil, errors.Errorf("setup aggregates %d transfers, got %d statements and %d witnesses", s.K(), len(sts), len(wits))
	}
	sizes := s.pivot.Sizes()
	insts := make([]*instance, s.K())
	for k := range insts {
		var err error
		if insts[k], err = s.params.buildInstance(sizes.N(), sizes.C(), sts[k], wits[k]); err != nil {
			return nil, errors.WithMessagef(err, "transfer %d", k)
		}
	}

	return s.proveInstances(msg, sts, insts)
}

// proveInstances is Prove on instances that are already laid out. It is separate so
// that tests can corrupt a laid-out instance before proving.
func (s *Setup) proveInstances(msg []byte, sts []*TransferStatement, insts []*instance) (*Proof, error) {
	p := s.params
	pw := &pivot.Witness{W: make([][]fr.Element, s.K()), H: make([][]bls12381.G1Affine, s.K())}
	proof := &Proof{APrime: make([][2]bls12381.G1Affine, s.K())}
	for k, inst := range insts {
		pw.W[k], pw.H[k] = inst.w, inst.g
		proof.APrime[k] = inst.aPrime
	}

	tr := s.newTranscript(msg, sts, proof.APrime)
	committed, err := pivot.Commit(s.pivot, pw, tr)
	if err != nil {
		return nil, err
	}
	proof.Commitments = committed.Commitments()
	rel, err := s.collapse(tr)
	if err != nil {
		return nil, err
	}
	var out *pivot.Outcome
	if proof.Pivot, out, err = pivot.Prove(s.pivot, rel, s.statement(sts, proof.APrime), committed, tr); err != nil {
		return nil, err
	}

	// Aggregated Schnorr proofs on Nym^_i = sk^_i h_1 + r^_i h_0.
	eqTau := pivot.EqTable(out.Tau)
	var rho [2][2]fr.Element
	for i := range 2 {
		for j := range 2 {
			if rho[i][j], err = randFr(); err != nil {
				return nil, err
			}
		}
		if proof.Schnorr[i].T, err = msm([]bls12381.G1Affine{p.gens[genH1], p.gens[genH0]}, rho[i][:]); err != nil {
			return nil, err
		}
		absorbG1(tr, &proof.Schnorr[i].T)
	}
	c, err := squeeze(tr)
	if err != nil {
		return nil, err
	}
	for i := range 2 {
		var skHat, rHat fr.Element
		for k, inst := range insts {
			var t fr.Element
			t.Mul(&eqTau[k], &inst.sk[i])
			skHat.Add(&skHat, &t)
			t.Mul(&eqTau[k], &inst.rNym[i])
			rHat.Add(&rHat, &t)
		}
		proof.Schnorr[i].Z1.Mul(&c, &skHat)
		proof.Schnorr[i].Z1.Add(&proof.Schnorr[i].Z1, &rho[i][0])
		proof.Schnorr[i].Z2.Mul(&c, &rHat)
		proof.Schnorr[i].Z2.Add(&proof.Schnorr[i].Z2, &rho[i][1])
	}

	return proof, nil
}

// Verify checks an aggregated proof for K transfers against their statements and
// the signed message.
func Verify(s *Setup, msg []byte, sts []*TransferStatement, proof *Proof) error {
	if s == nil {
		return errors.New("setup is required")
	}
	if proof == nil || proof.Pivot == nil {
		return errors.Wrap(pivot.ErrMalformedProof, "proof is required")
	}
	if len(sts) != s.K() || len(proof.APrime) != s.K() {
		return errors.Wrapf(pivot.ErrMalformedProof, "setup aggregates %d transfers, got %d statements and %d A' pairs", s.K(), len(sts), len(proof.APrime))
	}
	p := s.params

	// A' != 0: the one BBS+ condition that is not linear, checked per transfer.
	for k := range proof.APrime {
		for i := range 2 {
			if proof.APrime[k][i].IsInfinity() {
				return errors.Wrapf(ErrVerificationFailed, "transfer %d input %d: A' is the identity", k, i)
			}
		}
	}

	tr := s.newTranscript(msg, sts, proof.APrime)
	if err := pivot.AbsorbCommitments(s.pivot, proof.Commitments, tr); err != nil {
		return err
	}
	rel, err := s.collapse(tr)
	if err != nil {
		return err
	}
	out, err := pivot.Verify(s.pivot, rel, s.statement(sts, proof.APrime), proof.Commitments, proof.Pivot, tr)
	if err != nil {
		return err
	}
	eqTau := pivot.EqTable(out.Tau)
	aBar := out.Revealed[:2]
	nyms := out.Revealed[2:]

	// Pairings, once per input slot: e(A'^_i, w) = e(A-bar^_i, g_2), with A'^_i
	// aggregated by the verifier from the published A'.
	for i := range 2 {
		col := make([]bls12381.G1Affine, s.K())
		for k := range col {
			col[k] = proof.APrime[k][i]
		}
		aHat, err := msm(col, eqTau)
		if err != nil {
			return err
		}
		var negABar bls12381.G1Affine
		negABar.Neg(&aBar[i])
		ok, err := bls12381.PairingCheck([]bls12381.G1Affine{aHat, negABar}, []bls12381.G2Affine{p.w, p.g2})
		if err != nil {
			return errors.Wrap(err, "pairing failed")
		}
		if !ok {
			return errors.Wrapf(ErrVerificationFailed, "input %d: aggregated BBS+ pairing check", i)
		}
	}

	// Aggregated Schnorr proofs: z1 h_1 + z2 h_0 = T + c Nym^_i.
	for i := range 2 {
		absorbG1(tr, &proof.Schnorr[i].T)
	}
	c, err := squeeze(tr)
	if err != nil {
		return err
	}
	for i := range 2 {
		lhs, err := msm([]bls12381.G1Affine{p.gens[genH1], p.gens[genH0]}, []fr.Element{proof.Schnorr[i].Z1, proof.Schnorr[i].Z2})
		if err != nil {
			return err
		}
		rhs := addG1(proof.Schnorr[i].T, scaleG1(nyms[i], c))
		if !lhs.Equal(&rhs) {
			return errors.Wrapf(ErrVerificationFailed, "input %d: aggregated Schnorr proof", i)
		}
	}

	return nil
}

// newTranscript binds the message, the statements and the published A' before any
// commitment, so every challenge depends on them.
func (s *Setup) newTranscript(msg []byte, sts []*TransferStatement, aPrime [][2]bls12381.G1Affine) *csp.Transcript {
	tr := pivot.NewTranscript(s.params.curve)
	tr.Absorb([]byte(DomainSeparator))
	absorbInt(tr, s.params.Bits)
	absorbInt(tr, len(msg))
	tr.Absorb(msg)
	absorbInt(tr, len(sts))
	for k, st := range sts {
		for i := range 2 {
			absorbG1(tr, &st.Inputs[i])
			absorbG1(tr, &st.Outputs[i])
			absorbG1(tr, &st.EidNyms[i])
			absorbG1(tr, &aPrime[k][i])
		}
	}

	return tr
}

// collapse draws eta and xi, after the commitments, and builds the pivot relation.
func (s *Setup) collapse(tr *csp.Transcript) (*pivot.Relation, error) {
	eta, err := squeeze(tr)
	if err != nil {
		return nil, err
	}
	xi, err := squeeze(tr)
	if err != nil {
		return nil, err
	}

	return s.params.buildRelation(s.pivot.Sizes(), eta, xi), nil
}

// statement returns the pivot statement: the public table, one row per transfer
// with its commitments, pseudonyms and published A', and the four revealed columns.
func (s *Setup) statement(sts []*TransferStatement, aPrime [][2]bls12381.G1Affine) *pivot.Statement {
	st := &pivot.Statement{Public: make([][]bls12381.G1Affine, len(sts)), RevealCols: revealCols}
	for k, t := range sts {
		st.Public[k] = []bls12381.G1Affine{
			t.Inputs[0], t.Inputs[1], t.Outputs[0], t.Outputs[1],
			t.EidNyms[0], t.EidNyms[1], aPrime[k][0], aPrime[k][1],
		}
	}

	return st
}

func absorbInt(tr *csp.Transcript, v int) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(v))
	tr.Absorb(b[:])
}

func absorbG1(tr *csp.Transcript, p *bls12381.G1Affine) {
	b := p.Bytes()
	tr.Absorb(b[:])
}

func squeeze(tr *csp.Transcript) (fr.Element, error) {
	z, err := tr.Squeeze()
	if err != nil {
		return fr.Element{}, errors.Wrap(err, "failed to squeeze challenge")
	}

	return toFr(z), nil
}
