/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package utxo

import (
	"github.com/IBM/idemix/bbs"
	"github.com/IBM/idemix/bccsp/schemes/aries"
	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"
	"google.golang.org/protobuf/proto"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/token"
	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/transfer"
	"github.com/LFDT-Panurus/panurus/token/services/identity"
	"github.com/LFDT-Panurus/panurus/token/services/identity/idemix/crypto/protos-go/config"
	"github.com/LFDT-Panurus/panurus/token/services/identity/idemixnym/nym"
)

// TransferStatement is the public part of one 2-input, 2-output transfer: exactly
// what a naive transfer publishes on the ledger.
type TransferStatement struct {
	// Inputs are the input token commitments.
	Inputs [2]bls12381.G1Affine
	// Outputs are the output token commitments.
	Outputs [2]bls12381.G1Affine
	// EidNyms are the input owners' enrollment-ID pseudonyms, the IdemixNym owner
	// identities of the input tokens.
	EidNyms [2]bls12381.G1Affine
}

// StatementFromAction reads the statement of a naive transfer action: its input and
// output commitments and the pseudonyms that own its inputs. The action must have
// two inputs and two outputs, and IdemixNym input owners.
func StatementFromAction(action *transfer.Action) (*TransferStatement, error) {
	if action == nil {
		return nil, errors.New("action is required")
	}
	if len(action.Inputs) != 2 || len(action.Outputs) != 2 {
		return nil, errors.Errorf("only 2-input 2-output transfers are supported, got %d x %d", len(action.Inputs), len(action.Outputs))
	}
	st := &TransferStatement{}
	for i, in := range action.Inputs {
		if in == nil || in.Token == nil {
			return nil, errors.Errorf("input %d carries no token", i)
		}
		var err error
		if st.Inputs[i], err = toAffine(in.Token.Data); err != nil {
			return nil, errors.WithMessagef(err, "input %d commitment", i)
		}
		typed, err := identity.UnmarshalTypedIdentity(in.Token.Owner)
		if err != nil {
			return nil, errors.Wrapf(err, "input %d owner", i)
		}
		// An IdemixNym owner identity is the pseudonym point itself.
		if _, err := st.EidNyms[i].SetBytes(typed.Identity); err != nil {
			return nil, errors.Wrapf(err, "input %d owner is not an IdemixNym pseudonym", i)
		}
	}
	for j, out := range action.Outputs {
		if out == nil {
			return nil, errors.Errorf("output %d is nil", j)
		}
		var err error
		if st.Outputs[j], err = toAffine(out.Data); err != nil {
			return nil, errors.WithMessagef(err, "output %d commitment", j)
		}
	}

	return st, nil
}

// Opening is the opening of one token commitment: its value and blinding factor.
type Opening struct {
	Value    uint64
	Blinding fr.Element
}

// OwnerSecrets is what the owner of an input knows: the BBS+ credential on
// (sk, ou, role, eid, rh), and the randomness of the enrollment-ID pseudonym that
// owns the input.
type OwnerSecrets struct {
	SK, OU, Role, EID, RH fr.Element
	A                     bls12381.G1Affine
	E, S                  fr.Element
	EidNymRand            fr.Element
}

// TransferWitness is the private part of one transfer.
type TransferWitness struct {
	// Type is the token type as a scalar, HashToZr(type).
	Type    fr.Element
	Inputs  [2]Opening
	Outputs [2]Opening
	Owners  [2]*OwnerSecrets
}

// OpeningFromMetadata converts a token opening into an Opening, checking that the
// value fits the range.
func (p *Params) OpeningFromMetadata(m *token.Metadata) (Opening, error) {
	if m == nil || m.Value == nil || m.BlindingFactor == nil {
		return Opening{}, errors.New("metadata carries no opening")
	}
	v := toFr(m.Value)
	if !v.IsUint64() || (p.Bits < 64 && v.Uint64()>>p.Bits != 0) {
		return Opening{}, errors.Errorf("value does not fit in %d bits", p.Bits)
	}

	return Opening{Value: v.Uint64(), Blinding: toFr(m.BlindingFactor)}, nil
}

// TypeScalar returns the scalar a token type is committed under.
func (p *Params) TypeScalar(tokenType string) fr.Element {
	return toFr(p.curve.HashToZr([]byte(tokenType)))
}

// LoadOwnerSecrets reads an owner's secrets from its Idemix signer configuration
// (the serialized IdemixSignerConfig of the owner's MSP) and the audit information
// of its IdemixNym identity, and checks the credential against the issuer key.
func (p *Params) LoadOwnerSecrets(signerConfig, auditInfo []byte) (*OwnerSecrets, error) {
	cfg := &config.IdemixSignerConfig{}
	if err := proto.Unmarshal(signerConfig, cfg); err != nil {
		return nil, errors.Wrap(err, "failed to parse the signer configuration")
	}
	cred := &aries.Credential{}
	if err := proto.Unmarshal(cfg.Cred, cred); err != nil {
		return nil, errors.Wrap(err, "failed to parse the credential")
	}
	if cred.SkPos != 0 || len(cred.Attrs) != len(idemixAttributes) {
		return nil, errors.Errorf("unsupported credential layout: sk at %d, %d attributes", cred.SkPos, len(cred.Attrs))
	}
	sig, err := bbs.NewBBSLib(p.curve).ParseSignature(cred.Cred)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse the BBS+ signature")
	}
	ai, err := nym.DeserializeAuditInfo(auditInfo)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse the audit information")
	}
	if ai.AuditInfo == nil || ai.EidNymAuditData == nil {
		return nil, errors.New("audit information carries no enrollment-ID pseudonym data")
	}

	s := &OwnerSecrets{
		SK:         toFr(p.curve.NewZrFromBytes(cfg.Sk)),
		OU:         toFr(p.curve.NewZrFromBytes(cred.Attrs[0])),
		Role:       toFr(p.curve.NewZrFromBytes(cred.Attrs[1])),
		EID:        toFr(p.curve.NewZrFromBytes(cred.Attrs[2])),
		RH:         toFr(p.curve.NewZrFromBytes(cred.Attrs[3])),
		E:          toFr(sig.E),
		S:          toFr(sig.S),
		EidNymRand: toFr(ai.EidNymAuditData.Rand),
	}
	if s.A, err = toAffine(sig.A); err != nil {
		return nil, err
	}
	if eid := toFr(ai.EidNymAuditData.Attr); !eid.Equal(&s.EID) {
		return nil, errors.New("the pseudonym's enrollment ID is not the credential's")
	}
	if err := p.checkCredential(s); err != nil {
		return nil, err
	}

	return s, nil
}

// credentialB returns B = g_1 + s h_0 + sk h_1 + ou h_2 + role h_3 + eid h_4 + rh h_5,
// the point a BBS+ signature (A, e, s) certifies through (x + e) A = B.
func (p *Params) credentialB(s *OwnerSecrets) (bls12381.G1Affine, error) {
	return msm(
		[]bls12381.G1Affine{p.g1, p.gens[genH0], p.gens[genH1], p.gens[genH2], p.gens[genH3], p.gens[genH4], p.gens[genH5]},
		[]fr.Element{fr.One(), s.S, s.SK, s.OU, s.Role, s.EID, s.RH},
	)
}

// checkCredential verifies e(A, w + e g_2) = e(B, g_2).
func (p *Params) checkCredential(s *OwnerSecrets) error {
	b, err := p.credentialB(s)
	if err != nil {
		return err
	}
	var q bls12381.G2Affine
	q.ScalarMultiplication(&p.g2, bigOf(s.E))
	q.Add(&q, &p.w)
	var negB bls12381.G1Affine
	negB.Neg(&b)
	ok, err := bls12381.PairingCheck([]bls12381.G1Affine{s.A, negB}, []bls12381.G2Affine{q, p.g2})
	if err != nil {
		return errors.Wrap(err, "pairing failed")
	}
	if !ok {
		return errors.New("the credential does not verify under the issuer key")
	}

	return nil
}

// instance holds one transfer's pivot rows and the values the aggregated proof needs
// besides them.
type instance struct {
	w      []fr.Element
	g      []bls12381.G1Affine
	aPrime [2]bls12381.G1Affine
	// sk and rNym are kept for the aggregated Schnorr proofs.
	sk, rNym [2]fr.Element
}

// randFr returns a uniformly random field element.
func randFr() (fr.Element, error) {
	var e fr.Element
	if _, err := e.SetRandom(); err != nil {
		return e, errors.Wrap(err, "failed to sample randomness")
	}

	return e, nil
}

// buildInstance lays out one transfer's witness, drawing the fresh randomness of the
// type-and-sum commitment, the range blinding and the credential randomisation.
func (p *Params) buildInstance(n, c int, st *TransferStatement, wit *TransferWitness) (*instance, error) {
	if st == nil || wit == nil || wit.Owners[0] == nil || wit.Owners[1] == nil {
		return nil, errors.New("statement, witness and both owners are required")
	}
	kappa := p.Bits
	inst := &instance{w: make([]fr.Element, n), g: make([]bls12381.G1Affine, c)}
	w, g := inst.w, inst.g

	// Type and sum.
	rT, err := randFr()
	if err != nil {
		return nil, err
	}
	w[fTau], w[fRT] = wit.Type, rT
	var sigma fr.Element
	for i, slot := range [2][2]int{{fVin0, fS0}, {fVin1, fS1}} {
		w[slot[0]].SetUint64(wit.Inputs[i].Value)
		w[slot[1]].Sub(&wit.Inputs[i].Blinding, &rT)
		sigma.Add(&sigma, &w[slot[1]])
	}
	for j, slot := range [2][2]int{{fVout0, fT0}, {fVout1, fT1}} {
		w[slot[0]].SetUint64(wit.Outputs[j].Value)
		w[slot[1]].Sub(&wit.Outputs[j].Blinding, &rT)
		sigma.Sub(&sigma, &w[slot[1]])
	}
	w[fSigma] = sigma
	if g[gCT], err = msm([]bls12381.G1Affine{p.gens[genGt], p.gens[genH]}, []fr.Element{wit.Type, rT}); err != nil {
		return nil, err
	}

	// Range: a_j interpolates (0, a_{j,0}), (l, bit_{l-1}); b_j = a_j (a_j - 1).
	for j := range 2 {
		a0, err := randFr()
		if err != nil {
			return nil, err
		}
		a := make([]fr.Element, kappa+1)
		a[0] = a0
		for l := 1; l <= kappa; l++ {
			a[l].SetUint64((wit.Outputs[j].Value >> (l - 1)) & 1)
		}
		for l := range a {
			w[fA(kappa, j, l)] = a[l]
		}
		w[fB(kappa, j, 0)] = aTimesAMinusOne(a0)
		for l := 1; l <= kappa; l++ {
			var at fr.Element
			for m := range a {
				var t fr.Element
				t.Mul(&p.extrap[l-1][m], &a[m])
				at.Add(&at, &t)
			}
			w[fB(kappa, j, kappa+l)] = aTimesAMinusOne(at)
		}
	}

	// Ownership: randomise each credential for a BBS+ proof of knowledge.
	for i, s := range wit.Owners {
		if err := p.ownership(inst, i, s); err != nil {
			return nil, errors.WithMessagef(err, "input %d", i)
		}
	}

	return inst, nil
}

// ownership fills input i's ownership slots from its owner's secrets:
//
//	A' = r1 A,  A-bar = r1 B - e A',  d = r1 B - r2 h_0,  r3 = 1/r1,  s' = s - r2 r3,
//	Nym = sk h_1 + r_nym h_0,  RhNym = rh h_5 + r_rh h_0.
func (p *Params) ownership(inst *instance, i int, s *OwnerSecrets) error {
	kappa := p.Bits
	var rnd [4]fr.Element
	for k := range rnd {
		var err error
		if rnd[k], err = randFr(); err != nil {
			return err
		}
	}
	r1, r2, rNym, rRh := rnd[0], rnd[1], rnd[2], rnd[3]
	var r3, sPrime fr.Element
	r3.Inverse(&r1)
	sPrime.Mul(&r2, &r3)
	sPrime.Sub(&s.S, &sPrime)

	b, err := p.credentialB(s)
	if err != nil {
		return err
	}
	aPrime := scaleG1(s.A, r1)
	r1B := scaleG1(b, r1)
	var negE fr.Element
	negE.Neg(&s.E)
	aBar := addG1(r1B, scaleG1(aPrime, negE))
	var negR2 fr.Element
	negR2.Neg(&r2)
	d := addG1(r1B, scaleG1(p.gens[genH0], negR2))
	nymPt, err := msm([]bls12381.G1Affine{p.gens[genH1], p.gens[genH0]}, []fr.Element{s.SK, rNym})
	if err != nil {
		return err
	}
	rhNym, err := msm([]bls12381.G1Affine{p.gens[genH5], p.gens[genH0]}, []fr.Element{s.RH, rRh})
	if err != nil {
		return err
	}

	w, g := inst.w, inst.g
	for off, v := range map[int]fr.Element{
		oSK: s.SK, oOU: s.OU, oRole: s.Role, oEID: s.EID, oRH: s.RH, oE: s.E,
		oR2: r2, oR3: r3, oSPrime: sPrime, oRNym: rNym, oREid: s.EidNymRand, oRRh: rRh,
	} {
		w[fOwn(kappa, i, off)] = v
	}
	g[gIn(i, gABar)], g[gIn(i, gD)], g[gIn(i, gNym)], g[gIn(i, gRhNym)] = aBar, d, nymPt, rhNym
	inst.aPrime[i] = aPrime
	inst.sk[i], inst.rNym[i] = s.SK, rNym

	return nil
}

// aTimesAMinusOne returns a (a - 1).
func aTimesAMinusOne(a fr.Element) fr.Element {
	var am1, out fr.Element
	one := fr.One()
	am1.Sub(&a, &one)
	out.Mul(&a, &am1)

	return out
}

// addG1 returns a + b.
func addG1(a, b bls12381.G1Affine) bls12381.G1Affine {
	var out bls12381.G1Affine
	out.Add(&a, &b)

	return out
}

// msm returns sum_i scalars[i] points[i].
func msm(points []bls12381.G1Affine, scalars []fr.Element) (bls12381.G1Affine, error) {
	var out bls12381.G1Affine
	var acc bls12381.G1Jac
	if _, err := acc.MultiExp(points, scalars, ecc.MultiExpConfig{}); err != nil {
		return out, errors.Wrap(err, "multi-scalar multiplication failed")
	}
	out.FromJacobian(&acc)

	return out, nil
}
