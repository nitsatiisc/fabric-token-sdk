/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pivot

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/sumcheck"
	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/titan"
)

// Commitments are the two commitments that open the protocol: W to the field
// witness table W~, G to the group witness table g~.
type Commitments struct {
	W *titan.Commitment
	G *titan.Commitment
}

// Proof is everything the prover sends after the commitments, in transcript order.
//
// Each sum-check leaves a claim about values at its random point; the fields that
// follow it are the prover's values for that claim, which later steps discharge.
type Proof struct {
	// SC1 is the aggregation sum-check over the group witness. Its asserted sum is
	// T1, the eq(., tau)-weighted sum of the hidden-group part of the K group
	// equations.
	SC1 *sumcheck.Proof
	// PEval is v_P = P~(rho_c, rho_K) with P = B W, discharged by SC4.
	PEval fr.Element
	// GEval is g~(rho_c, rho_K), discharged by the group batch.
	GEval bls12381.G1Affine

	// SC1Pub is the aggregation sum-check over the statement's public table,
	// asserting T1Pub; nil when the statement has none.
	SC1Pub *sumcheck.Proof
	// PubEval is v_P' = P'~(rho_t, rho_K') with P' = BPub W, discharged by SC4.
	PubEval fr.Element

	// SC2 is the sum-check over the public generators, asserting -G0 - T1 - T1Pub.
	SC2 *sumcheck.Proof
	// QEval is v_Q = Q~_tau(rho_l) with Q_tau = Gamma W_tau, discharged by SC4.
	QEval fr.Element

	// SC3 is the zero-check of the field constraint, nil when the relation has
	// none.
	SC3 *sumcheck.Proof
	// FormEvals holds L~_k(rho') for every affine form, discharged by SC4.
	FormEvals []fr.Element

	// SC4 is the sparse-product sum-check over the field positions.
	SC4 *sumcheck.Proof
	// WEvals holds W~ at (sigma, rho_K), (sigma, tau), then (sigma, rho') with a
	// field constraint, then (sigma, rho_K') with a public table.
	WEvals []fr.Element

	// WBatch reduces the WEvals claims to one point; WOpen is W~ there and WPCS
	// its opening.
	WBatch *sumcheck.Proof
	WOpen  fr.Element
	WPCS   *titan.EvalProof

	// Revealed holds sum_k eq(k, tau) H[k][col] for each revealed column.
	Revealed []bls12381.G1Affine

	// GBatch reduces the g~ claims (GEval and the revealed columns) to one
	// point; GOpen is g~ there and GPCS its opening.
	GBatch *sumcheck.Proof
	GOpen  bls12381.G1Affine
	GPCS   *titan.GroupEvalProof
}

// checkShape rejects a proof with missing parts or wrongly sized vectors, before
// any of it is interpreted.
func (p *Proof) checkShape(rel *Relation, st *Statement) error {
	if p == nil {
		return errors.Wrap(ErrMalformedProof, "proof is required")
	}
	if p.SC1 == nil || p.SC2 == nil || p.SC4 == nil || p.WBatch == nil || p.GBatch == nil ||
		p.WPCS == nil || p.GPCS == nil {
		return errors.Wrap(ErrMalformedProof, "proof is missing a sub-proof")
	}
	wantW := 2
	if rel.hasFieldConstraint() {
		if p.SC3 == nil {
			return errors.Wrap(ErrMalformedProof, "relation has a field constraint but the proof has no SC3")
		}
		if len(p.FormEvals) != len(rel.Forms) {
			return errors.Wrapf(ErrMalformedProof, "%d form values for %d forms", len(p.FormEvals), len(rel.Forms))
		}
		wantW = 3
	} else if p.SC3 != nil || len(p.FormEvals) != 0 {
		return errors.Wrap(ErrMalformedProof, "relation has no field constraint but the proof carries one")
	}
	if st.publicWidth() > 0 {
		if p.SC1Pub == nil {
			return errors.Wrap(ErrMalformedProof, "statement has a public table but the proof has no SC1Pub")
		}
		wantW++
	} else if p.SC1Pub != nil {
		return errors.Wrap(ErrMalformedProof, "statement has no public table but the proof carries SC1Pub")
	}
	if len(p.WEvals) != wantW {
		return errors.Wrapf(ErrMalformedProof, "%d field evaluations, expected %d", len(p.WEvals), wantW)
	}
	if len(p.Revealed) != len(st.RevealCols) {
		return errors.Wrapf(ErrMalformedProof, "%d revealed values for %d revealed columns", len(p.Revealed), len(st.RevealCols))
	}

	return nil
}

// Outcome is what a successful verification tells the caller beyond acceptance:
// the aggregation challenge and the revealed column aggregates, both needed for
// checks the caller runs outside the relation.
type Outcome struct {
	// Tau is the aggregation challenge, in table order over the instance bits.
	Tau []fr.Element
	// Revealed[j] is sum_k eq(k, Tau) H[k][st.RevealCols[j]].
	Revealed []bls12381.G1Affine
}
