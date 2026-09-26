/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package pivot implements the aggregation meta-protocol for the mixed-witness
// pivot relation: a proof that K instances of
//
//	f(g, w) = ( G0 + alpha^T g + g^T B w + G^T Gamma w ,  Phi(L_1(w), ..., L_tau(w)) ) = (0_G, 0_F)
//
// all hold, with one commitment to the field witnesses W (K x n) and one to the
// group witnesses H (K x c), four sum-checks and one polynomial-commitment opening
// per commitment.
//
// Here g in G^c is a private group witness, w in F^n a private field witness,
// alpha in F^c, B in F^{c x n} and Gamma in F^{l x n} are public (B and Gamma
// sparse), G in G^l are public generators shared by every instance, G0 is a public
// offset, and Phi is a public polynomial in public affine forms L_k of w.
//
// # Protocol
//
// The prover commits to W~ with the Titan field PCS and to g~ (the multilinear
// extension of H) with the Titan group PCS. The tables are laid out position-first:
// entry x + (z << log n) of W~ is w^(z)[x], and entry b + (z << log c) of g~ is
// g^(z)[b]. After the commitments, with tau drawn from F^{log K}:
//
//	SC1 (group):  sum_{b,z} eq(z,tau) (alpha_b + (B w^(z))_b) g^(z)_b = T1
//	SC2 (group):  sum_y (Gamma W_tau)_y G_y = -G0 - T1,  W_tau(x) = W~(x, tau)
//	SC3 (field):  sum_z eq(z,tau) Phi(L~_1(z), ..., L~_tau(z)) = 0      (MultiClaim)
//	SC4 (field):  one 3-term MultiClaim over x that discharges the sparse products
//	              v_P, v_Q left by SC1 and SC2 and the affine-form values left by SC3
//
// SC1 and SC2 together are the eq(.,tau)-weighted sum of the K group equations, so
// only their sum has to vanish; SC3 is the zero-check of the K field constraints.
// The residual evaluation claims on W~ (three) and on g~ (one, plus one per public
// or revealed column) are batched by an eq-weighted sum-check into a single point
// each, and closed by one PCS opening per commitment.
//
// # Column slices
//
// A Statement can name public columns of H, whose values the verifier knows, and
// revealed columns, whose tau-aggregate the proof discloses. Both are evaluation
// claims of g~ at a point whose column bits are boolean and whose instance bits are
// tau, and ride on the group batch at no extra opening. Revealed columns are how a
// caller aggregates checks that are linear in a column, such as pairing checks.
//
// # Parameters that depend on challenges
//
// The API is split into Commit and Prove so that a caller can squeeze challenges
// from the transcript after the commitments and derive the Relation from them, as
// the UTXO instantiation does for its collapse challenges. Verify mirrors this with
// AbsorbCommitments.
//
// # Security notes
//
// The protocol is not zero-knowledge: the Titan PCS is not hiding and sum-check
// messages are sent in the clear. Its soundness is conditional on the evaluation
// binding of the Titan PCS; see docs/crypto/titan.md for the regime in which that
// is established. Every one of the K instances must satisfy the relation: padding K
// to a power of two with all-zero instances does not work once G0 is non-zero.
package pivot
