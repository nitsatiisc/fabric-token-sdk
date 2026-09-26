/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package utxo

// Slot layout of one transfer
//
// A transfer has two inputs (i = 0, 1) and two outputs (j = 0, 1). Its field
// witness w and group witness g are laid out as below; every slot beyond the last
// listed one is zero padding.
//
// Field slots:
//
//	0 tau, 1 r_T, 2 vin_0, 3 s_0, 4 vin_1, 5 s_1, 6 vout_0, 7 t_0, 8 vout_1, 9 t_1, 10 sigma,
//	then per output j a range block of 2*kappa+2 slots:
//	    a_{j,0}, ..., a_{j,kappa}, b_{j,0}, b_{j,kappa+1}, ..., b_{j,2kappa}
//	then per input i an ownership block of 12 slots:
//	    sk, ou, role, eid, rh, e, r_2, r_3, s', r_nym, r_eid, r_rh
//
// Group slots of the private witness H:
//
//	0 C_T, then per input i: A-bar_i, d_i, Nym_i, RhNym_i
//
// Columns of the statement's public table (not committed):
//
//	0 Cin_0, 1 Cin_1, 2 Cout_0, 3 Cout_1, 4 EidNym_0, 5 EidNym_1, 6 A'_0, 7 A'_1
//
// The public table holds the transfer's commitments, the input owners'
// enrollment-ID pseudonyms, and the randomised signature elements the aggregated
// proof sends in the clear. The prover does not commit to it: the verifier knows it.

const (
	fTau = iota
	fRT
	fVin0
	fS0
	fVin1
	fS1
	fVout0
	fT0
	fVout1
	fT1
	fSigma
	fRangeBase
)

// Offsets inside an ownership block.
const (
	oSK = iota
	oOU
	oRole
	oEID
	oRH
	oE
	oR2
	oR3
	oSPrime
	oRNym
	oREid
	oRRh
	ownershipBlock
)

// Private group slots.
const (
	gCT = iota
	gInputBase
)

// Public table columns.
const (
	pCin0 = iota
	pCin1
	pCout0
	pCout1
	pEidNym0
	pEidNym1
	pAPrime0
	pAPrime1
	numPublicCols
)

// Offsets inside a group input block.
const (
	gABar = iota
	gD
	gNym
	gRhNym
	gInputBlock
)

// rangeBlock is the size of an output's range block.
func rangeBlock(kappa int) int { return 2*kappa + 2 }

// fA returns the slot of a_{j,l}, l in [0, kappa].
func fA(kappa, j, l int) int { return fRangeBase + j*rangeBlock(kappa) + l }

// fB returns the slot of b_{j,l}, l in {0} u [kappa+1, 2kappa].
func fB(kappa, j, l int) int {
	if l == 0 {
		return fRangeBase + j*rangeBlock(kappa) + kappa + 1
	}

	return fRangeBase + j*rangeBlock(kappa) + l + 1
}

// fOwn returns the slot of ownership field off for input i.
func fOwn(kappa, i, off int) int {
	return fRangeBase + 2*rangeBlock(kappa) + i*ownershipBlock + off
}

// gIn returns the group slot of input field off for input i.
func gIn(i, off int) int { return gInputBase + i*gInputBlock + off }

// numFieldSlots is the number of used field slots, 4 kappa + 39.
func numFieldSlots(kappa int) int { return fOwn(kappa, 2, 0) }

// numGroupSlots is the number of used group slots.
const numGroupSlots = gInputBase + 2*gInputBlock

// revealCols are the private columns whose aggregates the deferred checks need:
// A-bar_i for the pairings and Nym_i for the Schnorr proofs.
var revealCols = []int{gIn(0, gABar), gIn(1, gABar), gIn(0, gNym), gIn(1, gNym)}
