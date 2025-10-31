/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rp_test

import (
	"context"
	"fmt"
	"math/big"
	"strconv"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/hyperledger-labs/fabric-token-sdk/token/core/zkatdlog/nogh/v1/crypto/common"
	//"github.com/hyperledger-labs/fabric-token-sdk/token/core/zkatdlog/nogh/v1/crypto/evmzcat"
	math "github.com/IBM/mathlib"
	"github.com/hyperledger-labs/fabric-token-sdk/token/core/zkatdlog/nogh/v1/crypto/rp"
	evmzcat "github.com/nitsatiisc/zkatsolidity"
	"github.com/stretchr/testify/assert"
)

func TestBFProofVerify(t *testing.T) {
	curve := math.Curves[1]
	nr := uint64(3)
	l := uint64(1 << nr)
	leftGens := make([]*math.G1, l)
	rightGens := make([]*math.G1, l)

	rand, err := curve.Rand()
	assert.NoError(t, err)

	Q := curve.GenG1.Mul(curve.NewRandomZr(rand))
	P := curve.GenG1.Mul(curve.NewRandomZr(rand))
	H := curve.GenG1.Mul(curve.NewRandomZr(rand))
	G := curve.GenG1.Mul(curve.NewRandomZr(rand))
	for i := 0; i < len(leftGens); i++ {
		leftGens[i] = curve.HashToG1([]byte(strconv.Itoa(2 * i)))
		rightGens[i] = curve.HashToG1([]byte(strconv.Itoa(2*i + 1)))
	}
	bf := curve.NewRandomZr(rand)
	com := G.Mul(curve.NewZrFromInt(115))
	com.Add(H.Mul(bf))
	prover := rp.NewRangeProver(com, 115, []*math.G1{G, H}, bf, leftGens, rightGens, P, Q, nr, l, curve)
	verifier := rp.NewRangeVerifier(com, []*math.G1{G, H}, leftGens, rightGens, P, Q, nr, l, curve)

	proof, err := prover.Prove()
	assert.NoError(t, err)
	assert.NotNil(t, proof)
	err = verifier.Verify(proof)
	assert.NoError(t, err)
}

func TestBFProofVerifySolidity(t *testing.T) {
	curve := math.Curves[1]
	nr := uint64(6)
	l := uint64(1 << nr)
	leftGens := make([]*math.G1, l)
	rightGens := make([]*math.G1, l)

	rand, err := curve.Rand()
	assert.NoError(t, err)

	Q := curve.GenG1.Mul(curve.NewRandomZr(rand))
	P := curve.GenG1.Mul(curve.NewRandomZr(rand))
	H := curve.GenG1.Mul(curve.NewRandomZr(rand))
	G := curve.GenG1.Mul(curve.NewRandomZr(rand))
	for i := 0; i < len(leftGens); i++ {
		leftGens[i] = curve.HashToG1([]byte(strconv.Itoa(2 * i)))
		rightGens[i] = curve.HashToG1([]byte(strconv.Itoa(2*i + 1)))
	}
	bf := curve.NewRandomZr(rand)
	com := G.Mul(curve.NewZrFromInt(115))
	com.Add(H.Mul(bf))
	prover := rp.NewRangeProver(com, 115, []*math.G1{G, H}, bf, leftGens, rightGens, P, Q, nr, l, curve)
	verifier := rp.NewRangeVerifier(com, []*math.G1{G, H}, leftGens, rightGens, P, Q, nr, l, curve)
	proof, err := prover.Prove()
	assert.NoError(t, err)
	assert.NotNil(t, proof)
	start := time.Now()
	err = verifier.Verify(proof)
	fmt.Println("Time for Verification Plaintext: ", time.Since(start))
	assert.NoError(t, err)

	verifiersol := evmzcat.ZKATVerifierRangeVerifier{
		ComV:            common.MakeZKATPoint(verifier.Commitment),
		G:               common.MakeZKATPoint(verifier.CommitmentGenerators[0]),
		H:               common.MakeZKATPoint(verifier.CommitmentGenerators[1]),
		LeftGenerators:  common.MakeZKATPoints(verifier.LeftGenerators),
		RightGenerators: common.MakeZKATPoints(verifier.RightGenerators),
		P:               common.MakeZKATPoint(verifier.P),
		Q:               common.MakeZKATPoint(verifier.Q),
		Rounds:          new(big.Int).SetUint64(verifier.NumberOfRounds),
		Nr:              new(big.Int).SetUint64(verifier.BitLength),
	}

	fmt.Println("V.Commitment = ", verifier.Commitment.String())
	fmt.Println("ComV = ", verifiersol.ComV)

	proofsol := evmzcat.ZKATVerifierRangeProof{
		C:            common.MakeZKATPoint(proof.Data.C),
		D:            common.MakeZKATPoint(proof.Data.D),
		T1:           common.MakeZKATPoint(proof.Data.T1),
		T2:           common.MakeZKATPoint(proof.Data.T2),
		Tau:          new(big.Int).SetBytes(proof.Data.Tau.Bytes()),
		Delta:        new(big.Int).SetBytes(proof.Data.Delta.Bytes()),
		InnerProduct: new(big.Int).SetBytes(proof.Data.InnerProduct.Bytes()),
		IpaProof: evmzcat.ZKATVerifierIPAProof{
			Left:  new(big.Int).SetBytes(proof.IPA.Left.Bytes()),
			Right: new(big.Int).SetBytes(proof.IPA.Right.Bytes()),
			L:     common.MakeZKATPoints(proof.IPA.L),
			R:     common.MakeZKATPoints(proof.IPA.R),
		},
	}

	abi, err := evmzcat.IdemixevmMetaData.GetAbi()
	assert.NoError(t, err)
	input, err := abi.Pack("verifyRange", verifiersol, proofsol)
	assert.NoError(t, err)
	backend, _, addr, auth, err := common.CreateInstance()
	assert.NoError(t, err)
	// Prepare call message
	msg := ethereum.CallMsg{
		From:     auth.From,
		To:       addr,
		GasPrice: big.NewInt(0),
		Data:     input,
	}

	// Estimate gas
	start = time.Now()
	gasUsed, err := backend.EstimateGas(context.Background(), msg)
	assert.NoError(t, err)
	fmt.Println("Time for Execution on EVM: ", time.Since(start))
	fmt.Println("Gas used: ", gasUsed)

}
