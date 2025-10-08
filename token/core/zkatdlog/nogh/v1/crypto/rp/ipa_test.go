/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package rp_test

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum"
	"github.com/hyperledger-labs/fabric-token-sdk/token/core/zkatdlog/nogh/v1/crypto/evmzcat"
	"math/big"
	"strconv"
	"testing"
	"time"

	math "github.com/IBM/mathlib"
	"github.com/hyperledger-labs/fabric-token-sdk/token/core/zkatdlog/nogh/v1/crypto/rp"
	"github.com/stretchr/testify/assert"
)

func TestIPAProofVerify(t *testing.T) {
	curve := math.Curves[0]
	nr := uint64(6)
	l := uint64(1 << nr)
	leftGens := make([]*math.G1, l)
	rightGens := make([]*math.G1, l)
	left := make([]*math.Zr, l)
	right := make([]*math.Zr, l)
	rand, err := curve.Rand()
	assert.NoError(t, err)
	com := curve.NewG1()
	Q := curve.GenG1
	for i := 0; i < len(left); i++ {
		leftGens[i] = curve.HashToG1([]byte(strconv.Itoa(i)))
		rightGens[i] = curve.HashToG1([]byte(strconv.Itoa(i + 1)))
		left[i] = curve.NewRandomZr(rand)
		right[i] = curve.NewRandomZr(rand)
		com.Add(leftGens[i].Mul(left[i]))
		com.Add(rightGens[i].Mul(right[i]))
	}

	prover := rp.NewIPAProver(innerProduct(left, right, curve), left, right, Q, leftGens, rightGens, com, nr, curve)
	proof, err := prover.Prove()
	assert.NoError(t, err)
	assert.NotNil(t, proof)
	verifier := rp.NewIPAVerifier(innerProduct(left, right, curve), Q, leftGens, rightGens, com, nr, curve)
	err = verifier.Verify(proof)
	assert.NoError(t, err)

}

func TestIPAProofVerifySolidity(t *testing.T) {
	curve := math.Curves[1]
	nr := uint64(6)
	l := uint64(1 << nr)
	leftGens := make([]*math.G1, l)
	rightGens := make([]*math.G1, l)
	left := make([]*math.Zr, l)
	right := make([]*math.Zr, l)
	rand, err := curve.Rand()
	assert.NoError(t, err)
	com := curve.NewG1()
	Q := curve.GenG1
	for i := 0; i < len(left); i++ {
		leftGens[i] = curve.HashToG1([]byte(strconv.Itoa(i)))
		rightGens[i] = curve.HashToG1([]byte(strconv.Itoa(i + 1)))
		left[i] = curve.NewRandomZr(rand)
		right[i] = curve.NewRandomZr(rand)
		com.Add(leftGens[i].Mul(left[i]))
		com.Add(rightGens[i].Mul(right[i]))
	}

	prover := rp.NewIPAProver(innerProduct(left, right, curve), left, right, Q, leftGens, rightGens, com, nr, curve)
	proof, err := prover.Prove()
	assert.NoError(t, err)
	assert.NotNil(t, proof)
	verifier := rp.NewIPAVerifier(innerProduct(left, right, curve), Q, leftGens, rightGens, com, nr, curve)
	start := time.Now()
	err = verifier.Verify(proof)
	assert.NoError(t, err)
	fmt.Println("Time for Verification Plaintext: ", time.Since(start))

	verifiersol := evmzcat.ZKATVerifierIPAVerifier{
		InnerProduct:    new(big.Int).SetBytes(verifier.InnerProduct.Bytes()),
		Q:               evmzcat.MakeZKATPoint(verifier.Q),
		LeftGenerators:  evmzcat.MakeZKATPoints(verifier.LeftGenerators),
		RightGenerators: evmzcat.MakeZKATPoints(verifier.RightGenerators),
		Commitment:      evmzcat.MakeZKATPoint(verifier.Commitment),
		Rounds:          new(big.Int).SetUint64(verifier.NumberOfRounds),
	}

	proofsol := evmzcat.ZKATVerifierIPAProof{
		Left:  new(big.Int).SetBytes(proof.Left.Bytes()),
		Right: new(big.Int).SetBytes(proof.Right.Bytes()),
		L:     evmzcat.MakeZKATPoints(proof.L),
		R:     evmzcat.MakeZKATPoints(proof.R),
	}

	abi, err := evmzcat.EvmzcatMetaData.GetAbi()
	assert.NoError(t, err)
	input, err := abi.Pack("verifyIPA", verifiersol, proofsol)
	assert.NoError(t, err)

	backend, _, addr, auth, err := evmzcat.CreateInstance()
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

	//start = time.Now()
	//ok, err := instance.(*evmzcat.Evmzcat).VerifyIPA(nil, verifiersol, proofsol)
	//assert.NoError(t, err)
	//assert.True(t, ok)
	//fmt.Println("Time for Verification EVM: ", time.Since(start))
}

func innerProduct(left []*math.Zr, right []*math.Zr, c *math.Curve) *math.Zr {
	ip := c.NewZrFromInt(0)
	for i, l := range left {
		ip = c.ModAdd(ip, c.ModMul(l, right[i], c.GroupOrder), c.GroupOrder)
	}
	return ip
}
