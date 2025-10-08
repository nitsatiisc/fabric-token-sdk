package evmzcat_test

import (
	"fmt"
	"testing"
	"time"

	math "github.com/IBM/mathlib"
	"github.com/hyperledger-labs/fabric-token-sdk/token/core/zkatdlog/nogh/v1/crypto/evmzcat"
	//"github.com/hyperledger-labs/fabric-token-sdk/token/core/zkatdlog/nogh/v1/crypto/common"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var curve = math.Curves[math.BN254]
var g1 = curve.GenG1
var g2 = curve.GenG2

func TestExample(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Example Suite")
}

var _ = Describe("DlogProof", func() {
	It("DlogProof", func() {
		rand, err := curve.Rand()
		Expect(err).NotTo(HaveOccurred())
		x := curve.NewRandomZr(rand)
		G := g1.Copy()
		P := g1.Copy().Mul(x)
		instance, err := evmzcat.CreateInstance()
		Expect(err).NotTo(HaveOccurred())

		prover := &evmzcat.SigmaProver{
			G: G,
			X: x,
			P: P,
		}

		verifier := &evmzcat.SigmaVerifier{
			G: G,
			P: P,
		}
		proof, err := prover.Prove()
		Expect(err).NotTo(HaveOccurred())

		start := time.Now()
		err = verifier.Verify(proof)
		Expect(err).NotTo(HaveOccurred())
		elapsed := time.Since(start)
		fmt.Printf("Time for plaintext verifier=%v\n", elapsed.Milliseconds())

		start = time.Now()
		err = verifier.VerifySolidity(instance, proof)
		Expect(err).NotTo(HaveOccurred())
		elapsed = time.Since(start)
		fmt.Printf("Time for solidity verifier=%v\n", elapsed.Milliseconds())
	})

})
