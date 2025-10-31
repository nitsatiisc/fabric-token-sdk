package common

import (
	"fmt"
	"log"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fp"

	math "github.com/IBM/mathlib"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/crypto"
	//"github.com/hyperledger-labs/fabric-token-sdk/token/core/zkatdlog/nogh/v1/crypto/common"
	evmzcat "github.com/nitsatiisc/zkatsolidity"
	"github.com/pkg/errors"
)

var G1size = math.Curves[math.BN254].G1ByteSize
var G2size = math.Curves[math.BN254].G2ByteSize
var Zrsize = math.Curves[math.BN254].ScalarByteSize
var Curve = math.Curves[math.BN254]
var g1 = Curve.GenG1

var BASE_FIELD_FP, _ = new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)
var BASE_FIELD_FR, _ = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

// Gnark-crypto stores coordinates of G1 as Fp elements.
// Each Fp element is maintained in Montgomery representation modulo BASE_PRIME_FP
// Before we pass to solidity, or wish to verify the curve equation, we must
// convert to regular representation.
func CancelMontgomery(b []byte) *big.Int {
	var fpX fp.Element
	fpX.SetBytes(b)
	xCanon, _ := new(big.Int).SetString("0", 10)
	fpX.BigInt(xCanon)
	return xCanon
}

func AsPoints(e *math.G1) (*big.Int, *big.Int) {
	x := new(big.Int).SetBytes(e.Bytes()[0 : G1size/2])
	y := new(big.Int).SetBytes(e.Bytes()[G1size/2 : G1size])
	return x, y
}

func CreateInstance() (*backends.SimulatedBackend, any, *common.Address, *bind.TransactOpts, error) {
	key, _ := crypto.GenerateKey()
	auth, _ := bind.NewKeyedTransactorWithChainID(key, big.NewInt(1337))
	alloc := map[common.Address]core.GenesisAccount{
		auth.From: {Balance: big.NewInt(1e18)}, // 1 ETH
	}
	sim := backends.NewSimulatedBackend(alloc, 8_000_000_000)

	// 2. Deploy
	addr, _, instance, err := evmzcat.DeployIdemixevm(auth, sim)
	if err != nil {
		return nil, nil, nil, nil, errors.Wrapf(err, "failed to deploy evmzcat")
	}
	sim.Commit()
	log.Println("Contract at:", addr.Hex())
	return sim, instance, &addr, auth, nil
}

func MakeZKATPoint(g *math.G1) evmzcat.ZKATVerifierG1Point {
	gx, gy := AsPoints(g)
	return evmzcat.ZKATVerifierG1Point{X: gx, Y: gy}
}

func MakeZKATPoints(gs []*math.G1) []evmzcat.ZKATVerifierG1Point {
	points := make([]evmzcat.ZKATVerifierG1Point, len(gs))
	for i, g := range gs {
		points[i] = MakeZKATPoint(g)
	}
	return points
}

func isOnCurveBN254(x *big.Int, y *big.Int) bool {

	// y^2 mod p
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, BASE_FIELD_FP)

	// x^3 + 3 mod p
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x) // x^3
	x3.Add(x3, big.NewInt(3))
	x3.Mod(x3, BASE_FIELD_FP)
	fmt.Println(x)
	fmt.Println(y)
	fmt.Println(x3)
	fmt.Println(y2)
	return y2.Cmp(x3) == 0
}
