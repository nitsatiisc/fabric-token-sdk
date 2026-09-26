/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package utxo

import (
	"math/bits"
	"strconv"

	"github.com/IBM/idemix/bccsp/schemes/aries"
	mathlib "github.com/IBM/mathlib"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/pivot"
	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/titan"
	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/setup"
)

// idemixAttributes are the attribute names of the default Idemix credential
// schema, after the user secret key: OU, Role, EnrollmentID, RevocationHandle.
// The BBS+ message vector is (sk, ou, role, eid, rh) on generators h_1..h_5.
var idemixAttributes = []string{"OU", "Role", "EnrollmentID", "RevocationHandle"}

// generator indices into the public-generator vector G of the relation.
const (
	genGt = iota
	genGv
	genH
	genH0
	genH1 // sk
	genH2 // ou
	genH3 // role
	genH4 // eid
	genH5 // rh
	numGens
)

// Params are the public parameters of the aggregated UTXO relation. They are
// derived entirely from the token public parameters, so an aggregated transfer
// consumes exactly what the naive transfers it replaces consume: the Pedersen
// generators of the token commitments, the range bit length, and the Idemix
// issuer public key that the owners' credentials verify under.
type Params struct {
	// Bits is the range bit length kappa.
	Bits int

	curve *mathlib.Curve

	// gens is (G_t, G_v, H, h_0, h_1, ..., h_5), the generators every instance
	// shares, padded with the identity to a power of two.
	gens []bls12381.G1Affine
	// g1 is the BBS+ constant generator, which enters the relation through G0.
	g1 bls12381.G1Affine
	// w is the issuer's BBS+ public key and g2 the G2 generator, for the pairings.
	w, g2 bls12381.G2Affine

	logN int

	// extrap[l-1][m] is L_m(kappa + l), the Lagrange coefficient of node m in
	// {0..kappa} at the integer point kappa + l, l = 1..kappa. The prover uses it
	// to extend a_j beyond its nodes when it builds b_j = a_j (a_j - 1).
	extrap [][]fr.Element
}

// NewParams derives the relation's parameters from token public parameters. The
// token curve and the Idemix curve must coincide, so that one group hosts both the
// token commitments and the credentials.
func NewParams(pp *setup.PublicParams) (*Params, error) {
	if pp == nil {
		return nil, errors.New("public parameters are required")
	}
	if len(pp.PedersenGenerators) != 3 {
		return nil, errors.Errorf("expected 3 Pedersen generators, got %d", len(pp.PedersenGenerators))
	}
	if len(pp.IdemixIssuerPublicKeys) == 0 {
		return nil, errors.New("public parameters carry no Idemix issuer public key")
	}
	ipkEntry := pp.IdemixIssuerPublicKeys[0]
	if ipkEntry.Curve != pp.Curve {
		return nil, errors.Errorf("token curve %d and Idemix curve %d differ; the aggregated relation needs one group", pp.Curve, ipkEntry.Curve)
	}
	curve := mathlib.Curves[pp.Curve]

	var kappa uint64
	switch {
	case pp.CSPRangeProofParams != nil:
		kappa = pp.CSPRangeProofParams.BitLength
	case pp.RangeProofParams != nil:
		kappa = pp.RangeProofParams.BitLength
	default:
		return nil, errors.New("public parameters carry no range proof parameters")
	}
	if kappa == 0 || kappa > 64 {
		return nil, errors.Errorf("unsupported range bit length %d", kappa)
	}

	ipkAny, err := (&aries.Issuer{Curve: curve}).NewPublicKeyFromBytes(ipkEntry.PublicKey, idemixAttributes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse the Idemix issuer public key")
	}
	ipk, ok := ipkAny.(*aries.IssuerPublicKey)
	if !ok {
		return nil, errors.Errorf("unexpected issuer public key type %T", ipkAny)
	}

	p := &Params{Bits: int(kappa), curve: curve}
	p.gens = make([]bls12381.G1Affine, 16)
	for i, g := range []*mathlib.G1{
		pp.PedersenGenerators[0], pp.PedersenGenerators[1], pp.PedersenGenerators[2],
		ipk.PKwG.H0, ipk.PKwG.H[0], ipk.PKwG.H[1], ipk.PKwG.H[2], ipk.PKwG.H[3], ipk.PKwG.H[4],
	} {
		if p.gens[i], err = toAffine(g); err != nil {
			return nil, err
		}
	}
	if p.g1, err = toAffine(curve.GenG1); err != nil {
		return nil, err
	}
	if _, err := p.w.SetBytes(ipk.PK.PointG2.Bytes()); err != nil {
		return nil, errors.Wrap(err, "failed to decode the issuer key")
	}
	if _, err := p.g2.SetBytes(curve.GenG2.Bytes()); err != nil {
		return nil, errors.Wrap(err, "failed to decode the G2 generator")
	}
	p.logN = bits.Len(uint(numFieldSlots(p.Bits) - 1))
	p.extrap = make([][]fr.Element, p.Bits)
	for l := 1; l <= p.Bits; l++ {
		var x fr.Element
		x.SetUint64(uint64(p.Bits + l))
		p.extrap[l-1] = lagrange(x, p.Bits)
	}

	return p, nil
}

// Curve returns the curve of the token and Idemix public parameters.
func (p *Params) Curve() *mathlib.Curve { return p.curve }

// Setup is the aggregation setup for a fixed number of transfers K: the pivot
// setup, whose commitment parameters depend on K.
type Setup struct {
	params *Params
	pivot  *pivot.Setup
	logK   int
}

// NewSetup builds the setup for aggregates of k transfers, k a power of two >= 2.
//
// The committed group witness holds only the 9 private slots, padded to c = 16 or
// 32, whichever makes log c + log K even, as the group commitment requires. The
// per-transfer public elements are not committed. The field commitment's matrix split is chosen so that
// its row half is even, which is what the fold phase needs. The field commitment's
// Pedersen generators are derived by hashing to the curve, so the setup is
// transparent.
func NewSetup(p *Params, k int) (*Setup, error) {
	if p == nil {
		return nil, errors.New("params are required")
	}
	if k < 2 || k&(k-1) != 0 {
		return nil, errors.Errorf("the number of transfers must be a power of two >= 2, got %d", k)
	}
	logK := bits.Len(uint(k)) - 1
	logC := 4
	if (logC+logK)%2 != 0 {
		logC = 5
	}
	sizes := pivot.Sizes{LogN: p.logN, LogC: logC, LogL: 4, LogK: logK}

	m := p.logN + logK
	m1 := m / 2
	if (m-m1)%2 != 0 {
		m1--
	}
	split := titan.Split{M: m, M1: m1}
	gens := make([]bls12381.G1Affine, split.Cols())
	for i := range gens {
		g := p.curve.HashToG1([]byte("lfdt-panurus.pivot-utxo.field-generator." + strconv.Itoa(i)))
		var err error
		if gens[i], err = toAffine(g); err != nil {
			return nil, err
		}
	}
	ps, err := pivot.NewSetup(sizes, gens, p.curve, pivot.SetupOptions{FieldSplit: &split})
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to build the pivot setup for %d transfers", k)
	}

	return &Setup{params: p, pivot: ps, logK: logK}, nil
}

// K returns the number of transfers the setup aggregates.
func (s *Setup) K() int { return 1 << s.logK }

// toAffine converts a mathlib point into a gnark affine point.
func toAffine(g *mathlib.G1) (bls12381.G1Affine, error) {
	var out bls12381.G1Affine
	if g == nil {
		return out, errors.New("point is nil")
	}
	if _, err := out.SetBytes(g.Bytes()); err != nil {
		return out, errors.Wrap(err, "failed to decode point")
	}

	return out, nil
}

// toFr converts a mathlib scalar into a field element.
func toFr(z *mathlib.Zr) fr.Element {
	var e fr.Element
	e.SetBytes(z.Bytes())

	return e
}
