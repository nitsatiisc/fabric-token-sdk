/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/sumcheck"
)

// EncodeCosets builds the coset-wise oracle the folding phase queries.
//
// # What a coset is
//
// A coset for a point y of the folded domain L^(2^ell) is
//
//	{ G(b, y, y^2, y^4, ...) : b in {0,1}^ell }
//
// -- boolean in the first ell coordinates, powers of y in the remaining m-ell.
// That set is what one consistency query needs, because folding the first ell
// variables at challenges r is exactly an inner product against eq(r, .) over it
// (see foldCoset).
//
// # Why this is not a regrouping of the flat codeword
//
// EncodeGroupOracle evaluates the power curve Ghat(x) = Gtilde(x, x^2, x^4, ...)
// at every x in L, so its entries are full power-curve points. The 2^ell roots of
// x^(2^ell) = y do sit in that array, at the strided positions
// {y, y + N/2^ell, y + 2N/2^ell, ...}, and they are the set a k-round fold depends
// on -- but the values there are Ghat(x), not G(b, powers(y)). Recovering the
// latter from the former costs the ell folding rounds, which is exactly the work a
// coset is supposed to save.
//
// So the oracle is built a different way: encode each slice separately. For every
// b in {0,1}^ell, restrict G to that b and encode the resulting (m-ell)-variable
// polynomial over the folded domain, giving 2^ell codewords of 2^(m-ell+logRate)
// points. The coset for y is then index y read across all of them.
//
// This is the construction the Titan paper describes and the reference
// implementation uses. Same total encoding work as one large FFT: 2^ell transforms
// of size 2^(m-ell+logRate).
//
// # Slice indexing
//
// The first ell variables are the LOW bits of the evaluation table index, so slice
// b is G[b], G[b + 2^ell], G[b + 2*2^ell], ... Both facts -- the slice stride and
// the resulting coset semantics -- are pinned by
// TestEncodeCosetsGivesSemanticCosets.
//
// Returns the leaves in folded-domain order, leaves[y] being the coset for
// L^(2^ell).Elements[y], each holding 2^ell points.
func EncodeCosets(G sumcheck.GroupPoly, dom *Domain, ell int) ([][]bls12381.G1Affine, *Domain, error) {
	if G == nil {
		return nil, nil, errors.WithMessage(ErrNilPolynomial, "cannot encode cosets")
	}
	if dom == nil {
		return nil, nil, errors.WithMessage(ErrNilDomain, "cannot encode cosets")
	}

	m, err := numVarsOf(len(G))
	if err != nil {
		return nil, nil, err
	}
	if ell < 1 || ell > m {
		return nil, nil, errors.Wrapf(ErrInvalidCosetDim, "ell must be in [1, %d] for %d variables, got %d", m, m, ell)
	}
	if dom.LogSize < m {
		return nil, nil, errors.Wrapf(ErrDomainTooSmall, "domain 2^%d is smaller than the polynomial 2^%d", dom.LogSize, m)
	}

	// The slices live on m-ell variables, so they encode over the domain of the
	// same rate: 2^(m-ell+logRate) where logRate = dom.LogSize - m.
	logRate := dom.LogSize - m
	folded, err := NewDomain(m - ell + logRate)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to build the folded domain")
	}

	cosetSize := 1 << ell
	sub := 1 << (m - ell)

	// Encode each slice, then transpose into cosets. The transpose is what makes a
	// leaf contiguous in memory, which is what lets one Merkle opening answer one
	// query.
	slice := make(sumcheck.GroupPoly, sub)
	leaves := make([][]bls12381.G1Affine, folded.Size())
	for y := range leaves {
		leaves[y] = make([]bls12381.G1Affine, cosetSize)
	}

	for b := range cosetSize {
		for i := range sub {
			slice[i] = G[b+i*cosetSize]
		}

		codeword, err := EncodeGroupOracle(slice, folded)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "failed to encode slice %d of %d", b, cosetSize)
		}

		for y, v := range codeword {
			leaves[y][b] = v
		}
	}

	return leaves, folded, nil
}

// foldCoset folds one coset at the challenges r, returning the value the folded
// codeword holds at that coset's index.
//
// Because a coset is { G(b, powers(y)) : b in {0,1}^ell } and folding the first
// ell variables at r means substituting r for them, the fold is just
//
//	sum_b eq(r, b) * coset[b]
//
// a single MSM over 2^ell points. No per-round butterfly, no domain arithmetic,
// and nothing that depends on which round we are in -- which is the whole payoff
// of the coset layout over regrouping the flat codeword.
//
// The same identity checks the final reduced claim, so the verifier has one
// primitive rather than two (see verifyFold).
func foldCoset(coset []bls12381.G1Affine, eq []fr.Element) (bls12381.G1Affine, error) {
	if len(coset) != len(eq) {
		return bls12381.G1Affine{}, errors.Wrapf(ErrNumVarsMismatch,
			"coset holds %d points but the eq table has %d entries", len(coset), len(eq))
	}

	return msm(coset, eq)
}

// CosetCommitment is the Merkle commitment to a coset-wise oracle, together with
// the shape a verifier needs to check openings against it.
type CosetCommitment struct {
	// Root is the Merkle root over the cosets.
	Root []byte

	// NumVars is m, the number of variables of the committed group polynomial.
	NumVars int

	// Ell is the coset dimension: each leaf holds 2^Ell points.
	Ell int

	// LogDomain is the log size of the FOLDED domain, so NumLeaves = 2^LogDomain.
	LogDomain int

	// Fold is the configuration this oracle was built for, including the query
	// count the verifier must require.
	//
	// The query count lives in the commitment rather than being read off the
	// proof. Reading it from the proof would let a prover send a single query and
	// have the verifier accept it as the full set, silently reducing the proof's
	// soundness to a few bits -- the count is a security parameter, and a security
	// parameter the prover chooses is not one.
	Fold FoldConfig
}

// CosetOpeningHint is the prover state for a coset-wise oracle. It must not be
// given to a verifier: Leaves holds the whole oracle.
type CosetOpeningHint struct {
	// Leaves[y] is the coset for folded-domain point y, holding 2^Ell points.
	Leaves [][]bls12381.G1Affine

	// Folded is the domain the cosets are indexed by.
	Folded *Domain

	// Tree is the Merkle tree over Leaves.
	Tree *Tree
}

// CommitCosets builds and Merkle-commits the coset-wise oracle for G.
//
// This is the oracle the folding phase queries, and it is committed separately
// from the flat codeword CommitGroup produces because the two hold different
// values -- see EncodeCosets.
//
// The returned hint is prover state and must not be given to a verifier.
func CommitCosets(G sumcheck.GroupPoly, dom *Domain, ell int) (*CosetCommitment, *CosetOpeningHint, error) {
	leaves, folded, err := EncodeCosets(G, dom, ell)
	if err != nil {
		return nil, nil, err
	}

	tree, err := BuildTree(leaves)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to build the merkle tree over the cosets")
	}

	m, err := numVarsOf(len(G))
	if err != nil {
		return nil, nil, err
	}

	c := &CosetCommitment{
		Root:      tree.Root(),
		NumVars:   m,
		Ell:       ell,
		LogDomain: folded.LogSize,
	}
	hint := &CosetOpeningHint{Leaves: leaves, Folded: folded, Tree: tree}

	return c, hint, nil
}

// OpenCoset returns the coset at the given folded-domain index together with its
// Merkle path.
func (h *CosetOpeningHint) OpenCoset(index int) ([]bls12381.G1Affine, *MerkleProof, error) {
	if h == nil || h.Tree == nil {
		return nil, nil, errors.WithMessage(ErrNilTree, "cannot open a coset")
	}
	if index < 0 || index >= len(h.Leaves) {
		return nil, nil, errors.Wrapf(ErrLeafIndexOutOfRange, "index %d is not in [0, %d)", index, len(h.Leaves))
	}

	proof, err := h.Tree.Prove(index)
	if err != nil {
		return nil, nil, err
	}

	return h.Leaves[index], proof, nil
}
