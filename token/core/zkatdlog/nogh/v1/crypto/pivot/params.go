/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pivot

import (
	mathlib "github.com/IBM/mathlib"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/titan"
)

// Sizes are the log2 dimensions of an aggregate: n field slots and c group slots
// per instance, l public generators, and K instances. Every dimension is a power of
// two; callers pad to it.
type Sizes struct {
	LogN int
	LogC int
	LogL int
	LogK int
}

// N returns the number of field slots per instance.
func (s Sizes) N() int { return 1 << s.LogN }

// C returns the number of group slots per instance.
func (s Sizes) C() int { return 1 << s.LogC }

// L returns the number of public generators.
func (s Sizes) L() int { return 1 << s.LogL }

// K returns the number of instances.
func (s Sizes) K() int { return 1 << s.LogK }

// validate rejects sizes the protocol cannot run at.
//
// Every dimension needs at least one variable, since each is the variable set of
// some sum-check. The group commitment covers log c + log K variables and the group
// PCS requires that to be even; stating it here turns a confusing setup error into
// a parameter-selection one.
func (s Sizes) validate() error {
	if s.LogN < 1 || s.LogC < 1 || s.LogL < 1 || s.LogK < 1 {
		return errors.Wrapf(ErrInvalidSizes, "every dimension needs at least one variable, got %+v", s)
	}
	if (s.LogC+s.LogK)%2 != 0 {
		return errors.Wrapf(ErrInvalidSizes,
			"log c + log K must be even for the group commitment, got %d + %d", s.LogC, s.LogK)
	}

	return nil
}

// SetupOptions are the commitment parameters a caller may override. The zero value
// takes the Titan defaults.
type SetupOptions struct {
	// FieldSplit is the matrix split of the field commitment over log n + log K
	// variables. Nil takes titan.DefaultMatrixSplit, which only folds when that
	// count is a multiple of four; other counts need an explicit split.
	FieldSplit *titan.Split
	// FieldFold and GroupFold are the folding configurations; the zero value takes
	// the Titan default for the size.
	FieldFold titan.FoldConfig
	GroupFold titan.FoldConfig
}

// Setup holds the public parameters shared by provers and verifiers: the sizes and
// the two commitment setups. Build it once with NewSetup.
type Setup struct {
	sizes Sizes
	curve *mathlib.Curve
	field *titan.FieldSetup
	group *titan.GroupSetup
}

// NewSetup builds the public parameters for aggregates of the given sizes.
//
// gens are the Pedersen generators of the field commitment; it needs as many as
// the field split has columns. curve is used for the Fiat-Shamir transcript and the
// commitments.
func NewSetup(sizes Sizes, gens []bls12381.G1Affine, curve *mathlib.Curve, opts SetupOptions) (*Setup, error) {
	if curve == nil {
		return nil, errors.Wrap(ErrInvalidSizes, "curve is required")
	}
	if err := sizes.validate(); err != nil {
		return nil, err
	}

	split := titan.DefaultMatrixSplit(sizes.LogN + sizes.LogK)
	if opts.FieldSplit != nil {
		split = *opts.FieldSplit
	}
	if split.M != sizes.LogN+sizes.LogK {
		return nil, errors.Wrapf(ErrInvalidSizes,
			"field split is for %d variables, the field commitment has %d", split.M, sizes.LogN+sizes.LogK)
	}
	field, err := titan.NewFieldSetupWithSplit(split, gens, curve, opts.FieldFold)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to build the field commitment setup")
	}
	group, err := titan.NewGroupSetup(sizes.LogC+sizes.LogK, curve, opts.GroupFold)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to build the group commitment setup")
	}

	return &Setup{sizes: sizes, curve: curve, field: field, group: group}, nil
}

// Sizes returns the sizes the setup was built for.
func (s *Setup) Sizes() Sizes { return s.sizes }

// Curve returns the curve used for transcripts and commitments.
func (s *Setup) Curve() *mathlib.Curve { return s.curve }

// SparseEntry is one non-zero entry of a sparse public matrix.
type SparseEntry struct {
	Row int
	Col int
	Val fr.Element
}

// LinearEntry is one non-zero coefficient of an affine form: Val times w[Col].
type LinearEntry struct {
	Col int
	Val fr.Element
}

// AffineForm is L(w) = sum_i Coeffs[i].Val * w[Coeffs[i].Col] + Const.
type AffineForm struct {
	Coeffs []LinearEntry
	Const  fr.Element
}

// Monomial is Coeff * prod_{k in Vars} Z_k, where Z_k is the value of the k-th
// affine form. A repeated index raises that form to a power; empty Vars is a
// constant.
type Monomial struct {
	Coeff fr.Element
	Vars  []int
}

// Relation is the public part of the pivot relation:
//
//	G0 + sum_s (Alpha_s + (B w)_s) g_s + sum_t (AlphaPub_t + (BPub w)_t) x_t
//	   + sum_i (Gamma w)_i G_i                                          = 0_G
//	sum_m Phi[m].Coeff * prod_{k in Phi[m].Vars} Forms[k](w)          = 0_F
//
// g is the private group witness and x the instance's row of the statement's public
// table. B is c x n, BPub is cp x n and Gamma is l x n, all given by their non-zero
// entries. AlphaPub and BPub must be empty when the statement has no public table.
// An empty Phi means there is no field constraint, and SC3 is skipped.
type Relation struct {
	Alpha    []fr.Element
	B        []SparseEntry
	AlphaPub []fr.Element
	BPub     []SparseEntry
	Gamma    []SparseEntry
	G        []bls12381.G1Affine
	G0       bls12381.G1Affine
	Forms    []AffineForm
	Phi      []Monomial
}

// validate checks that every index is in range for the sizes and for a public table
// of cp columns.
func (r *Relation) validate(s Sizes, cp int) error {
	if r == nil {
		return errors.Wrap(ErrInvalidRelation, "relation is required")
	}
	if len(r.Alpha) != s.C() {
		return errors.Wrapf(ErrInvalidRelation, "alpha has %d entries, need c = %d", len(r.Alpha), s.C())
	}
	if len(r.G) != s.L() {
		return errors.Wrapf(ErrInvalidRelation, "G has %d generators, need l = %d", len(r.G), s.L())
	}
	for i, e := range r.B {
		if e.Row < 0 || e.Row >= s.C() || e.Col < 0 || e.Col >= s.N() {
			return errors.Wrapf(ErrInvalidRelation, "B entry %d at (%d, %d) is outside %d x %d", i, e.Row, e.Col, s.C(), s.N())
		}
	}
	if len(r.AlphaPub) != cp {
		return errors.Wrapf(ErrInvalidRelation, "AlphaPub has %d entries, the public table has %d columns", len(r.AlphaPub), cp)
	}
	for i, e := range r.BPub {
		if e.Row < 0 || e.Row >= cp || e.Col < 0 || e.Col >= s.N() {
			return errors.Wrapf(ErrInvalidRelation, "BPub entry %d at (%d, %d) is outside %d x %d", i, e.Row, e.Col, cp, s.N())
		}
	}
	for i, e := range r.Gamma {
		if e.Row < 0 || e.Row >= s.L() || e.Col < 0 || e.Col >= s.N() {
			return errors.Wrapf(ErrInvalidRelation, "Gamma entry %d at (%d, %d) is outside %d x %d", i, e.Row, e.Col, s.L(), s.N())
		}
	}
	for k, f := range r.Forms {
		for _, e := range f.Coeffs {
			if e.Col < 0 || e.Col >= s.N() {
				return errors.Wrapf(ErrInvalidRelation, "form %d refers to column %d, n = %d", k, e.Col, s.N())
			}
		}
	}
	for m, mono := range r.Phi {
		for _, v := range mono.Vars {
			if v < 0 || v >= len(r.Forms) {
				return errors.Wrapf(ErrInvalidRelation, "monomial %d refers to form %d, have %d", m, v, len(r.Forms))
			}
		}
	}

	return nil
}

// phiDegree returns the total degree of Phi.
func (r *Relation) phiDegree() int {
	d := 0
	for _, m := range r.Phi {
		if len(m.Vars) > d {
			d = len(m.Vars)
		}
	}

	return d
}

// hasFieldConstraint reports whether SC3 runs.
func (r *Relation) hasFieldConstraint() bool { return len(r.Phi) > 0 }

// Statement is the per-aggregate public input.
//
// Public is the table of per-instance public group elements: Public[k] is instance
// k's row x. These are the group elements that differ per instance but are known
// to the verifier -- commitments, pseudonyms -- and they are NOT committed: the
// relation reads them through AlphaPub and BPub, and the verifier evaluates the
// table itself (one MSM over all of it) where the protocol needs it. Every row has
// the same power-of-two width cp >= 2, or Public is nil.
//
// RevealCols names columns of the private H whose tau-aggregate
// sum_k eq(k, tau) H[k][col] the proof discloses, for checks a caller runs outside
// the relation. Verify returns them.
type Statement struct {
	Public     [][]bls12381.G1Affine
	RevealCols []int
}

// publicWidth returns cp, the width of the public table, or 0 without one.
func (st *Statement) publicWidth() int {
	if st == nil || len(st.Public) == 0 {
		return 0
	}

	return len(st.Public[0])
}

// validate checks the statement against the sizes.
func (st *Statement) validate(s Sizes) error {
	if st == nil {
		return nil
	}
	if st.Public != nil {
		if len(st.Public) != s.K() {
			return errors.Wrapf(ErrInvalidStatement, "the public table has %d rows, need K = %d", len(st.Public), s.K())
		}
		cp := st.publicWidth()
		if cp < 2 || cp&(cp-1) != 0 {
			return errors.Wrapf(ErrInvalidStatement, "the public table's width must be a power of two >= 2, got %d", cp)
		}
		for k, row := range st.Public {
			if len(row) != cp {
				return errors.Wrapf(ErrInvalidStatement, "public row %d has %d entries, row 0 has %d", k, len(row), cp)
			}
		}
	}
	for _, col := range st.RevealCols {
		if col < 0 || col >= s.C() {
			return errors.Wrapf(ErrInvalidStatement, "revealed column %d is outside c = %d", col, s.C())
		}
	}

	return nil
}

// Witness is the prover's private input: W[k] is the field witness of instance k
// and H[k] its group witness, already padded to n and c.
type Witness struct {
	W [][]fr.Element
	H [][]bls12381.G1Affine
}

// validate checks the witness dimensions.
func (w *Witness) validate(s Sizes) error {
	if w == nil {
		return errors.Wrap(ErrInvalidWitness, "witness is required")
	}
	if len(w.W) != s.K() || len(w.H) != s.K() {
		return errors.Wrapf(ErrInvalidWitness, "need K = %d instances, have %d field and %d group rows", s.K(), len(w.W), len(w.H))
	}
	for k := range w.W {
		if len(w.W[k]) != s.N() {
			return errors.Wrapf(ErrInvalidWitness, "instance %d has %d field slots, need n = %d", k, len(w.W[k]), s.N())
		}
		if len(w.H[k]) != s.C() {
			return errors.Wrapf(ErrInvalidWitness, "instance %d has %d group slots, need c = %d", k, len(w.H[k]), s.C())
		}
	}

	return nil
}
