/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"
)

// Split is the outer division of an m-variable multilinear into the matrix form the
// two legs run over: M1 column variables and M - M1 row variables.
//
// The row half is the group multilinear G -- one Pedersen commitment per row -- so
// M - M1 is what the folding phase and the evaluation domain are sized by, and M1 is
// what leg 2 (the CSP inner product) runs over.
//
// # Why this is a parameter and not m/2
//
// The reference implementation treats the split as a tuned free parameter
// (TitanSetupConfig.m1) and ships asymmetric configurations: m1 = 8 at m = 20, where
// a square split would force 10. The two halves have genuinely different costs, so
// the optimum is not at the midpoint in general.
//
// # Why the default is m/2 here, where the reference uses m/2 - 2
//
// The reference folds the generator oracle as well (its l2), so its m2 = m - m1 half
// is itself compressed and a larger m2 is cheap. This package does NOT fold leg 2 --
// that is the deferred O(n^(1/4)) layer -- so every extra variable in the column half
// is paid in full as a linear CSP cost. DefaultSplit therefore keeps the column half
// as small as a balanced split allows.
//
// Revisit this default when leg 2 folding lands, not before: it is a consequence of
// what is implemented, not a disagreement with the reference.
type Split struct {
	// M is the number of variables of the field multilinear.
	M int
	// M1 is the number of COLUMN variables, so the matrix has 2^M1 columns and leg 2
	// runs over M1 variables.
	M1 int
}

// DefaultMatrixSplit returns the balanced split of an m-variable multilinear.
//
// Named to distinguish it from DefaultSplit in groupsumcheck.go, which returns the
// sum-check prover's ell -- an unrelated parameter that happens also to default to
// m/2.
//
// For even m this is the square 2^(m/2) x 2^(m/2) form. For odd m = 2s+1 a square
// split does not exist, so the extra variable goes to the *rows*: 2^(s+1) rows of 2^s
// columns. Putting it on the rows rather than the columns keeps the row MSMs shorter
// and gives the group multilinear one more variable, which is the cheaper side to
// grow -- group operations dominate. The choice is arbitrary but must be fixed, since
// prover and verifier have to agree on the shape.
func DefaultMatrixSplit(m int) Split { return Split{M: m, M1: m / 2} }

// RowVars returns the number of row variables, M - M1.
//
// This is the group multilinear's variable count, and therefore what FoldConfig is
// validated against and what the evaluation domain is sized by -- not M. Sizing the
// domain by M instead oversizes it by 2^M1 and nothing functional notices; see
// TestPCSSetupSizesTheDomainByTheFoldedHalf.
func (s Split) RowVars() int { return s.M - s.M1 }

// ColVars returns the number of column variables, M1.
func (s Split) ColVars() int { return s.M1 }

// Rows returns the matrix row count, 2^(M - M1).
func (s Split) Rows() int { return 1 << s.RowVars() }

// Cols returns the matrix column count, 2^M1, which is also the number of Pedersen
// generators a field commitment needs.
func (s Split) Cols() int { return 1 << s.M1 }

// Validate checks that the split describes a usable matrix form.
//
// This is the COMMIT-time contract, and it is deliberately weaker than what folding
// needs. A matrix only requires that the two halves multiply back to 2^M, so the
// rules here are that M is positive and that M1 leaves a whole number of variables
// on each side. Committing a field polynomial at an odd row half is perfectly well
// defined -- it produces 2^RowVars Pedersen commitments like any other shape -- and
// this package did exactly that before the split became a parameter.
//
// This is also all the fold needs from a split: any row half, odd or even, can carry
// a fold, whose own constraints live in FoldConfig.Validate. An earlier version had a
// separate ValidateForFold demanding an EVEN row half; that rule was not needed for
// correctness and was removed (see docs/crypto/titan.md, section 13.10).
//
// M1 == 0 is allowed only at M == 1, the degenerate 2x1 matrix, because
// matrixShape(1) produced it before and no configuration can fold it anyway.
func (s Split) Validate() error {
	if s.M <= 0 {
		return errors.Wrapf(ErrInvalidMatrixSplit, "number of variables must be positive, got %d", s.M)
	}
	if s.M == 1 && s.M1 == 0 {
		return nil
	}
	if s.M1 <= 0 || s.M1 >= s.M {
		return errors.Wrapf(ErrInvalidMatrixSplit,
			"column variables must be in [1, %d] for %d variables, got %d", s.M-1, s.M, s.M1)
	}

	return nil
}
