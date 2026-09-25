/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package titan

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"
	"github.com/stretchr/testify/require"

	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/rp/csp"
	"github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/sumcheck"
)

// foldTestSetup is one complete folding instance: a committed oracle and the claim
// the folding phase is supposed to close.
type foldTestSetup struct {
	G     sumcheck.GroupPoly
	cfg   FoldConfig
	alpha []fr.Element
	claim bls12381.G1Affine
	com   *CosetCommitment
	hint  *CosetOpeningHint
}

// foldTranscript opens a fresh transcript for the folding phase alone.
//
// The production path continues the group sum-check's transcript. These tests
// exercise the folding phase in isolation, so they open their own; the two sides
// of every test use the same construction, which is what transcript agreement
// requires.
func foldTranscript(t *testing.T) *csp.Transcript {
	t.Helper()

	tr := &csp.Transcript{Curve: testCurve()}
	tr.InitHasherWithDomain("TitanFoldTest")

	return tr
}

// newFoldSetup builds a random instance with a small query count, so the tests
// stay fast while still exercising the query path. Soundness-relevant query counts
// are checked in foldconfig_test.go, not here.
func newFoldSetup(t *testing.T, m, ell, queries int) *foldTestSetup {
	t.Helper()

	cfg := FoldConfig{Ell: ell, LogRate: DefaultLogRate, Queries: queries, Regime: Capacity}
	require.NoError(t, cfg.Validate(m))

	dom, err := NewDomain(m + cfg.LogRate)
	require.NoError(t, err)

	G := randomGroupPoly(t, m)

	com, hint, err := CommitCosets(G, dom, ell)
	require.NoError(t, err)

	alpha := make([]fr.Element, m)
	for i := range alpha {
		_, err := alpha[i].SetRandom()
		require.NoError(t, err)
	}

	// The honest claim: sum_x eq(alpha, x) * G(x).
	claim, err := msm(G, eqTable(alpha))
	require.NoError(t, err)

	return &foldTestSetup{G: G, cfg: cfg, alpha: alpha, claim: claim, com: com, hint: hint}
}

func (s *foldTestSetup) prove(t *testing.T) *FoldProof {
	t.Helper()

	p, err := proveFold(foldTranscript(t), s.G, s.hint, s.cfg, s.alpha, &s.claim)
	require.NoError(t, err)

	return p
}

func (s *foldTestSetup) verify(t *testing.T, p *FoldProof) error {
	t.Helper()

	return verifyFold(foldTranscript(t), s.com, s.cfg, s.alpha, &s.claim, p)
}

// TestFoldRoundTrip is the acceptance case, across every legal ell for each even m.
func TestFoldRoundTrip(t *testing.T) {
	t.Parallel()

	for _, m := range []int{4, 6, 8, 10} {
		for ell := 1; ell <= m/2; ell++ {
			s := newFoldSetup(t, m, ell, 3)
			require.NoError(t, s.verify(t, s.prove(t)), "m=%d ell=%d", m, ell)
		}
	}
}

// TestFoldReducedPolyMatchesFieldFold cross-checks the reduced polynomial against
// an independent computation: folding the ORIGINAL polynomial at the transcript's
// challenges. This catches a prover that sends a reduced polynomial satisfying the
// round checks without being the actual fold.
func TestFoldReducedPolyMatchesFieldFold(t *testing.T) {
	t.Parallel()

	const m, ell = 8, 3
	s := newFoldSetup(t, m, ell, 3)
	p := s.prove(t)

	// Replay the verifier's transcript to recover the challenges.
	tr := foldTranscript(t)
	absorbPoint(tr, &s.claim)
	want := s.G
	for round := range ell {
		evals := p.Rounds[round]
		for i := range evals {
			absorbPoint(tr, &evals[i])
		}
		r, err := squeezeScalar(tr)
		require.NoError(t, err)
		want, err = foldFirstGroup(want, &r)
		require.NoError(t, err)
	}

	require.Len(t, p.Reduced, len(want))
	for i := range want {
		require.True(t, p.Reduced[i].Equal(&want[i]), "coefficient %d", i)
	}
}

// TestFoldRejectsALyingProver is the test step 5 exists for.
//
// The prover commits G, then runs the whole folding phase over a DIFFERENT
// polynomial G'. The claim it proves is G's honest claim, and it is a genuine
// sum-check proof -- every round check passes and the reduced claim opens
// correctly, because the folding is internally consistent. Only the consistency
// queries can tell that the oracle under the root is not the polynomial that was
// folded.
//
// Before step 5 this attack succeeded: VerifyGroupEval returned an opening and
// nothing checked it against the root. If this test ever passes verification, the
// folding phase has stopped binding the proof to the commitment.
//
// This case is caught by the Merkle check, because the openings come from the
// wrong tree. The strictly harder attack -- genuine openings of the RIGHT tree
// against a foreign fold -- is TestFoldRejectsAForeignFoldWithGenuineOpenings,
// and that is the test which pins the coset-fold identity itself.
func TestFoldRejectsALyingProver(t *testing.T) {
	t.Parallel()

	const m, ell = 6, 2
	s := newFoldSetup(t, m, ell, DefaultSecurityBits/DefaultLogRate)

	// A different polynomial, committed nowhere.
	other := randomGroupPoly(t, m)
	otherClaim, err := msm(other, eqTable(s.alpha))
	require.NoError(t, err)

	dom, err := NewDomain(m + s.cfg.LogRate)
	require.NoError(t, err)
	_, otherHint, err := CommitCosets(other, dom, ell)
	require.NoError(t, err)

	// A perfectly valid fold proof -- for the wrong polynomial.
	bad, err := proveFold(foldTranscript(t), other, otherHint, s.cfg, s.alpha, &otherClaim)
	require.NoError(t, err)

	// It verifies against its own commitment, so the proof itself is well formed.
	require.NoError(t, verifyFold(foldTranscript(t), otherCommitment(t, other, dom, ell), s.cfg, s.alpha, &otherClaim, bad))

	// Against the committed root, it must fail -- and fail on the query check,
	// not on a shape check that would mask the real reason.
	err = verifyFold(foldTranscript(t), s.com, s.cfg, s.alpha, &otherClaim, bad)
	require.ErrorIs(t, err, ErrCosetOpeningInvalid)
}

// TestFoldRejectsAForeignFoldWithGenuineOpenings is the sharpest soundness case,
// and the one that pins the coset-fold identity rather than the Merkle tree.
//
// The prover holds the honest oracle for G and opens GENUINE cosets of it, with
// valid authentication paths under the real committed root. What it lies about is
// the folding: the round messages, the challenges they induce and the reduced
// polynomial all come from a different polynomial G'. So:
//
//   - the round checks pass (the folding of G' is internally consistent),
//   - the reduced claim opens correctly (it is G”s honest residual),
//   - every Merkle path verifies (the cosets really are under the root).
//
// The only thing left that can reject it is check 3: the opened coset of G must
// fold to the reduced codeword, and the reduced codeword here is G”s. A mutation
// that deletes check 3 leaves every other test in this file green and is caught
// only here -- which is why this test exists separately from
// TestFoldRejectsALyingProver.
func TestFoldRejectsAForeignFoldWithGenuineOpenings(t *testing.T) {
	t.Parallel()

	const m, ell = 6, 2
	s := newFoldSetup(t, m, ell, 4)

	// A different polynomial, and its honest claim and oracle.
	other := randomGroupPoly(t, m)
	otherClaim, err := msm(other, eqTable(s.alpha))
	require.NoError(t, err)

	dom, err := NewDomain(m + s.cfg.LogRate)
	require.NoError(t, err)
	_, otherHint, err := CommitCosets(other, dom, ell)
	require.NoError(t, err)

	// Fold G'. The transcript is the construction both sides use, so the
	// challenges and sampled indices are the ones the verifier will recompute.
	bad, err := proveFold(foldTranscript(t), other, otherHint, s.cfg, s.alpha, &otherClaim)
	require.NoError(t, err)

	// Now swap in genuine openings of the COMMITTED oracle at the very same
	// indices. The forged proof then carries real paths under the real root.
	for _, q := range bad.Queries {
		leaf, path, err := s.hint.OpenCoset(q.Index)
		require.NoError(t, err)
		require.True(t, VerifyMerkleProof(s.com.Root, leaf, path),
			"the substituted opening must be genuine, or this test proves nothing")
		q.Leaf = append([]bls12381.G1Affine(nil), leaf...)
		q.Path = path
	}

	// Sanity: the parts of the proof that are not check 3 really do pass. If the
	// round or reduced-claim checks were what rejected this, the test would not be
	// exercising the coset-fold identity at all.
	require.NoError(t, verifyFoldRoundsOnly(t, s, &otherClaim, bad),
		"rounds and reduced claim must be internally consistent")

	err = verifyFold(foldTranscript(t), s.com, s.cfg, s.alpha, &otherClaim, bad)
	require.ErrorIs(t, err, ErrCosetOpeningInvalid)
}

// verifyFoldRoundsOnly runs checks 1 and 2 -- round consistency and the reduced
// claim -- without the consistency queries.
//
// It exists so TestFoldRejectsAForeignFoldWithGenuineOpenings can assert that the
// forged proof is rejected *specifically* by check 3, rather than tripping over an
// earlier check and only appearing to test it.
func verifyFoldRoundsOnly(t *testing.T, s *foldTestSetup, claim *bls12381.G1Affine, p *FoldProof) error {
	t.Helper()

	tr := foldTranscript(t)
	absorbPoint(tr, claim)

	expected := *claim
	eqCur := eqTable(s.alpha)

	for round := range s.cfg.Ell {
		evals := p.Rounds[round]

		var got bls12381.G1Jac
		got.FromAffine(&evals[0])
		got.AddMixed(&evals[1])
		var gotAff bls12381.G1Affine
		gotAff.FromJacobian(&got)
		if !gotAff.Equal(&expected) {
			return errors.Wrapf(ErrFoldRoundMismatch, "round %d", round+1)
		}

		for i := range evals {
			absorbPoint(tr, &evals[i])
		}
		r, err := squeezeScalar(tr)
		require.NoError(t, err)

		expected, err = interpolateGroupAt(&evals, &r)
		require.NoError(t, err)
		eqCur = foldFirstField(eqCur, &r)
	}

	got, err := msm(p.Reduced, eqCur)
	require.NoError(t, err)
	if !got.Equal(&expected) {
		return ErrReducedClaimMismatch
	}

	return nil
}

func otherCommitment(t *testing.T, G sumcheck.GroupPoly, dom *Domain, ell int) *CosetCommitment {
	t.Helper()

	com, _, err := CommitCosets(G, dom, ell)
	require.NoError(t, err)

	return com
}

// TestFoldSoundnessNegatives walks the tampering cases. Each mutates a valid proof
// in exactly one way and requires rejection.
func TestFoldSoundnessNegatives(t *testing.T) {
	t.Parallel()

	const m, ell = 6, 2

	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, s *foldTestSetup, p *FoldProof)
		target error
	}{
		{
			name: "tampered leaf",
			mutate: func(t *testing.T, s *foldTestSetup, p *FoldProof) {
				p.Queries[0].Leaf[0].Add(&p.Queries[0].Leaf[0], &p.Queries[0].Leaf[0])
			},
			target: ErrCosetOpeningInvalid,
		},
		{
			name: "tampered merkle path",
			mutate: func(t *testing.T, s *foldTestSetup, p *FoldProof) {
				p.Queries[0].Path.Siblings[0][0] ^= 0xff
			},
			target: ErrCosetOpeningInvalid,
		},
		{
			name: "wrong query index",
			mutate: func(t *testing.T, s *foldTestSetup, p *FoldProof) {
				p.Queries[0].Index = (p.Queries[0].Index + 1) % (1 << s.com.LogDomain)
			},
			target: ErrCosetOpeningInvalid,
		},
		{
			name: "swapped queries",
			mutate: func(t *testing.T, s *foldTestSetup, p *FoldProof) {
				p.Queries[0], p.Queries[1] = p.Queries[1], p.Queries[0]
			},
			target: ErrCosetOpeningInvalid,
		},
		{
			name: "permuted leaf",
			mutate: func(t *testing.T, s *foldTestSetup, p *FoldProof) {
				l := p.Queries[0].Leaf
				l[0], l[len(l)-1] = l[len(l)-1], l[0]
			},
			target: ErrCosetOpeningInvalid,
		},
		{
			name: "tampered reduced coefficient",
			mutate: func(t *testing.T, s *foldTestSetup, p *FoldProof) {
				p.Reduced[0].Add(&p.Reduced[0], &p.Reduced[0])
			},
			target: ErrReducedClaimMismatch,
		},
		{
			name: "reduced polynomial replaced wholesale",
			mutate: func(t *testing.T, s *foldTestSetup, p *FoldProof) {
				p.Reduced = randomGroupPoly(t, m-ell)
			},
			target: ErrReducedClaimMismatch,
		},
		{
			name: "reduced polynomial truncated",
			mutate: func(t *testing.T, s *foldTestSetup, p *FoldProof) {
				p.Reduced = p.Reduced[:len(p.Reduced)-1]
			},
			target: ErrReducedPolyMismatch,
		},
		{
			name: "tampered round message",
			mutate: func(t *testing.T, s *foldTestSetup, p *FoldProof) {
				p.Rounds[0][0].Add(&p.Rounds[0][0], &p.Rounds[0][0])
			},
			target: ErrFoldRoundMismatch,
		},
		{
			name: "dropped round",
			mutate: func(t *testing.T, s *foldTestSetup, p *FoldProof) {
				p.Rounds = p.Rounds[:len(p.Rounds)-1]
			},
			target: ErrFoldRoundMismatch,
		},
		{
			name: "dropped query",
			mutate: func(t *testing.T, s *foldTestSetup, p *FoldProof) {
				p.Queries = p.Queries[:len(p.Queries)-1]
			},
			target: ErrQueryCountMismatch,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := newFoldSetup(t, m, ell, 4)
			p := s.prove(t)
			require.NoError(t, s.verify(t, p), "the unmutated proof must verify")

			tc.mutate(t, s, p)
			require.ErrorIs(t, s.verify(t, p), tc.target)
		})
	}
}

// TestFoldRejectsAWrongClaim pins that the folding phase is about a specific
// claim: the same proof against a different asserted value must fail.
func TestFoldRejectsAWrongClaim(t *testing.T) {
	t.Parallel()

	s := newFoldSetup(t, 6, 2, 3)
	p := s.prove(t)

	var wrong bls12381.G1Affine
	wrong.Add(&s.claim, &s.claim)

	require.Error(t, verifyFold(foldTranscript(t), s.com, s.cfg, s.alpha, &wrong, p))
}

// TestFoldRejectsAWrongAlpha pins that alpha is bound. A permuted alpha describes
// a different claim, and eq factorizes over any split, so this is the shape of
// error that self-verifies if alpha is not actually used.
func TestFoldRejectsAWrongAlpha(t *testing.T) {
	t.Parallel()

	s := newFoldSetup(t, 6, 2, 3)
	p := s.prove(t)

	other := make([]fr.Element, len(s.alpha))
	copy(other, s.alpha)
	other[0], other[len(other)-1] = other[len(other)-1], other[0]

	require.NoError(t, verifyFold(foldTranscript(t), s.com, s.cfg, s.alpha, &s.claim, p),
		"the honest alpha must verify")
	require.Error(t, verifyFold(foldTranscript(t), s.com, s.cfg, other, &s.claim, p),
		"a permuted alpha must not verify")
}

// TestFoldValidation covers the argument checks.
func TestFoldValidation(t *testing.T) {
	t.Parallel()

	s := newFoldSetup(t, 6, 2, 3)
	p := s.prove(t)

	t.Run("prove without transcript", func(t *testing.T) {
		t.Parallel()
		_, err := proveFold(nil, s.G, s.hint, s.cfg, s.alpha, &s.claim)
		require.Error(t, err)
	})

	t.Run("prove without oracle", func(t *testing.T) {
		t.Parallel()
		_, err := proveFold(foldTranscript(t), s.G, nil, s.cfg, s.alpha, &s.claim)
		require.ErrorIs(t, err, ErrNilTree)
	})

	t.Run("prove without claim", func(t *testing.T) {
		t.Parallel()
		_, err := proveFold(foldTranscript(t), s.G, s.hint, s.cfg, s.alpha, nil)
		require.ErrorIs(t, err, ErrNilElement)
	})

	t.Run("prove with wrong alpha length", func(t *testing.T) {
		t.Parallel()
		_, err := proveFold(foldTranscript(t), s.G, s.hint, s.cfg, s.alpha[:1], &s.claim)
		require.ErrorIs(t, err, ErrNumVarsMismatch)
	})

	t.Run("verify without transcript", func(t *testing.T) {
		t.Parallel()
		require.Error(t, verifyFold(nil, s.com, s.cfg, s.alpha, &s.claim, p))
	})

	t.Run("verify without commitment", func(t *testing.T) {
		t.Parallel()
		require.Error(t, verifyFold(foldTranscript(t), nil, s.cfg, s.alpha, &s.claim, p))
	})

	t.Run("verify without proof", func(t *testing.T) {
		t.Parallel()
		require.ErrorIs(t, verifyFold(foldTranscript(t), s.com, s.cfg, s.alpha, &s.claim, nil), ErrNilProof)
	})

	t.Run("verify with mismatched ell", func(t *testing.T) {
		t.Parallel()
		cfg := s.cfg
		cfg.Ell = 1
		require.ErrorIs(t, verifyFold(foldTranscript(t), s.com, cfg, s.alpha, &s.claim, p), ErrInvalidFoldConfig)
	})

	t.Run("verify with wrong alpha length", func(t *testing.T) {
		t.Parallel()
		require.ErrorIs(t, verifyFold(foldTranscript(t), s.com, s.cfg, s.alpha[:1], &s.claim, p), ErrNumVarsMismatch)
	})
}

// TestFoldRoundMessageValidation covers the round-message helper's guards.
func TestFoldRoundMessageValidation(t *testing.T) {
	t.Parallel()

	G := randomGroupPoly(t, 3)

	_, err := foldRoundMessage(G, eqTable(make([]fr.Element, 2)))
	require.ErrorIs(t, err, ErrNumVarsMismatch)

	_, err = foldRoundMessage(G[:1], eqTable(nil))
	require.ErrorIs(t, err, ErrNotPowerOfTwo)
}

// TestEvalGroupWithFoldRoundTrip is the end-to-end sound path: commit with a coset
// oracle, prove, verify.
func TestEvalGroupWithFoldRoundTrip(t *testing.T) {
	t.Parallel()

	for _, m := range []int{4, 6, 8} {
		cfg, err := DefaultFoldConfig(m)
		require.NoError(t, err)
		cfg.Queries = 4 // keep the test fast; the count itself is pinned elsewhere

		dom, err := NewDomain(m + cfg.LogRate)
		require.NoError(t, err)

		G := randomGroupPoly(t, m)

		c, hint, err := CommitGroupWithFold(G, dom, 0, cfg)
		require.NoError(t, err)
		require.NotNil(t, c.Cosets)

		alpha := randomPoint(t, m)

		proof, sigma, err := hint.EvalGroup(testCurve(), alpha)
		require.NoError(t, err)
		require.NotNil(t, proof.Fold, "a commitment with a coset oracle must yield a fold proof")

		_, err = VerifyEvalGroup(testCurve(), c, alpha, &sigma, proof)
		require.NoError(t, err, "m=%d", m)
	}
}

// TestEvalGroupWithFoldIsSound is the end-to-end version of the attack: a proof
// built over a different polynomial must not verify against this commitment.
//
// This is the assertion the whole step exists to make true. Before the folding
// phase, VerifyEvalGroup accepted it.
func TestEvalGroupWithFoldIsSound(t *testing.T) {
	t.Parallel()

	const m = 6
	cfg, err := DefaultFoldConfig(m)
	require.NoError(t, err)
	cfg.Queries = 8

	dom, err := NewDomain(m + cfg.LogRate)
	require.NoError(t, err)

	G := randomGroupPoly(t, m)
	c, _, err := CommitGroupWithFold(G, dom, 0, cfg)
	require.NoError(t, err)

	// A different polynomial, honestly committed and honestly proved.
	other := randomGroupPoly(t, m)
	otherCom, otherHint, err := CommitGroupWithFold(other, dom, 0, cfg)
	require.NoError(t, err)

	alpha := randomPoint(t, m)
	proof, sigma, err := otherHint.EvalGroup(testCurve(), alpha)
	require.NoError(t, err)

	// It verifies against its own commitment...
	_, err = VerifyEvalGroup(testCurve(), otherCom, alpha, &sigma, proof)
	require.NoError(t, err)

	// ...and must not against ours.
	_, err = VerifyEvalGroup(testCurve(), c, alpha, &sigma, proof)
	require.Error(t, err)
}

// TestEvalGroupRejectsAMissingFoldProof pins that a prover cannot downgrade a
// sound commitment to an unsound opening by omitting the fold proof. That would be
// the easiest possible attack on this wiring.
func TestEvalGroupRejectsAMissingFoldProof(t *testing.T) {
	t.Parallel()

	const m = 6
	cfg, err := DefaultFoldConfig(m)
	require.NoError(t, err)
	cfg.Queries = 4

	dom, err := NewDomain(m + cfg.LogRate)
	require.NoError(t, err)

	G := randomGroupPoly(t, m)
	c, hint, err := CommitGroupWithFold(G, dom, 0, cfg)
	require.NoError(t, err)

	alpha := randomPoint(t, m)
	proof, sigma, err := hint.EvalGroup(testCurve(), alpha)
	require.NoError(t, err)

	proof.Fold = nil
	_, err = VerifyEvalGroup(testCurve(), c, alpha, &sigma, proof)
	require.ErrorIs(t, err, ErrNilProof)
}

// TestEvalGroupRejectsAReducedQueryCount pins that the query count is a security
// parameter the commitment fixes, not something the prover chooses. A proof
// carrying fewer queries than the commitment requires must be rejected even though
// every query it does carry is valid.
func TestEvalGroupRejectsAReducedQueryCount(t *testing.T) {
	t.Parallel()

	const m = 6
	cfg, err := DefaultFoldConfig(m)
	require.NoError(t, err)
	cfg.Queries = 8

	dom, err := NewDomain(m + cfg.LogRate)
	require.NoError(t, err)

	G := randomGroupPoly(t, m)
	c, hint, err := CommitGroupWithFold(G, dom, 0, cfg)
	require.NoError(t, err)

	alpha := randomPoint(t, m)
	proof, sigma, err := hint.EvalGroup(testCurve(), alpha)
	require.NoError(t, err)

	proof.Fold.Queries = proof.Fold.Queries[:1]
	_, err = VerifyEvalGroup(testCurve(), c, alpha, &sigma, proof)
	require.ErrorIs(t, err, ErrQueryCountMismatch)
}

// newFieldFoldFixture commits a random m-variable field polynomial WITH the coset
// oracle, so its Eval proof can be closed rather than only reduced.
//
// Note the fold configuration is relative to the ROW polynomial's variable count,
// not m: the folding phase operates on the tier-1 group polynomial G, which has one
// variable per row bit. Getting this wrong is a shape error the validation catches,
// but it is worth stating because m is the number that is in scope at the call.
//
// # Only m divisible by 4 is usable on the field path
//
// rowVars = m - m/2, so an even rowVars needs m divisible by 4: m=6 gives rowVars=3
// and DefaultFoldConfig rejects it. This is the even-m assumption composed with the
// matrix split, not a limitation of the folding itself, and it is pinned by
// TestFieldFoldRequiresMDivisibleByFour.
func newFieldFoldFixture(t *testing.T, m, queries int) (*evalFixture, FoldConfig) {
	t.Helper()

	rowVars := m - m/2
	cfg, err := DefaultFoldConfig(rowVars)
	require.NoError(t, err)
	cfg.Queries = queries

	f := randomFieldPoly(t, m)
	_, numCols := matrixShape(m)
	gens := testGenerators(t, numCols)

	dom, err := NewDomain(rowVars + cfg.LogRate)
	require.NoError(t, err)

	c, hint, err := CommitFieldWithFold(f, gens, dom, 0, cfg)
	require.NoError(t, err)
	require.NotNil(t, c.Cosets)

	curve := testCurve()
	cg, err := NewGenerators(curve, gens)
	require.NoError(t, err)

	return &evalFixture{
		curve: curve, f: f, gens: gens, dom: dom, c: c, hint: hint, cg: cg,
		alpha: randomPoint(t, m), m: m,
	}, cfg
}

// TestEvalWithFoldRoundTripAndMatchesDirectEvaluation is the field path's sound
// round trip, with the same two assertions the step-4 round trip makes: that
// verification accepts, and that sigma is the value the polynomial actually takes.
//
// The second assertion is the one that catches a swapped variable split, which
// self-verifies; see splitAlpha.
func TestEvalWithFoldRoundTripAndMatchesDirectEvaluation(t *testing.T) {
	t.Parallel()

	for _, m := range []int{4, 8, 12} {
		fx, _ := newFieldFoldFixture(t, m, 4)

		proof, sigma, err := fx.hint.Eval(fx.curve, fx.cg, fx.alpha)
		require.NoError(t, err)
		require.NotNil(t, proof.Fold, "a commitment with a coset oracle must yield a fold proof")

		_, err = VerifyEval(fx.curve, fx.c, fx.cg, fx.alpha, sigma, proof)
		require.NoError(t, err, "m=%d", m)

		want, err := fx.f.EvaluatePoint(fx.alpha)
		require.NoError(t, err)
		require.True(t, sigma.Equal(&want), "m=%d: sigma is not f(alpha)", m)
	}
}

// TestEvalWithFoldIsSound is the field path's end-to-end soundness assertion: an
// honest proof for a different polynomial must not verify against this commitment.
func TestEvalWithFoldIsSound(t *testing.T) {
	t.Parallel()

	const m = 8
	fx, cfg := newFieldFoldFixture(t, m, 8)

	// A different polynomial over the same generators, domain and point.
	other := randomFieldPoly(t, m)
	otherCom, otherHint, err := CommitFieldWithFold(other, fx.gens, fx.dom, 0, cfg)
	require.NoError(t, err)

	proof, sigma, err := otherHint.Eval(fx.curve, fx.cg, fx.alpha)
	require.NoError(t, err)

	// It verifies against its own commitment...
	_, err = VerifyEval(fx.curve, otherCom, fx.cg, fx.alpha, sigma, proof)
	require.NoError(t, err)

	// ...and must not against ours.
	_, err = VerifyEval(fx.curve, fx.c, fx.cg, fx.alpha, sigma, proof)
	require.Error(t, err)
}

// TestEvalRejectsAMissingFoldProof pins the downgrade attack on the field path.
func TestEvalRejectsAMissingFoldProof(t *testing.T) {
	t.Parallel()

	fx, _ := newFieldFoldFixture(t, 8, 4)

	proof, sigma, err := fx.hint.Eval(fx.curve, fx.cg, fx.alpha)
	require.NoError(t, err)

	proof.Fold = nil
	_, err = VerifyEval(fx.curve, fx.c, fx.cg, fx.alpha, sigma, proof)
	require.ErrorIs(t, err, ErrNilProof)
}

// TestEvalRejectsAForeignFoldProof pins that the fold proof is bound to this
// claim: a fold proof lifted from another polynomial's Eval must be rejected even
// though both legs of the host proof are honest.
func TestEvalRejectsAForeignFoldProof(t *testing.T) {
	t.Parallel()

	const m = 8
	fx, cfg := newFieldFoldFixture(t, m, 4)

	proof, sigma, err := fx.hint.Eval(fx.curve, fx.cg, fx.alpha)
	require.NoError(t, err)

	other := randomFieldPoly(t, m)
	_, otherHint, err := CommitFieldWithFold(other, fx.gens, fx.dom, 0, cfg)
	require.NoError(t, err)
	otherProof, _, err := otherHint.Eval(fx.curve, fx.cg, fx.alpha)
	require.NoError(t, err)

	proof.Fold = otherProof.Fold
	_, err = VerifyEval(fx.curve, fx.c, fx.cg, fx.alpha, sigma, proof)
	require.Error(t, err)
}

// TestEvalWithoutCosetsRejectsAFoldProof pins the other direction: a commitment
// with no coset oracle must not accept a proof that carries a folding phase.
// Accepting it would mean the verifier believed a check it never performed.
func TestEvalWithoutCosetsRejectsAFoldProof(t *testing.T) {
	t.Parallel()

	const m = 8
	fx, _ := newFieldFoldFixture(t, m, 4)
	proof, sigma, err := fx.hint.Eval(fx.curve, fx.cg, fx.alpha)
	require.NoError(t, err)

	plain := *fx.c
	plain.Cosets = nil
	_, err = VerifyEval(fx.curve, &plain, fx.cg, fx.alpha, sigma, proof)
	require.ErrorIs(t, err, ErrNilProof)
}

// TestFieldFoldRequiresMDivisibleByFour pins the constraint the field path inherits
// from composing the even-m assumption with the matrix split.
//
// The folding phase runs on the tier-1 group polynomial, which has rowVars = m-m/2
// variables, and FoldConfig requires an even count. So m=4,8,12 are foldable and
// m=2,6,10 are not -- a real restriction on CommitFieldWithFold, recorded here so
// it is a documented boundary rather than a surprise at the call site.
func TestFieldFoldRequiresMDivisibleByFour(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		m        int
		foldable bool
	}{
		{2, false}, {4, true}, {6, false}, {8, true}, {10, false}, {12, true},
	} {
		rowVars := tc.m - tc.m/2
		_, err := DefaultFoldConfig(rowVars)
		if tc.foldable {
			require.NoError(t, err, "m=%d (rowVars=%d) should be foldable", tc.m, rowVars)
		} else {
			require.ErrorIs(t, err, ErrInvalidFoldConfig, "m=%d (rowVars=%d) should not be", tc.m, rowVars)
		}
	}
}

// TestFoldChecksEveryQueryNotJustTheFirst pins that the verifier checks all Q
// consistency queries, by corrupting the LAST one.
//
// This exists because sampleQueryIndices is sequential: sampling Q-1 indices
// returns exactly the first Q-1 of the honest Q, so a verifier that looped over
// cfg.Queries-1 queries would agree with the honest prover on every one it looked
// at and accept. The len(proof.Queries) != cfg.Queries guard does not catch it --
// that guard bounds what the prover SENDS, and this is about what the verifier
// READS. A mutation truncating the verifier's loop survived the whole suite,
// because every other negative here tampers with query [0].
//
// The number of queries actually checked is the soundness parameter; silently
// checking one fewer costs bits that no honest-path test can see.
func TestFoldChecksEveryQueryNotJustTheFirst(t *testing.T) {
	t.Parallel()

	const m, ell, queries = 8, 2, 6
	s := newFoldSetup(t, m, ell, queries)

	// Corrupt each query position in turn -- including, crucially, the last.
	for pos := range queries {
		proof, err := proveFold(foldTranscript(t), s.G, s.hint, s.cfg, s.alpha, &s.claim)
		require.NoError(t, err)
		require.Len(t, proof.Queries, queries)

		q := proof.Queries[pos]
		q.Leaf[0].Add(&q.Leaf[0], &q.Leaf[0])

		err = verifyFold(foldTranscript(t), s.com, s.cfg, s.alpha, &s.claim, proof)
		require.ErrorIs(t, err, ErrCosetOpeningInvalid,
			"corrupting query %d of %d was not caught: the verifier does not check every query", pos, queries)
	}
}

// TestFoldRejectsAShortCoset pins that a malformed coset is rejected.
//
// Note what does the rejecting: the leaf is hashed whole, so a leaf of the wrong
// length produces a different digest and VerifyMerkleProof rejects it before the
// size check is reached. Verified directly -- VerifyMerkleProof(root, short, path)
// is false on its own. Deleting cfg.CosetSize() check therefore leaves this test,
// and the whole suite, green: it is an equivalent mutant, and the check is
// defence in depth that names the malformed opening rather than a soundness gate.
//
// Recorded rather than papered over, because a test whose name suggests it pins a
// check it does not pin is worse than no test -- the same overclaim found earlier
// in this work when the headline lying-prover test turned out to be caught by the
// Merkle check.
func TestFoldRejectsAShortCoset(t *testing.T) {
	t.Parallel()

	s := newFoldSetup(t, 8, 2, 4)

	proof, err := proveFold(foldTranscript(t), s.G, s.hint, s.cfg, s.alpha, &s.claim)
	require.NoError(t, err)

	proof.Queries[0].Leaf = proof.Queries[0].Leaf[:len(proof.Queries[0].Leaf)-1]

	err = verifyFold(foldTranscript(t), s.com, s.cfg, s.alpha, &s.claim, proof)
	require.ErrorIs(t, err, ErrCosetOpeningInvalid)
}
