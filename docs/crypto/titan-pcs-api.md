# Titan PCS — interface reference

The `titan` package implements the Titan polynomial commitment scheme over BLS12-381
G1. This page documents the **public interface**: the types a caller touches, the
order to call them in, and the size constraints that decide whether a given number of
variables is usable at all.

For the construction itself — what the two legs prove and why the consistency queries
are the binding step — see [`titan-crypto.tex`](titan-crypto.tex). For the internal
design record, including the mutation-testing notes and the defects no functional test
can see, see [`titan.md`](titan.md).

Package: `token/core/zkatdlog/nogh/v1/crypto/titan`

---

## 1. Two schemes, one interface shape

The package commits two different kinds of multilinear, and the API is deliberately
parallel between them:

| | committed object | commitment is | evaluation is |
|---|---|---|---|
| **Field** | `sumcheck.FieldPoly` (`[]fr.Element`) | Merkle root over the codeword of the derived group multilinear | `fr.Element` |
| **Group** | `sumcheck.GroupPoly` (`[]bls12381.G1Affine`) | Merkle root over the codeword of the polynomial itself | `bls12381.G1Affine` |

The **field** scheme is the one a caller normally wants: it commits a scalar
multilinear `f` in `m` variables and opens `f̃(α) = σ`. It is built *on top of* the
group scheme — the row commitments of `f` form a group multilinear `G`, and `G` is
what actually gets encoded and Merkle-committed. The **group** scheme is exported in
its own right because that inner layer is independently useful, and because it is the
honest place to put the folding phase.

Both follow the same four-step flow:

```
Setup  ->  Prover(Setup, Statement, Witness)  ->  Prove()  ->  Verifier(Setup, Statement, Commitment).Verify(proof, sigma)
```

---

## 2. Field scheme

### 2.1 Setup

```go
func NewFieldSetup(numVars int, gens []bls12381.G1Affine, curve *mathlib.Curve, cfg FoldConfig) (*FieldSetup, error)
func NewFieldSetupWithSplit(split Split, gens []bls12381.G1Affine, curve *mathlib.Curve, cfg FoldConfig) (*FieldSetup, error)

func (s *FieldSetup) Split() Split
func (s *FieldSetup) NumVars() int
func (s *FieldSetup) FoldConfig() FoldConfig
```

`NewFieldSetup` uses the balanced matrix split (`M1 = m/2`).
`NewFieldSetupWithSplit` takes the cut from the caller; see [§5](#5-the-matrix-split).

- `gens` must hold at least `split.Cols()` = `2^M1` Pedersen generators. Extra
  generators are ignored, not an error.
- `curve` may be `nil`, meaning "the curve matching this package's types". It is used
  for the Fiat–Shamir transcript and for leg 2.
- `cfg` may be the zero `FoldConfig`, meaning `DefaultFoldConfig` — 128 bits under the
  capacity bound. Note that `cfg` is validated against `split.RowVars()`, not
  `numVars`, because the fold runs over the row half only.

A setup is the shared public parameter. **Prover and verifier must hold the same
one**: the split is recorded in the commitment and cross-checked, so mismatched setups
are rejected rather than silently proving different polynomials.

### 2.2 Statement and witness

```go
type FieldStatement struct { Alpha []fr.Element }   // len == setup.NumVars()
type FieldWitness   struct { Poly  sumcheck.FieldPoly } // len == 1 << setup.NumVars()
```

`Alpha` has one coordinate per variable of `f` — `setup.NumVars()` of them, **not**
`Commitment.NumVars`, which counts only the row half.

### 2.3 Prover

```go
func NewFieldProver(setup *FieldSetup, st FieldStatement, w FieldWitness) (*FieldProver, error)
func (p *FieldProver) Commitment() *Commitment
func (p *FieldProver) Prove() (*EvalProof, fr.Element, error)
```

`NewFieldProver` commits — it runs the row MSMs, derives `G`, encodes it and builds
both Merkle trees — so `Commitment()` is available before `Prove()` is called. That
ordering is the point: a commitment must be fixed before `Alpha` would be chosen by a
real Fiat–Shamir chain.

`Prove()` returns the proof and `σ = f̃(α)`. The value is returned rather than taken as
an input so the prover cannot be asked to prove a claim it did not compute.

### 2.4 Verifier

```go
func NewFieldVerifier(setup *FieldSetup, st FieldStatement, com *Commitment) (*FieldVerifier, error)
func (v *FieldVerifier) Verify(proof *EvalProof, sigma fr.Element) int      // 1 = accept, 0 = reject
func (v *FieldVerifier) VerifyErr(proof *EvalProof, sigma fr.Element) error // nil = accept
```

`Verify` returns `int` to match the convention in the surrounding zkatdlog code.
`VerifyErr` is the same check reporting *why* it failed, against the sentinels in
[§7](#7-sentinel-errors). Use `VerifyErr` in tests and when diagnosing; use `Verify`
at call sites that only need the bit.

### 2.5 Worked example

```go
import (
    "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
    "github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"
)

const m = 8 // see section 6 for which m are usable

setup, err := titan.NewFieldSetup(m, gens, nil, titan.FoldConfig{})
if err != nil {
    return errors.WithMessage(err, "failed to set up the field PCS")
}

st := titan.FieldStatement{Alpha: alpha}         // len(alpha) == m
w  := titan.FieldWitness{Poly: f}                // len(f) == 1 << m

prover, err := titan.NewFieldProver(setup, st, w)
if err != nil {
    return errors.WithMessage(err, "failed to commit")
}
com := prover.Commitment()                        // send to the verifier

proof, sigma, err := prover.Prove()
if err != nil {
    return errors.WithMessage(err, "failed to prove the evaluation")
}

verifier, err := titan.NewFieldVerifier(setup, st, com)
if err != nil {
    return errors.WithMessage(err, "failed to set up the verifier")
}
if err := verifier.VerifyErr(proof, sigma); err != nil {
    return errors.WithMessage(err, "the opening did not verify")
}
```

---

## 3. Group scheme

Identical in shape, without the matrix split — a group multilinear has no rows to
commit, so it is encoded directly.

```go
func NewGroupSetup(numVars int, curve *mathlib.Curve, cfg FoldConfig) (*GroupSetup, error)
func (s *GroupSetup) NumVars() int
func (s *GroupSetup) FoldConfig() FoldConfig

type GroupStatement struct { Alpha []fr.Element }
type GroupWitness   struct { Poly  sumcheck.GroupPoly }

func NewGroupProver(setup *GroupSetup, st GroupStatement, w GroupWitness) (*GroupProver, error)
func (p *GroupProver) Commitment() *Commitment
func (p *GroupProver) Prove() (*GroupEvalProof, bls12381.G1Affine, error)

func NewGroupVerifier(setup *GroupSetup, st GroupStatement, com *Commitment) (*GroupVerifier, error)
func (v *GroupVerifier) Verify(proof *GroupEvalProof, sigma *bls12381.G1Affine) int
func (v *GroupVerifier) VerifyErr(proof *GroupEvalProof, sigma *bls12381.G1Affine) error
```

There are no generators: the committed object is already group elements. `numVars`
must be **even** (the fold halves it), so the floor is `m = 4` rather than the field
scheme's `m = 8`.

---

## 4. Commitment

```go
type Commitment struct {
    Root      []byte            // RESERVED, always nil — see below
    NumVars   int               // variables of G — for a field commitment, log2(rows), NOT m
    LogDomain int               // log2 |L|
    K         int               // coset dimension: 2^K points per leaf
    NumLeaves int               // |L| / 2^K
    ColVars   int               // M1 of the matrix split; 0 for a group commitment
    Cosets    *CosetCommitment  // the oracle the fold queries; nil if committed without one
}
```

Two fields deserve attention.

**`NumVars` is not `m`.** For a field commitment it is `log2` of the matrix row count,
i.e. `RowVars`. A caller that wants `m` reads it from the statement or the setup.

**`ColVars` is wire state, and `0` means "not stated".** `NumVars` pins down `RowVars`
and nothing else — a commitment with `NumVars = 4` is consistent with every `M1`. So
the split has to travel with the commitment, or a prover and verifier cutting the
matrix in different places could not be detected. Group commitments leave it `0`, as
does a field commitment serialized before the field existed; the verifier treats `0`
as "fall back to the balanced split", so such a commitment still verifies exactly as
it did.

**`Root` is always nil, and is reserved.** There is exactly one root that matters,
`Cosets.Root`, over the coset-wise oracle whose leaves are `{G(b, powers(y))}`. The
flat codeword — full power-curve points — used to be Merkle-committed too, but nothing
ever verified against that root: the folding phase is the only stage that opens the
oracle, and it opens cosets. So the tree was built and hashed for no verifier, and is
no longer computed.

The field is kept, nil, rather than removed, to reserve the name. Leaving it
*populated* would have been the worst option: an exported `[]byte` called `Root`
invites a future batching or serialization layer to `VerifyMerkleProof` against it,
which would pass while binding nothing the protocol relies on. Nil makes that misuse
fail at once instead of silently.

---

## 5. The matrix split

```go
type Split struct { M, M1 int }

func DefaultMatrixSplit(m int) Split   // Split{M: m, M1: m / 2}

func (s Split) RowVars() int            // M - M1  — sizes the fold and the domain
func (s Split) ColVars() int            // M1      — leg 2 runs over these
func (s Split) Rows() int               // 1 << RowVars()
func (s Split) Cols() int               // 1 << M1  — the generator count

func (s Split) Validate() error         // commit-time contract
func (s Split) ValidateForFold() error  // Validate + even row half
```

The field construction reads `f` as a `2^RowVars × 2^M1` matrix. Moving the cut trades
one leg against the other:

| | smaller `M1` | larger `M1` |
|---|---|---|
| leg 2 (CSP inner product) | cheaper | more expensive |
| Pedersen generators needed | fewer | more |
| row MSM length | shorter | longer |
| evaluation domain / FFT | **larger** | smaller |

The default is `m/2`. The Rust reference uses `m/2 − 2` because it also folds the
generator oracle, so a larger column half is cheap there; this package does not fold
leg 2 yet, so every extra column variable is paid in full as linear CSP cost. Revisit
the default when leg-2 folding lands — it is a consequence of what is implemented, not
a disagreement with the reference.

### 5.1 Two validators, deliberately

`Validate` is the **commit-time** contract: `M > 0`, and `M1` leaves a whole number of
variables on each side. That is all a matrix needs.

`ValidateForFold` adds the rule the coset layout needs: an **even row half**.

They are separate on purpose. Committing at an odd row half is perfectly well defined
— it produces `2^RowVars` Pedersen commitments like any other shape — and folding out
of a commitment is a property of the `FoldConfig` attached later, not of the
commitment. An earlier draft conflated them and broke every odd-`m` and `m = 2` case
in the package at once. Callers that attach a fold want `ValidateForFold`; callers that
only commit want `Validate`.

---

## 6. Which sizes are usable

Three independent constraints. Only the first depends on the split.

**1. Even row half** (`ValidateForFold`). Under the *balanced* split
`RowVars = m − m/2`, which is even exactly when `m mod 4 ∈ {0, 3}`:

| `m mod 4` | `RowVars` | balanced split foldable? |
|---|---|---|
| 0 | `m/2`, even | yes — 4, 8, 12, … |
| 3 | `(m+1)/2`, even | yes — 3, 7, 11, … |
| 1 | `(m+1)/2`, odd | no |
| 2 | `m/2`, odd | no |

This is a property of the *balanced split*, not of the scheme. `NewFieldSetupWithSplit`
lifts it: `m = 10` at `M1 = 4` has a row half of 6 and folds fine.

**2. Drawability** (`FoldConfig.Validate`). The consistency queries are *distinct*
indices into the folded domain, so `Queries ≤ NumCosets(rowVars) = 2^(rowVars − Ell + LogRate)`.
At the default 43 queries this is what actually blocks the small odd sizes: `m = 3, 7,
11` pass the parity rule and fail here.

**3. The practical floors.** Field scheme: `m = 8`. Group scheme: `m = 4`.

Sizes rejected by `NewFieldSetup` for parity alone — `m = 6, 10, 14, 18` — are usable
via `NewFieldSetupWithSplit`; `m = 18` at `M1 = 8` is where the Rust reference's own
config table starts.

---

## 7. Fold configuration and soundness

```go
type FoldConfig struct {
    Ell     int              // folding rounds
    LogRate int              // rho = 2^-LogRate
    Queries int              // consistency queries — this is the security parameter
    Regime  SoundnessRegime  // Capacity (default) or Johnson
}

func DefaultFoldConfig(m int) (FoldConfig, error)
func DefaultEll(m, queries int) int
func QueryCount(lambda, logRate int, regime SoundnessRegime) (int, error)

func (c FoldConfig) Validate(m int) error
func (c FoldConfig) SecurityBits() int
func (c FoldConfig) NumCosets(m int) int  // 1 << (m - Ell + LogRate)
func (c FoldConfig) CosetSize() int       // 1 << Ell
```

Defaults: `DefaultSecurityBits = 128`, `DefaultLogRate = 3` (so `ρ = 1/8`), `Regime =
Capacity`. Under the capacity bound `Q = ⌈λ / log₂(1/ρ)⌉ = ⌈128/3⌉ = **43**`. Note 42
would give only 126 bits.

**`Capacity` is conjectured; `Johnson` is what is provable.** Johnson costs twice the
queries (86 at the same target). The default is `Capacity` because that is what the
reference implementation and the paper's cost analysis assume, but a caller who needs
a provable bound should set `Johnson` explicitly.

`DefaultEll` minimizes proof size: the proof carries `Queries` cosets of `2^Ell` points
plus the reduced polynomial's `2^(m−Ell)` coefficients, so it minimizes
`Queries·2^Ell + 2^(m−Ell)`. Because the coset term carries the `Queries` factor, the
optimum sits **below** the paper's `m/2 − 1` — at `m = 12` it is 3, not 5. `Ell` is a
field rather than a constant so a caller who wants the paper's value can set it.

`SecurityBits()` is the inverse of `QueryCount`: a caller who sets `Queries` by hand
can use it to see what that bought.

> **Out of scope:** the reference implementation uses 70 queries. That is Johnson's
> radius plus the soundness error of folding the CSP leg — neither of which applies
> here, since this package does not fold leg 2. The difference is not a discrepancy to
> reconcile.

---

## 8. Sentinel errors

All in `errors.go`; match with `errors.Is`. The ones a caller of the PCS interface
will actually see:

| sentinel | means |
|---|---|
| `ErrInvalidMatrixSplit` | column half outside `[1, m-1]`, or an odd row half where the fold needs even |
| `ErrInvalidFoldConfig` | `Ell` outside `[1, m/2]`, odd `m`, non-positive rate/queries, or queries not drawable |
| `ErrInsufficientGenerators` | fewer than `2^M1` Pedersen generators supplied |
| `ErrNumVarsMismatch` | `Alpha`, the polynomial and the setup disagree on the variable count |
| `ErrQueryCountMismatch` | the proof does not carry the configured number of queries — accepting fewer would lower soundness below its stated level |
| `ErrCosetOpeningInvalid` | **a consistency query failed** — the coset is not under the root, or does not fold to the reduced codeword. This is the error that catches a prover who committed to one polynomial and folded another |
| `ErrReducedClaimMismatch` | the folding is internally consistent but opens to the wrong value |
| `ErrReducedPolyMismatch` | the reduced polynomial has the wrong length |
| `ErrFoldRoundMismatch` | wrong round count, or a round message inconsistent with the previous claim |
| `ErrRoundCheckFailed`, `ErrSumMismatch` | sum-check round inconsistency |
| `ErrDomainTooLarge` | domain exceeds BLS12-381 Fr's two-adicity of `2^32` |

`ErrInvalidSplit` (the sum-check prover's `ell`) and `ErrInvalidMatrixSplit` (the
matrix cut) are distinct sentinels because they fail for unrelated reasons.

---

## 9. What this interface does not yet offer

Deliberate omissions, each with a reason:

- **No `Setup` / trusted-setup ceremony.** Generators are passed in.
- **No serialization.** `Commitment`, `EvalProof` and `GroupEvalProof` are Go structs;
  there is no wire encoding yet. `ColVars` is described as "on the wire" in the sense
  that it is part of the commitment's *content* and is checked — not that a codec
  exists.
- **No batch opening.** One `Alpha` per proof.
- **No zero-knowledge.** The proof reveals `Queries` cosets of the oracle and the
  reduced polynomial in plain. Titan is a commitment scheme here, not a ZK argument.
- **Not WHIR proper.** The reduced polynomial is sent in plain rather than recursed on,
  so the verifier is `O(2^(m−Ell))` rather than polylogarithmic.
- **No `O(n^¼)`.** That needs a second folding layer over the *generator* oracle — the
  reference's `l2`. Its absence is why `M1` defaults to `m/2` rather than `m/2 − 2`.
