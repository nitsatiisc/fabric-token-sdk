# Titan PCS — interface reference

The `titan` package implements the Titan polynomial commitment scheme over BLS12-381
G1. This page documents the **public interface**: how to configure a setup, the types a
caller touches, and the order to call them in.

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
multilinear $`f`$ in $`m`$ variables and opens $`\tilde f(\alpha) = \sigma`$. It is built
*on top of* the group scheme — the row commitments of $`f`$ form a group multilinear
$`G`$, and $`G`$ is what actually gets encoded and Merkle-committed. The **group** scheme
is exported in its own right because that inner layer is independently useful, and
because it is the honest place to put the folding phase.

Both follow the same four-step flow:

```
Setup  ->  Prover(Setup, Statement, Witness)  ->  Prove()  ->  Verifier(Setup, Statement, Commitment).Verify(proof, sigma)
```

---

## 2. Configuration: canonical or custom

Every setup is built one of two ways. In the **canonical** configuration the package
chooses everything. In a **custom** configuration the caller chooses everything, and the
package only checks that the choice works.

### 2.1 What gets chosen

A commitment is shaped by up to two splits, then by the soundness parameters. In the
formulas below:

| symbol | meaning | in the API |
|---|---|---|
| $`m`$ | variables of the committed polynomial | `setup.NumVars()` |
| $`M_1`$ | column variables of the field matrix | `Split.M1` |
| $`m'`$ | variables of the group multilinear $`G`$ | `Commitment.NumVars` |
| $`\ell`$ | coset dimension, and number of folding rounds | `FoldConfig.Ell` |
| $`\rho`$ | code rate, $`\rho = 2^{-\mathrm{LogRate}}`$ | `FoldConfig.LogRate` |
| $`Q`$ | number of consistency queries | `FoldConfig.Queries` |

**Split 1: rows × columns (field scheme only).** The field polynomial $`f`$ in $`m`$
variables is read as a matrix with $`2^{M_1}`$ columns and $`2^{m - M_1}`$ rows:

- each row is committed with a Pedersen MSM over the $`2^{M_1}`$ columns;
- the row commitments form the group multilinear $`G`$ in $`m' = m - M_1`$ variables;
- the column half is opened by the CSP inner product.

A group commitment has no matrix, so for the group scheme $`m' = m`$.

**Split 2: coset × reduced (both schemes).** The group multilinear $`G`$ in $`m'`$
variables is split once more:

- $`\ell`$ variables form the coset dimension. Each Merkle leaf holds $`2^{\ell}`$
  points, and the prover folds $`\ell`$ rounds.
- The remaining $`m' - \ell`$ variables form the reduced polynomial, which the prover
  sends in plain and the verifier checks directly.

**Soundness parameters.** The rate $`\rho`$, the number of queries $`Q`$, and the
regime (`Capacity` or `Johnson`) the query count was derived under.

The prover's group sum-check also splits its variables internally, at
$`\lfloor m'/2 \rfloor`$, to decide how it computes the round messages. This is the
prover's own bookkeeping: the messages are the same for every split, the verifier never
sees it, and it is not part of the configuration.

### 2.2 Canonical configuration

Pass the zero `FoldConfig`:

```go
fs, err := titan.NewFieldSetup(m, gens, nil, titan.FoldConfig{})
gs, err := titan.NewGroupSetup(m, nil, titan.FoldConfig{})
```

The package then chooses:

| | field | group |
|---|---|---|
| split 1 | balanced: $`M_1 = m/2`$, so $`m' = m/2`$ | none: $`m' = m`$ |
| split 2 | $`\ell`$ = `DefaultEll(m', 43)` | $`\ell`$ = `DefaultEll(m', 43)` |
| soundness | $`\rho = 1/8`$, $`Q = 43`$, `Capacity` (128 bits) | same |
| accepted sizes | $`m \equiv 0 \pmod 4`$ | $`m`$ even |

`DefaultEll` picks the $`\ell \le m'/2`$ that minimises proof size, see
[§2.5](#25-choosing-a-custom-configuration).

The canonical configuration is strict on purpose: it covers the square shapes the
defaults were tuned for. Any other size is rejected with `ErrInvalidFoldConfig`, and
the error message points to the custom route. The strictness is about tuning only.
Every size the custom route accepts is just as sound.

### 2.3 Custom configuration

Pass both splits and a non-zero `FoldConfig`:

```go
split := titan.Split{M: m, M1: m1}
fs, err := titan.NewFieldSetupWithSplit(split, gens, nil, cfg)
gs, err := titan.NewGroupSetup(m, nil, cfg)
```

A custom configuration is checked for **correctness only**:

| check | rule | returns |
|---|---|---|
| split 1 (`Split.Validate`) | $`m \ge 1`$ and $`1 \le M_1 \le m - 1`$; any parity, any balance | `ErrInvalidMatrixSplit` |
| split 2 (`FoldConfig.Validate`) | $`1 \le \ell \le m'`$; any parity, including $`\ell > m'/2`$ | `ErrInvalidFoldConfig` |
| rate, queries | $`\rho < 1`$ (`LogRate` at least 1) and $`Q \ge 1`$ | `ErrInvalidFoldConfig` |
| regime | `Capacity` or `Johnson` | `ErrInvalidFoldConfig` |
| generators (field) | at least $`2^{M_1}`$ generators in `gens` | `ErrInsufficientGenerators` |

Nothing else is enforced. In particular, $`Q`$ may exceed the number of cosets,
$`2^{m' - \ell} / \rho`$. The queries are independent draws, the prover opens each
distinct one once, and many draws over a small oracle open most or all of it, which is
at least as sound. A custom configuration uses the same code path as the canonical
one, and `odd_test.go` shows that odd sizes and $`\ell > m'/2`$ are complete and reject
forgeries.

A typical custom configuration keeps the canonical soundness parameters and changes
only the shape:

```go
q, err := titan.QueryCount(titan.DefaultSecurityBits, titan.DefaultLogRate, titan.Capacity) // 43
if err != nil {
    return err
}

split := titan.Split{M: 10, M1: 4} // 2^6 rows x 2^4 columns, so m' = 6
cfg := titan.FoldConfig{
    Ell:     titan.DefaultEll(split.RowVars(), q),
    LogRate: titan.DefaultLogRate,
    Queries: q,
    Regime:  titan.Capacity,
}
fs, err := titan.NewFieldSetupWithSplit(split, gens, nil, cfg)
```

**Partly custom setups.** The two constructors also take the mixed cases. Each part
left at its default follows the canonical rule for that part:

- `NewFieldSetup(m, gens, nil, cfg)` with a non-zero `cfg` takes the balanced split
  and your fold.
- `NewFieldSetupWithSplit(split, gens, nil, FoldConfig{})` takes your split and the
  canonical fold on its row half. That needs an even $`m'`$.

### 2.4 Soundness parameters

The defaults are `DefaultSecurityBits` $`\lambda = 128`$ and `DefaultLogRate = 3`, so
$`\rho = 1/8`$. `QueryCount` returns

```math
Q = \left\lceil \frac{\lambda}{\log_2(1/\rho)} \right\rceil \ \text{(Capacity)},
\qquad
Q = \left\lceil \frac{2\lambda}{\log_2(1/\rho)} \right\rceil \ \text{(Johnson)}.
```

- **`Capacity`**, the default, gives $`\lceil 128/3 \rceil = 43`$ queries (42 would
  give only 126 bits). It is the conjectured bound, and the one the reference
  implementation and the paper's cost analysis use.
- **`Johnson`** gives 86 queries at the same target. It is the provable bound: a caller
  that needs one should set it explicitly.

`FoldConfig.SecurityBits()` is the inverse of `QueryCount`, so a caller who sets
$`Q`$ by hand can see what the choice buys.

The reference implementation uses 70 queries. That count accounts for the Johnson
radius together with folding the CSP leg. This package does not fold the CSP leg, so
the number does not apply here.

### 2.5 Choosing a custom configuration

**Split 1** trades the column side against the row side:

| | smaller $`M_1`$ | larger $`M_1`$ |
|---|---|---|
| CSP inner product | cheaper | more expensive |
| Pedersen generators needed | fewer | more |
| row MSM length | shorter | longer |
| group multilinear $`G`$, domain, FFT | **larger** | smaller |

The canonical $`M_1 = m/2`$ keeps the column half as small as a balanced split allows,
because this package does not fold the CSP leg, so every column variable costs a
linear amount. The Rust reference folds that leg and so uses $`M_1 = m/2 - 2`$.

**Split 2** trades the two parts of the proof. The proof carries up to $`Q`$ cosets of
$`2^{\ell}`$ points plus the $`2^{m' - \ell}`$ coefficients of the reduced polynomial, so
its size in group elements is roughly

```math
Q \cdot 2^{\ell} + 2^{m' - \ell}.
```

`DefaultEll(m', Q)` minimises this over $`1 \le \ell \le m'/2`$. Because of the factor
$`Q`$, the optimum is well below $`m'/2`$: it is 1 up to $`m' = 8`$, 3 at $`m' = 12`$,
and 5 at $`m' = 16`$. A larger $`\ell`$ shrinks the reduced polynomial, and with it the
verifier's work, at the cost of a larger proof.

---

## 3. Field scheme

### 3.1 Setup

```go
func NewFieldSetup(numVars int, gens []bls12381.G1Affine, curve *mathlib.Curve, cfg FoldConfig) (*FieldSetup, error)
func NewFieldSetupWithSplit(split Split, gens []bls12381.G1Affine, curve *mathlib.Curve, cfg FoldConfig) (*FieldSetup, error)

func (s *FieldSetup) Split() Split
func (s *FieldSetup) NumVars() int
func (s *FieldSetup) FoldConfig() FoldConfig
```

See [§2](#2-configuration-canonical-or-custom) for which constructor and `cfg` to use.

- `gens` must hold at least $`2^{M_1}`$ Pedersen generators. Surplus generators are
  ignored.
- `curve` may be `nil`, which means the curve matching this package's types. It is
  used for the Fiat–Shamir transcript and the CSP inner product.

A setup is the shared public parameter, and **the prover and the verifier must hold the
same one**. The commitment records $`M_1`$, and the verifier rejects a commitment made
under a different split.

### 3.2 Statement and witness

```go
type FieldStatement struct { Alpha []fr.Element }       // len == setup.NumVars() == m
type FieldWitness   struct { Poly  sumcheck.FieldPoly } // len == 1 << m
```

### 3.3 Prover

```go
func NewFieldProver(setup *FieldSetup, st FieldStatement, w FieldWitness) (*FieldProver, error)
func (p *FieldProver) Commitment() *Commitment
func (p *FieldProver) Prove() (*EvalProof, fr.Element, error)
func (p *FieldProver) ProveAt(alpha []fr.Element) (*EvalProof, fr.Element, error)
```

`NewFieldProver` commits: it runs the row MSMs, encodes $`G`$, and builds the Merkle
tree over the coset oracle. So `Commitment()` is available before any proof, and the
commitment can be bound into a transcript before the evaluation point is drawn.

`Prove()` opens at `st.Alpha`. It returns the proof and $`\sigma = \tilde f(\alpha)`$,
and it computes $`\sigma`$ itself rather than taking it as an input. `ProveAt(alpha)`
opens the same commitment at another point. The caller must draw that point from its
transcript **after** binding the commitment.

### 3.4 Verifier

```go
func NewFieldVerifier(setup *FieldSetup, st FieldStatement, com *Commitment) (*FieldVerifier, error)
func (v *FieldVerifier) Verify(proof *EvalProof, sigma fr.Element) int      // 1 = accept, 0 = reject
func (v *FieldVerifier) VerifyErr(proof *EvalProof, sigma fr.Element) error // nil = accept
```

`VerifyErr` runs the same check as `Verify` and reports why it failed, using the
sentinels in [§6](#6-sentinel-errors). `Verify` returns an `int`, the convention in the
surrounding zkatdlog code.

### 3.5 Worked example

```go
import (
    "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
    "github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"
)

const m = 8 // canonical: m divisible by 4

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

## 4. Group scheme

The group scheme has the same shape as the field scheme, but no matrix split and no
generators: the committed object already consists of group elements.

```go
func NewGroupSetup(numVars int, curve *mathlib.Curve, cfg FoldConfig) (*GroupSetup, error)
func (s *GroupSetup) NumVars() int
func (s *GroupSetup) FoldConfig() FoldConfig

type GroupStatement struct { Alpha []fr.Element }
type GroupWitness   struct { Poly  sumcheck.GroupPoly }

func NewGroupProver(setup *GroupSetup, st GroupStatement, w GroupWitness) (*GroupProver, error)
func (p *GroupProver) Commitment() *Commitment
func (p *GroupProver) Prove() (*GroupEvalProof, bls12381.G1Affine, error)
func (p *GroupProver) ProveAt(alpha []fr.Element) (*GroupEvalProof, bls12381.G1Affine, error)

func NewGroupVerifier(setup *GroupSetup, st GroupStatement, com *Commitment) (*GroupVerifier, error)
func (v *GroupVerifier) Verify(proof *GroupEvalProof, sigma *bls12381.G1Affine) int
func (v *GroupVerifier) VerifyErr(proof *GroupEvalProof, sigma *bls12381.G1Affine) error
```

The canonical configuration takes even $`m`$. A custom `FoldConfig` takes any
$`m \ge 1`$ ([§2](#2-configuration-canonical-or-custom)).

---

## 5. Commitment

```go
type Commitment struct {
    Root      []byte           // unused, always nil
    NumVars   int              // m': variables of the group multilinear G
    LogDomain int              // log2 |L| = m' + LogRate
    K         int              // Ell: 2^K points per Merkle leaf
    NumLeaves int              // |L| / 2^K
    ColVars   int              // M1 for a field commitment, 0 for a group commitment
    Cosets    *CosetCommitment // the Merkle root the opening is checked against
}
```

A caller only passes the commitment from the prover to the verifier. Three fields can
mislead when read directly:

- **`NumVars` is $`m'`$, not $`m`$.** For a field commitment it counts the rows'
  variables only. $`m`$ comes from the setup or the statement.
- **`ColVars` records split 1.** The verifier checks it against its own setup and
  rejects a mismatch. `0` on a field commitment is read as the balanced split.
- **`Root` is unused.** The one root that binds the polynomial is `Cosets.Root`. `Root`
  is kept as a nil placeholder, so any code that tries to verify against it fails at
  once.

---

## 6. Sentinel errors

All sentinels are in `errors.go`; match them with `errors.Is`. These are the ones a
caller of the PCS interface will see:

| sentinel | meaning |
|---|---|
| `ErrInvalidMatrixSplit` | split 1 is invalid: $`m \le 0`$, or $`M_1`$ is outside $`[1, m-1]`$ |
| `ErrInvalidFoldConfig` | the canonical configuration was asked for a size it does not cover, or a custom `FoldConfig` failed a check in [§2.3](#23-custom-configuration) |
| `ErrInsufficientGenerators` | fewer than $`2^{M_1}`$ Pedersen generators |
| `ErrNumVarsMismatch` | `Alpha`, the polynomial and the setup disagree on the variable count |
| `ErrQueryCountMismatch` | the proof does not carry exactly one opening per distinct sampled index |
| `ErrCosetOpeningInvalid` | **a consistency query failed**: the coset is not under the root, or does not fold to the reduced polynomial. This is the error that catches a prover who committed to one polynomial and folded another |
| `ErrReducedClaimMismatch` | the folding is consistent but opens to the wrong value |
| `ErrReducedPolyMismatch` | the reduced polynomial has the wrong length |
| `ErrFoldRoundMismatch` | wrong round count, or a round message inconsistent with the previous claim |
| `ErrRoundCheckFailed`, `ErrSumMismatch` | a sum-check round is inconsistent |
| `ErrDomainTooLarge` | the domain exceeds the two-adicity $`2^{32}`$ of the BLS12-381 scalar field |

`ErrInvalidSplit` belongs to the prover's internal sum-check split, not to either
split in [§2](#2-configuration-canonical-or-custom). A caller of the PCS does not see it.

---

## 7. What this interface does not yet offer

Deliberate omissions, each with a reason:

- **No `Setup` / trusted-setup ceremony.** Generators are passed in.
- **No serialization.** `Commitment`, `EvalProof` and `GroupEvalProof` are Go structs;
  there is no wire encoding yet.
- **No batch opening.** One point per proof (`ProveAt` can open one commitment at
  several points, one proof each).
- **No zero-knowledge.** The proof reveals up to $`Q`$ cosets of the oracle and the
  reduced polynomial in plain. Titan is a commitment scheme here, not a ZK argument.
- **Not WHIR proper.** The reduced polynomial is sent in plain rather than recursed on,
  so the verifier is $`O(2^{m' - \ell})`$ rather than polylogarithmic.
- **No $`O(n^{1/4})`$ variant.** That needs a second folding layer over the *generator*
  oracle — the reference's `l2`. Its absence is why the canonical $`M_1`$ is $`m/2`$
  rather than $`m/2 - 2`$.
