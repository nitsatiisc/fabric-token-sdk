# Sum-Check Protocol

**Implementation**: [`token/core/zkatdlog/nogh/v1/crypto/sumcheck`](../../token/core/zkatdlog/nogh/v1/crypto/sumcheck)
**Curve**: BLS12-381 (G1)
**Date**: 2026-09-24

## Table of Contents
1. [Introduction](#1-introduction)
2. [The Claim](#2-the-claim)
3. [Protocol](#3-protocol)
4. [API](#4-api)
5. [Transcript and Fiat–Shamir](#5-transcript-and-fiat-shamir)
6. [Performance Notes](#6-performance-notes)
7. [Security Considerations](#7-security-considerations)
8. [Testing](#8-testing)
9. [References](#9-references)

---

## 1. Introduction

The sum-check protocol reduces a claim about a sum over the boolean hypercube to a
claim about a single evaluation at a random point. It is the standard engine behind
succinct arguments built on multilinear polynomials, and it is what makes those
arguments cheap to verify: the prover does work proportional to the hypercube size
$`2^{\mu}`$, while the verifier does work proportional only to the number of variables
$`\mu`$.

This package implements sum-check in two flavours over the same code path:

- **Field sum-check**, where the summand is a product of multilinear polynomials
  with scalar coefficients, and the claimed sum is a scalar.
- **Group sum-check**, where exactly one factor has G1 coefficients, and the claimed
  sum is a group element.

The package is deliberately **commitment-scheme agnostic**. Sum-check does not
close an argument on its own — it only reduces one. The residual claim is returned
to the caller, who closes it with a polynomial commitment opening, an oracle query,
or a direct evaluation. See [Security Considerations](#7-security-considerations).

### 1.1 Design Goals

- **Mixed field/group products** in one protocol, so a caller does not need two
  separate implementations for the two cases.
- **Composability**: the transcript can be supplied by an enclosing protocol, so
  sum-check can be nested inside a larger Fiat–Shamir argument without restarting
  the hash chain.
- **No `mathlib.Zr` in hot loops**: bulk arithmetic runs on the raw
  `gnark-crypto` types, with conversion confined to the API boundary
  (see [Performance Notes](#6-performance-notes)).

## 2. The Claim

A claim is a product of multilinear polynomials on the same number of variables:

```math
p(X_1, \ldots, X_{\mu}) = f_1(X) \cdot f_2(X) \cdots f_k(X) \cdot g_1(X)
```

with $`k \ge 0`$ field factors and **at most one** group factor $`g_1`$. The protocol
proves the value of

```math
S = \sum_{x \in \{0,1\}^{\mu}} p(x)
```

### 2.1 Why At Most One Group Factor

The product of two group elements is not defined in an elliptic-curve group, so a
summand may contain at most one G1 factor. This rule is enforced **structurally**
rather than by a runtime check: `Claim.Group` is a single `GroupPoly`, not a slice,
so a second group factor cannot be expressed in the API.

### 2.2 Representation

A multilinear polynomial on $`\mu`$ variables is represented by its $`2^{\mu}`$ evaluations
on the hypercube, indexed **little-endian**: entry $`i`$ holds
$`p(b_0, \ldots, b_{\mu-1})`$ where $`b_j`$ is bit $`j`$ of $`i`$. So $`b_0`$ is the low index bit
and $`b_{\mu-1}`$ the high one.

This convention determines the folding pairing, and the two must be kept in step.
Because $`b_{\mu-1}`$ is the high bit, its two slices are the bottom and top halves of
the table, so folding pairs entry $`i`$ with entry `i + half` and substitutes for the
**last** variable. Under the opposite (big-endian) convention the first variable
would be the high bit and folding would instead pair `2i` with $`2i+1`$. Choosing the
pairing that does not match the layout silently sums a different polynomial — and it
is invisible to round-trip tests, since prover and verifier fold identically and the
mistake cancels between them. `TestFoldSubstitutesLastVariable` pins it down.

| Type | Element | Meaning |
|------|---------|---------|
| `FieldPoly` | `fr.Element` | multilinear polynomial with scalar coefficients |
| `GroupPoly` | `bls12381.G1Affine` | multilinear polynomial with G1 coefficients |

The evaluation table length must be a power of two; `NewFieldPoly` and
`NewGroupPoly` reject anything else with `ErrNotPowerOfTwo`.

### 2.3 Round-Polynomial Degree

Each factor is multilinear, so it is degree 1 in the round variable and the product
has degree equal to the number of factors:

```math
\mathrm{degree} = \begin{cases} k + 1 & \text{with a group factor} \\ k & \text{field only} \end{cases}
```

Each round therefore sends `degree + 1` evaluations, which is exactly enough to
determine a univariate polynomial of that degree.

## 3. Protocol

For each variable in turn, the prover sends the univariate round polynomial

```math
q_j(t) = \sum_{x \in \{0,1\}^{\mu-j}} p(x, t, r_{j-1}, \ldots, r_1)
```

(variables are consumed from the last position inward, per
[section 2.2](#22-representation); $`r_1`$ is the challenge from round 1.)

evaluated at $`t = 0, 1, \ldots, \mathrm{degree}`$. The verifier checks

```math
q_j(0) + q_j(1) = \mathit{expected}
```

where `expected` is the asserted total in round 0 and the previous round polynomial
interpolated at the previous challenge thereafter. It then draws the next challenge
$`r_j`$ from the transcript and sets `expected = q_j(r_j)`.

After $`\mu`$ rounds, `expected` holds the residual claim: the value of $`p`$ at the
challenge point. Rounds consume variables from the last to the first, so the
challenges come out in reverse table order — call this **folding order**, as opposed
to the **table order** ($`b_0`$ first) the evaluation table is laid out in.

An `Opening`'s $`R`$ is in folding order. Both orders are useful, so evaluation is
exposed as two methods rather than one taking an implicit convention:

| Method | Argument order | Use when |
|--------|----------------|----------|
| `EvaluateOpening(at)` | folding: `at[0]` is $`b_{\mu-1}`$ | the point came from an `Opening`'s $`R`$; passed straight through |
| `EvaluatePoint(at)` | table: `at[0]` is $`b_0`$ | the caller thinks in the polynomial's own variables; reversed internally |

The two differ only in argument order, and each names the convention it means at the
call site. Getting this wrong is silent — the wrong value comes back with no
error — which is why there is no single `Evaluate`.

### 3.1 Folding

Between rounds the prover folds every factor at the challenge, using the multilinear
identity

```math
p(x, r) = p(x, 0) + r \cdot \bigl(p(x, 1) - p(x, 0)\bigr)
```

which costs one multiplication per surviving entry rather than two, and halves the
table each round. Total prover work across all rounds is therefore $`O(2^{\mu})`$, not
$`O(\mu \cdot 2^{\mu})`$.

### 3.2 Stepping t Without Multiplication

Because each factor is multilinear in the round variable, $`f_i(t, x)`$ is the straight
line through $`f_i(0, x)`$ and $`f_i(1, x)`$. Stepping $`t = 0, 1, 2, \ldots`$ needs only
repeated addition of the slope, so the only multiplications per evaluation point are
the ones forming the product itself. The same trick applies on the group side, where
stepping $`t`$ costs one curve addition rather than a scalar multiplication.

## 4. API

### 4.1 Building a Claim

```go
import "github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/sumcheck"

f, err := sumcheck.NewFieldPoly(evals)       // evals []*mathlib.Zr, len a power of two
if err != nil {
    return errors.Wrap(err, "failed to build field polynomial")
}
g, err := sumcheck.NewGroupPoly(points)      // points []*mathlib.G1
if err != nil {
    return errors.Wrap(err, "failed to build group polynomial")
}

claim := &sumcheck.Claim{
    Field: []sumcheck.FieldPoly{f},
    Group: g,                                 // omit for a field-only claim
}
```

### 4.2 Proving

```go
proof, opening, err := sumcheck.Prove(curve, claim)
if err != nil {
    return errors.Wrap(err, "sum-check prover failed")
}
```

`Prove` does not modify the caller's polynomials: it folds a deep copy.

### 4.3 Verifying

The verifier never holds the polynomials. It needs only the public shape of the
claim, which also determines the expected round degree:

```go
shape := sumcheck.Shape{
    NumVars:         numVars,
    NumFieldFactors: 1,
    HasGroupFactor:  true,
}

opening, err := sumcheck.Verify(curve, shape, proof)
if err != nil {
    return errors.Wrap(err, "sum-check verification failed")
}
```

### 4.4 The Opening

`Opening` is the residual claim at the challenge point $`R`$. The prover and the
verifier learn different things, so they populate different fields:

| Field | Set by `Prove` | Set by `Verify` |
|-------|----------------|-----------------|
| $`R`$ | ✅ challenge point | ✅ same point |
| `FieldEvals` | ✅ each $`f_i(R)`$ | ❌ nil |
| `GroupEval` | ✅ $`g_1(R)`$ | ✅ the full product `p(R)` (group claims) |
| `Product` | ❌ nil | ✅ `p(R)` (field-only claims) |

The asymmetry is inherent: the verifier derives the single value the rounds
telescope down to, namely the whole product `p(R)`, and cannot split it into
per-factor values without the polynomials. A caller closing the argument therefore
compares `Verify`'s `Product` (or `GroupEval`) against the product of the factor
values its commitment scheme opens to — not against `FieldEvals` element by element.

### 4.5 Composing Into a Larger Protocol

`ProveWithTranscript` and `VerifyWithTranscript` take a caller-supplied transcript
so sum-check can be nested inside a larger argument:

```go
tr := &csp.Transcript{Curve: curve}
tr.InitHasherWithDomain("MyProtocol-v1")
tr.Absorb(enclosingProtocolData)     // whatever public data the caller commits to

proof, opening, err := sumcheck.ProveWithTranscript(curve, claim, tr)
if err != nil {
    return errors.Wrap(err, "sum-check prover failed")
}
```

When these entry points are used, the package applies **no** domain separation and
**no** shape binding of its own — the caller owns both. Verification must run against
a transcript in an identical state, or every challenge diverges.

### 4.6 Composite Claims (`MultiClaim`)

A `Claim` is one product. A protocol that needs a polynomial $`\Phi(h_1, \ldots, h_p)`$
of several multilinears uses `MultiClaim`. It is the wrapper that lifts sum-check from
one product to $`\Phi`$ of several polynomials, and it is what the
[pivot protocol](pivot.md) uses for its field constraint and its sparse-product
check.

```math
H = \sum_{x \in \{0,1\}^{\mu}} \Phi\bigl(h_1(x), \ldots, h_p(x)\bigr)
```

$`\Phi`$ is a plain Go function. The prover only ever evaluates it at points, and
the caller evaluates it once to close the residual claim, so it never has to be
expanded into monomials.

#### 4.6.1 Types

```go
// MultiClaim: the pool of multilinears, the degree of Phi, and Phi over the pool.
// Phi receives one value per pool polynomial and must not modify or retain it.
type MultiClaim struct {
    Polys  []FieldPoly
    Degree int
    Phi    func(vals []fr.Element) fr.Element
}

// MultiShape is the public shape a verifier needs.
type MultiShape struct {
    NumVars int
    Degree  int
}
```

For example, $`\Phi(X, Y, Z) = X(1-Y)(1-Z) + XZ`$ over a pool of three polynomials is

```go
claim := &sumcheck.MultiClaim{
    Polys:  []sumcheck.FieldPoly{x, y, z},
    Degree: 3,
    Phi: func(v []fr.Element) fr.Element {
        var one, a, b fr.Element
        one.SetOne()
        a.Sub(&one, &v[1])
        b.Sub(&one, &v[2])
        a.Mul(&a, &b).Mul(&a, &v[0]) // X(1-Y)(1-Z)
        b.Mul(&v[0], &v[2])          // XZ

        return *a.Add(&a, &b)
    },
}
```

**Declared degree.** `Degree` must bound the total degree of $`\Phi`$. An understated
degree breaks completeness, since the honest round polynomials do not fit
(`TestMultiUnderstatedDegreeFails`). It does not affect soundness: the verifier's
caller closes the claim with the correct $`\Phi`$, so a prover working with any other
polynomial is caught except with probability
$`\max(d_{\text{declared}}, d_{\text{true}}) / \lvert\mathbb{F}\rvert`$ per round.

| Method | Returns |
|---|---|
| `(*MultiClaim).NumVars() int` | the number of variables shared by the pool |
| `(*MultiClaim).Shape() MultiShape` | `{NumVars, Degree}`, to hand to the verifier |
| `(*MultiClaim).Evaluate(evals []fr.Element) (fr.Element, error)` | $`\Phi`$ at the pool values `evals`; `ErrPoolSize` if there is not one value per pool polynomial |

#### 4.6.2 Proving and verifying

```go
func ProveMulti(curve *mathlib.Curve, claim *MultiClaim) (*Proof, *Opening, error)
func ProveMultiWithTranscript(curve *mathlib.Curve, claim *MultiClaim, tr *csp.Transcript) (*Proof, *Opening, error)

func VerifyMulti(curve *mathlib.Curve, shape MultiShape, proof *Proof) (*Opening, error)
func VerifyMultiWithTranscript(curve *mathlib.Curve, shape MultiShape, proof *Proof, tr *csp.Transcript) (*Opening, error)
```

The proof is an ordinary `Proof` with `FieldRounds` and `FieldSum` set: one round
polynomial per variable, as `Degree + 1` evaluations. `ProveMulti` folds a deep copy,
so the caller's tables are not modified.

| `Opening` field | Set by `ProveMulti` | Set by `VerifyMulti` |
|---|---|---|
| $`R`$ | ✅ challenge point, folding order | ✅ same point |
| `FieldEvals` | ✅ one value per **pool** entry, $`h_i(R)`$ | ❌ nil |
| `Product` | ❌ nil | ✅ `p(R) = Phi(h_1(R), …)` |

A nil error from `VerifyMulti` means only that the sum follows from the residual
claim. The caller closes it by obtaining the pool values at $`R`$ — from a commitment
opening, or directly — and checking that $`\Phi`$ at those values equals
`opening.Product`.

#### 4.6.3 Example

`ExampleProveMulti` (in `multi_example_test.go`, run by `go test`) proves
$`\Phi(h_0, h_1) = 2 h_0 h_1 - h_1^2`$ over two variables:

```go
claim := &sumcheck.MultiClaim{
    Polys: []sumcheck.FieldPoly{h0, h1},
    Degree: 2,
    Phi: func(h []fr.Element) fr.Element { // 2 h0 h1 - h1^2
        var a, b fr.Element
        a.Mul(&h[0], &h[1]).Double(&a)
        b.Square(&h[1])

        return *a.Sub(&a, &b)
    },
}
proof, _, err := sumcheck.ProveMulti(curve, claim)
opening, err := sumcheck.VerifyMulti(curve, claim.Shape(), proof)

// close the residual claim at opening.R
evals := []fr.Element{h0(R), h1(R)}             // from a commitment opening
phi, err := claim.Evaluate(evals)
ok := phi.Equal(productOf(opening))             // opening.Product as fr.Element
```

#### 4.6.4 Rules and errors

- **Structure:** at least one pool polynomial, a non-nil `Phi`, `Degree` at least 1,
  and every pool polynomial with the same number of variables (at least one) and a
  power-of-two table. Violations return `ErrNoFactors`, `ErrNumVarsMismatch` or
  `ErrNotPowerOfTwo`.
- **Degree:** the round degree is `Degree`. A verifier that passes a different degree
  gets `ErrRoundDegreeMismatch`.
- **Field only:** group factors are not supported in a `MultiClaim`. A product with
  one group factor is a `Claim`.
- **Sharing:** a polynomial used several times, or squared, is stored and folded
  once. The cost per round point is one addition per pool entry plus one evaluation
  of $`\Phi`$.
- **Transcript:** the standalone entry points bind `(NumVars, Degree)` under the
  sum-check domain with a kind byte of `2`, so a multi proof cannot be replayed as a
  single-product proof of the same size (`TestMultiRejectsTampering`). The
  `WithTranscript` variants leave domain separation and shape binding to the caller,
  as in §4.5.
- **Equivalence:** a `MultiClaim` whose $`\Phi`$ is a single product produces exactly
  the proof `Prove` produces for the equivalent `Claim` under the same transcript
  (`TestMultiSingleTermMatchesClaim`).

## 5. Transcript and Fiat–Shamir

The package reuses `crypto/rp/csp.Transcript`, the same chained SHA-256 transcript
the CSP range proof uses, rather than introducing a second Fiat–Shamir construction.

`Prove` and `Verify` construct the transcript with the domain separator
`SumCheck-v1` and absorb a 3-byte header carrying `{numVars, degree, isGroup}`
before the first round. Binding the claim's shape into the transcript means a proof
cannot be reinterpreted under a different shape: a verifier using the wrong factor
count both expects a different round degree and derives different challenges.

Every round polynomial is absorbed before its challenge is squeezed, and the
transcript is never reset mid-protocol.

## 6. Performance Notes

### 6.1 Convert at the Boundary, Never Per Call

`mathlib.Zr` wraps a `big.Int`, so bulk arithmetic through it is slow. All hot loops
in this package run on `fr.Element` and `bls12381.G1Affine`, with conversion confined
to the API boundary.

Measured on BLS12-381 for a 4096-entry table:

| Workload | via `mathlib.Zr` | via `fr.Element` | Verdict |
|----------|------------------|------------------|---------|
| Single pass (one fold) | 249 µs | 305 µs | `mathlib` wins — conversion dominates |
| Full log-n fold sequence | 383 µs | 182 µs | **`fr` wins by 2.1×** |

The lesson is the shape of the access pattern, not the primitive: a single pass does
not amortize the conversion, whereas sum-check's $`\mu`$ successive folds over a
shrinking table do. Callers should build a `FieldPoly`/`GroupPoly` **once** and hold
it across calls rather than reconstructing it per proof.

### 6.2 Scalar Multiplication Dominates the Group Path

Isolating the operations in a 190 ms group fold:

| Operation | Cost | Share |
|-----------|------|-------|
| Scalar multiplications | 161 ms | ~85% |
| $`n-1`$ Jacobian additions | 1.17 ms | ~0.6% |

Additions are ~137× cheaper than scalar multiplications, so the group design
minimizes scalar multiplications first; Jacobian-vs-affine representation tuning is
second-order. Concretely, `groupRoundEvals` gathers the scalars and points for a whole
evaluation point and applies them with a single multi-scalar multiplication, which
amortizes window precomputation across the round instead of repeating it per term.

`GroupPoly` conversion-in costs ~108 ms for 4096 points, because
`G1Affine.SetBytes` performs a subgroup check. That cost does not pay for itself on a
single fold, which is a second reason to hold a `GroupPoly` across calls.

### 6.3 MSM Dispatch

`msm` dispatches on length, following the crossovers already measured in
[`crypto/rp/csp/msm.go`](../../token/core/zkatdlog/nogh/v1/crypto/rp/csp/msm.go):
below three terms, `MultiExp`'s goroutine fan-out and window setup cost more than
they save, so a direct accumulation wins.

## 7. Security Considerations

### 7.1 Sum-Check Reduces a Claim; It Does Not Close One

A `nil` error from `Verify` means the hypercube sum **follows from** the returned
`Opening`. It does **not** mean the `Opening` is correct. A prover free to choose the
residual evaluation can prove any sum it likes.

The caller **must** close the argument by checking the returned evaluation against
something the prover could not choose freely:

- a polynomial commitment opening at $`R`$;
- an oracle query, in an interactive or idealized setting; or
- a direct evaluation of the original polynomials at $`R`$, where the verifier holds
  them.

Omitting this step leaves no soundness at all. This is a property of the protocol,
not a limitation of the implementation.

### 7.2 Soundness Error

For a degree-$`d`$ round polynomial over $`\mu`$ variables, a cheating prover's success
probability is bounded by `mu * d / |F|`. With BLS12-381's ~255-bit scalar field this
is negligible for any practical $`\mu`$ and $`d`$.

### 7.3 Why Interpolation Is Not Optional

Checking only `q(0) + q(1) == expected` is insufficient. An adversary can shift value
between `q(0)` and `q(1)` so the sum is preserved while the polynomial changes; the
tamper is caught only because the verifier interpolates at the challenge and carries
that value into the next round. The test suite exercises exactly this
("compensating tamper is still rejected") for both the field and group paths.

### 7.4 Transcript Discipline

Challenges must come from a transcript that has absorbed every round polynomial that
precedes them. Using `ProveWithTranscript` transfers responsibility for domain
separation and shape binding to the caller; a caller that reuses a transcript state
across two different claims, or that fails to bind the claim's shape, loses the
binding described in [section 5](#5-transcript-and-fiat-shamir).

## 8. Testing

| File | Coverage |
|------|----------|
| `sumcheck_test.go` | round-trip for $`k \in \{0,1,2,3\}`$ × $`\mu \in \{1,2,3,6,8,10\}`$, brute-force sum cross-check, input-immutability, field-vs-group cross-check, transcript binding, folding-convention pinning (`TestFoldSubstitutesLastVariable`) |
| `soundness_test.go` | wrong sum, tampered first/middle/final round, compensating tamper, dropped/extra/swapped round, wrong degree, nil elements, proof-under-wrong-shape, claim and shape validation |
| `fuzz_test.go` | `FuzzVerify` (attacker-controlled proof bytes), `FuzzNewFieldPoly` (arbitrary evaluation tables) |

Statement coverage is ~87%.

`TestGroupMatchesFieldScaled` is the strongest cross-check: with $`g(x) = [s(x)]\,G`$ for
a multilinear $`s`$, the group claim $`\sum_x f(x) \cdot g(x)`$ must equal
$`\bigl[\sum_x f(x) \cdot s(x)\bigr] G`$. The two runs absorb different bytes and so draw different
challenges, which means the round polynomials cannot be compared directly — but the
claimed sums must still agree once the field sum is scaled into G1. This catches
errors in the group path that a same-path test would not.

The tests were checked against **mutation testing** to confirm they are not vacuous:
reversing the fold's subtraction order produces `round consistency check failed`, and
dropping the group accumulator's `AddMixed` produces `claimed group sum is wrong`.

Both fuzz targets are registered in
[`.github/workflows/nightly-fuzz.yml`](../../.github/workflows/nightly-fuzz.yml) as
`zkatdlog-sumcheck-verify` and `zkatdlog-sumcheck-field-poly`; a target absent from
that matrix is only ever exercised by its seed corpus.

Run locally:

```bash
go test ./token/core/zkatdlog/nogh/v1/crypto/sumcheck/
go test ./token/core/zkatdlog/nogh/v1/crypto/sumcheck/ -run='^$' -fuzz='^FuzzVerify$' -fuzztime=30s
```

## 9. References

- Lund, Fortnow, Karloff, Nisan, *Algebraic Methods for Interactive Proof Systems*
  (1992) — the original sum-check protocol.
- Thaler, [*Proofs, Arguments, and Zero-Knowledge*](https://people.cs.georgetown.edu/jthaler/ProofsArgsAndZK.html)
  — chapter 4 covers sum-check and the linear-time prover.
- [ZKAT-DLOG (NOGH) Driver Specification](../drivers/dlogwogh.md) — the driver whose
  crypto package hosts this implementation.
