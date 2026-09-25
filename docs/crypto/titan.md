# Titan Multilinear Polynomial Commitment Scheme

**Implementation**: [`token/core/zkatdlog/nogh/v1/crypto/titan`](../../token/core/zkatdlog/nogh/v1/crypto/titan)
**Curve**: BLS12-381 (G1)
**Status**: in progress — step 1 (oracle encoding) complete
**Date**: 2026-09-25

## Table of Contents
1. [Introduction](#1-introduction)
2. [Why Titan](#2-why-titan)
3. [The Univariate-Multilinear Correspondence](#3-the-univariate-multilinear-correspondence)
4. [Oracle Encoding](#4-oracle-encoding)
5. [The Evaluation Domain](#5-the-evaluation-domain)
6. [API](#6-api)
7. [Performance Notes](#7-performance-notes)
8. [Porting Notes: Rust/Pasta to Go/BLS12-381](#8-porting-notes-rustpasta-to-gobls12-381)
9. [Testing](#9-testing)
10. [References](#10-references)

---

## 1. Introduction

Titan is a multilinear polynomial commitment scheme (PCS) built in two tiers:

1. **Pedersen-commit the matrix form of the witness.** A multilinear `ftilde` on
   `m` variables with `n = 2^m` coefficients is viewed as a `q x q` matrix with
   `q = 2^(m/2) = sqrt(n)`. Row `i` is Pedersen-committed to a single group
   element `G_i = sum_j ftilde_i(<j>) * g_j`.
2. **Commit the resulting group vector with a WHIR-style IOPP.** The `q` group
   elements are interpolated into a *group* multilinear `Gtilde` with
   `Gtilde(<i>) = G_i`, and `Gtilde` is committed by a Reed-Solomon IOPP that
   works over group elements rather than field elements.

The oracle for `Gtilde` *is* the commitment to `ftilde`.

## 2. Why Titan

The deciding reason for this codebase: **a group polynomial commitment scheme
falls out as a by-product.** The second tier already commits a group multilinear,
so committing to a group polynomial directly needs no new machinery — the same
IOPP serves both. Since the surrounding argument needs to commit both field and
group witnesses (see [sum-check](sumcheck.md), whose claims mix field and group
factors), one scheme covering both avoids maintaining two.

The two tiers also split the cost the way we want it: the expensive
multi-exponentiation is `O(n)` once, in tier 1, and everything after it runs at
`O(sqrt(n))`.

## 3. The Univariate-Multilinear Correspondence

The IOPP is a univariate Reed-Solomon proximity test, but the committed object is
multilinear. The two are joined by evaluating the multilinear along the *power
curve*:

```
fhat(X) := ftilde(X, X^2, X^4, ..., X^(2^(m-1)))
```

`fhat` is univariate of degree at most `2^m - 1`, and the map `ftilde -> fhat` is
injective: a multilinear monomial `prod_{j in S} X_j` maps to `X^(sum_{j in S} 2^j)`,
and distinct subsets `S` give distinct binary numbers, so no two of the `2^m`
coefficients collide. Committing `fhat` therefore commits `ftilde`.

"Encoding the oracle" means evaluating `fhat` on every point of the domain `L`.

## 4. Oracle Encoding

Evaluating `fhat` pointwise would cost one multi-exponentiation per domain point.
Instead the encoder runs a butterfly in `m` passes over the domain, using the
multilinear identity in the leading variable

```
ftilde(x, x^2, ...) = ftilde(0, x^2, ...) + x * (ftilde(1, x^2, ...) - ftilde(0, x^2, ...))
```

together with the fact that a smooth multiplicative subgroup is closed under
squaring: `x` and `-x` square to the same value, so a single scalar
multiplication `factor = (hi - lo) * x` yields **both** outputs, `lo + factor` at
`x` and `lo - factor` at `-x`. That is the standard FFT butterfly, and it costs

```
(n/2) * log n     scalar multiplications
```

against roughly `n * log n` for forming the coefficients of `fhat` explicitly.

### 4.1 Two Details That Are Easy to Get Wrong

**Bit-reversal comes first.** The butterfly consumes variables from the high bit
of the index downwards, pairing the first pass with the highest power
`x^(2^(m-1))`. But this repository indexes evaluation tables **little-endian** —
entry `i` holds `p(b_0, ..., b_(m-1))` with `b_j` the `j`-th bit of `i`, so `b_0`
sits at the low bit (see [sum-check §2.2](sumcheck.md#22-representation)). A
bit-reverse permutation before the butterfly relabels the variables in reverse, so
that bit 0 holds `b_(m-1)` and the passes come out in the order the power curve
needs. Omitting it silently encodes a *different* polynomial —
`TestEncodeFieldOracleMatchesNaive` fails at `m=2` without it.

**The blow-up repeats, it does not zero-pad.** When the domain is larger than the
message (`d > m`, which is what gives the code its rate and hence the IOPP its
distance), each coefficient is repeated `2^(d-m)` times. Repetition is what makes
the first pass see a constant on each block, which is the degree-0 base case of
the recursion. Zero-padding instead produces the wrong codeword.

## 5. The Evaluation Domain

`Domain` is the multiplicative subgroup `L` of `Fr` of order `2^d`, materialized
as the full list of its elements in generator order (`Elements[i] = Generator^i`).
The butterfly indexes this slice at power-of-two strides, so laying the elements
out beats recomputing them; at the `O(sqrt(n))` sizes Titan encodes, the slice is
negligible.

`NewDomain` builds on `gnark-crypto`'s `fft.NewDomain` for the root of unity, then
enumerates the powers. `fft.NewDomain` *panics* past the field's two-adicity, so
`NewDomain` bounds `logSize` by `MaxLogDomainSize` first and returns
`ErrDomainTooLarge` instead.

## 6. API

```go
import "github.com/LFDT-Panurus/panurus/token/core/zkatdlog/nogh/v1/crypto/titan"

dom, err := titan.NewDomain(11)          // |L| = 2^11, rate 1/2 for m = 10
if err != nil {
    return errors.Wrap(err, "failed to build evaluation domain")
}

codeword, err := titan.EncodeGroupOracle(groupPoly, dom)   // []bls12381.G1Affine
if err != nil {
    return errors.Wrap(err, "failed to encode group oracle")
}
```

| Function | Input | Output | Used for |
|----------|-------|--------|----------|
| `NewDomain(logSize)` | `d` | `*Domain` | the Reed-Solomon evaluation domain `L` |
| `EncodeGroupOracle(p, dom)` | `sumcheck.GroupPoly` | `[]bls12381.G1Affine` | the committed oracle for `Gtilde` |
| `EncodeFieldOracle(p, dom)` | `sumcheck.FieldPoly` | `[]fr.Element` | the public generator polynomial `gtilde`, which the verifier recomputes |

Both encoders take the polynomial types from
[`crypto/sumcheck`](../../token/core/zkatdlog/nogh/v1/crypto/sumcheck) rather than
redeclaring them, so a polynomial can be committed and sum-checked without
conversion. Neither modifies its input.

The domain must be at least as large as the polynomial (`ErrDomainTooSmall`
otherwise); a strictly larger domain is what gives the code a rate below 1.

## 7. Performance Notes

Measured on an Apple M4 Max, rate-1/2 domain (`d = m + 1`):

| `m` | Butterfly | Naive (per-point evaluation) | Speedup |
|-----|-----------|------------------------------|---------|
| 6 | 16.6 ms | 325 ms | **19.5x** |
| 8 | 82.3 ms | 5374 ms | **65x** |
| 10 | 431 ms | — | — |

The speedup grows with `m` because the naive baseline is quadratic in `n` in
scalar multiplications while the butterfly is `n log n`.

### 7.1 Where the Remaining Cost Is, and the Obvious Next Optimization

The butterfly performs exactly one scalar multiplication per node. For `m = 10`,
`d = 11` that is **10240** scalar multiplications, matching `(n/2) * log n = 11264`
to within the `d > m` bookkeeping. Since scalar multiplications are ~137x more
expensive than curve additions on this curve
([sum-check §6.2](sumcheck.md#62-scalar-multiplication-dominates-the-group-path)),
they are essentially the whole cost.

The distinct-root count per pass is heavily skewed:

| pass | nodes | distinct roots |
|------|-------|----------------|
| 0 | 1024 | 2 |
| 1 | 1024 | 4 |
| … | … | … |
| 9 | 1024 | 1024 |

So the early passes multiply many different points by the *same* few scalars.
Grouping a pass's nodes by root and applying each root with one multi-scalar
multiplication would amortize window precomputation the way `groupRoundEvals`
already does in sum-check. This is **not implemented** — it is a tuning change
with no effect on the output, deliberately deferred so the first cut stays
verifiable against the reference.

## 8. Porting Notes: Rust/Pasta to Go/BLS12-381

The reference implementation is Rust over the Pasta curves. Two things made the
port safe:

- **Two-adicity is identical.** Pallas's `Fq` and BLS12-381's `Fr` both have
  two-adicity **32** (verified by factoring `r - 1`, not by trusting
  documentation). Any smooth domain expressible in the reference is expressible
  here, so the encoding carries over with no change of domain strategy. This was
  the single largest portability risk and it is a non-issue.
- **The indexing convention already agrees.** The Rust code indexes multilinear
  coefficients as `coeffs[b_1 + 2*b_2 + ... + 2^(m-1)*b_m]`, which is the same
  little-endian layout this repository uses. The bit-reversal and butterfly port
  essentially as-is.

Where the reference is *not* usable as a guide, it is called out in
[`plan.md`](../../plan.md): the Rust group-sum-check **verifier** is incomplete
(its final evaluation is commented out and its round loop runs one round short),
so the Go verifier must be written from the paper rather than ported.

## 9. Testing

| File | Coverage |
|------|----------|
| `encode_test.go` | naive cross-check for `m ∈ 1..8` (field) and `1..6` (group) × rates `d - m ∈ {0,1,2}`; group-vs-field-scaled cross-check; degree bound via inverse DFT; domain generator primitivity and distinctness; bit-reversal semantics; input immutability; validation errors |
| `encode_bench_test.go` | butterfly vs naive baseline |

Statement coverage is **98.1%**, race-clean.

The decisive test is the **naive cross-check**: for every domain point, the
butterfly output must equal `GroupPoly.EvaluatePoint` along the power curve. The
naive side reuses the independently-tested evaluator from `crypto/sumcheck`, so
the two sides share no code.

`TestEncodeGroupMatchesFieldScaled` is the strongest structural check: with
`g(x) = [s(x)]G`, the group codeword must be the field codeword scaled into G1
pointwise. An error in the group butterfly that a group-only test would reproduce
on both sides shows up here.

Tests were confirmed non-vacuous by **mutation testing** — each of these
independently fails the suite:

| Mutation | Caught by |
|----------|-----------|
| drop the bit-reversal (field) | `TestEncodeFieldOracleMatchesNaive`, `TestEncodeDegreeBound` |
| drop the bit-reversal (group) | `TestEncodeGroupOracleMatchesNaive`, `TestEncodeGroupMatchesFieldScaled` |
| root stride off by one power | all three encode tests |
| reverse the pass order | all three encode tests |
| swap the `+`/`-` butterfly outputs | `TestEncodeFieldOracleMatchesNaive` |
| zero-pad instead of repeat on blow-up | `TestEncodeFieldOracleMatchesNaive` |

Run locally:

```bash
go test ./token/core/zkatdlog/nogh/v1/crypto/titan/
go test ./token/core/zkatdlog/nogh/v1/crypto/titan/ -run='^$' -bench=. -benchtime=3x
```

There is no fuzz target yet: this package has no deserializer or other
attacker-controlled parsing entry point so far. One is owed when proof
deserialization lands, and it must be registered in
[`.github/workflows/nightly-fuzz.yml`](../../.github/workflows/nightly-fuzz.yml) —
a target absent from that matrix is only exercised by its seed corpus.

## 10. References

- Titan paper — `eprint_version/` in the `titan` project; `group-sum-check.tex`
  covers the group oracle encoding and the efficient group sum-check.
- Rust reference implementation — the `titan-implementation` project
  (`src/utils.rs` for `multilinear_fft`, `src/group_sumcheck.rs` for the group
  sum-check).
- Arnon, Chiesa, Fenzi, Yogev, *WHIR: Reed–Solomon Proximity Testing with
  Super-Fast Verification* — the IOPP Titan adapts.
- Attema, Cramer, *Compressed Sigma-Protocol Theory* — the CSP used to close the
  evaluation argument.
- [Sum-Check Protocol](sumcheck.md) — the polynomial types and folding convention
  this package builds on.
