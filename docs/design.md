# eth-ntt Design and Optimizations

Reference: Longa, P. and Naehrig, M. "Speeding up the Number Theoretic Transform for Faster Ideal Lattice-Based Cryptography." IACR ePrint 2016/504. https://eprint.iacr.org/2016/504.pdf

Also, yes this document was written by AI because it was easier and faster than doing this by hand.

## Overview

eth-ntt implements NTT-based polynomial arithmetic as an Ethereum EVM precompile for post-quantum cryptographic signature verification (FALCON-512, Dilithium, Kyber). The implementation follows the algorithms and optimization strategies from Longa-Naehrig 2016, adapted for an EVM precompile context where field parameters arrive in calldata.

## Mathematical Foundation

### Ring Setting

Polynomial arithmetic operates in the quotient ring R_q = Z_q[X]/(X^n + 1), where:
- q is a prime satisfying q = 1 (mod 2n)
- n is a power of 2
- X^n + 1 is the 2n-th cyclotomic polynomial

This ring structure is the basis of Ring-LWE (R-LWE) cryptographic schemes. The congruence condition on q ensures that the finite field Z_q contains primitive 2n-th roots of unity, which are required for the NTT.

### Negative Wrapped Convolution

Direct polynomial multiplication in R_q via NTT would require doubling the input length and explicit reduction modulo X^n + 1. The negative wrapped convolution avoids this by introducing a primitive 2n-th root of unity psi (where psi^2 = omega, the n-th root of unity). Following Longa-Naehrig Section 2.2:

1. Pre-multiply inputs by powers of psi: a_hat[i] = a[i] * psi^i
2. Apply standard NTT of length n
3. Point-wise multiply in the NTT domain
4. Apply inverse NTT
5. Post-multiply by inverse powers of psi: c[i] = result[i] * psi^(-i)

In our implementation (following the paper's optimization), the psi multiplications are absorbed into the twiddle factors stored in bit-reversed order, eliminating the separate pre/post-multiplication steps entirely.

## NTT Algorithms

### Forward NTT: Cooley-Tukey Butterfly (Algorithm 1 from the paper)

The forward transform uses the decimation-in-time Cooley-Tukey butterfly. It takes input in standard order and produces output in bit-reversed order. The key structure:

```
t = n
for m = 1; m < n; m = 2m:
    t = t/2
    for i = 0 to m-1:
        S = psi_rev[m + i]
        for j = j1 to j1+t-1:
            U = a[j]
            V = a[j+t] * S mod q
            a[j]   = U + V mod q
            a[j+t] = U - V mod q
```

The twiddle factor table psi_rev stores powers of psi in bit-reversed order, so that psi_rev[m+i] = psi^(bitrev(i, log(m))). This eliminates the need for a separate bit-reversal permutation step.

### Inverse NTT: Gentleman-Sande Butterfly (Algorithm 2 from the paper)

The inverse transform uses the decimation-in-frequency Gentleman-Sande butterfly. It takes input in bit-reversed order and produces output in standard order. This pairing (CT forward + GS inverse) eliminates any explicit bit-reversal step, following the approach of Poppelmann et al. cited in the paper.

```
t = 1
for m = n; m > 1; m = m/2:
    h = m/2
    for i = 0 to h-1:
        S = psi_inv_rev[h + i]
        for j = j1 to j1+t-1:
            U = a[j]
            V = a[j+t]
            a[j]   = U + V mod q
            a[j+t] = (U - V) * S mod q
    t = 2t
for j = 0 to n-1:
    a[j] = a[j] * n^(-1) mod q
```

### Polynomial Multiplication Pipeline

A full polynomial multiply in R_q uses three precompile calls:

1. NTT_FW(f) and NTT_FW(g) - forward transforms
2. VECMULMOD(NTT(f), NTT(g)) - point-wise multiply
3. NTT_INV(product) - inverse transform

Total gas: 600 + 600 + 18 + 600 = 1818 for Falcon-512 parameters.

## Optimization Tiers

### Tier 1: BigUint Elimination (600x speedup)

The baseline implementation used heap-allocated arbitrary-precision BigUint for all modular arithmetic. Since practical lattice moduli fit in native integers (Falcon q=12289 is 14 bits, Dilithium q=8380417 is 23 bits), this is massively wasteful.

The fast path (`src/fast.rs`) uses native u64 arithmetic with u128 intermediates for modular multiplication:

```rust
fn mul_mod(a: u64, b: u64, q: u64) -> u64 {
    ((a as u128 * b as u128) % q as u128) as u64
}
```

Twiddle factor tables are precomputed once at `FastNttParams` construction time using u64 modular exponentiation, replacing the per-call BigUint modpow that dominated the original profile.

Dispatch: the precompile entry points (`ntt_fw_precompile`, etc.) try the fast path first by parsing q and psi directly as u64 from the calldata bytes, falling back to BigUint only if q >= 2^63.

### Tier 2: Montgomery Multiplication (additional 2x speedup)

For q < 2^31 (all practical lattice schemes), the implementation uses u32 Montgomery multiplication following the approach discussed in Longa-Naehrig Section 3 ("A remark on residue classes"). Montgomery form represents values as a_bar = a * R mod q where R = 2^32, replacing expensive division-based modular reduction with cheap multiply-shift operations.

Key constants precomputed at construction:
- q' = -q^(-1) mod 2^32 (via Newton's method, 5 iterations)
- R^2 mod q (for converting to Montgomery form)

The Montgomery reduction (REDC):
```rust
fn mont_redc(t: u64, q: u32, q_prime: u32) -> u32 {
    let m = (t as u32).wrapping_mul(q_prime);
    let u = (t.wrapping_add(m as u64 * q as u64)) >> 32;
    if u >= q { u - q } else { u }
}
```

This replaces the u128 software division (`__udivti3` on AArch64) with three native multiplies and a shift. The twiddle factor tables are stored in Montgomery form, so the butterfly inner loop operates entirely in the Montgomery domain. Conversion to/from Montgomery form happens only at the NTT input/output boundaries.

The paper's K-RED reduction (Section 3) exploits the special structure of Proth primes (q = k * 2^m + 1) for even cheaper reduction. Our Montgomery approach is more general (works for any q < 2^31) but achieves similar goals: eliminating expensive division from the hot loop.

### Tier 3: Precompile Fast-Path Decode

The precompile entry points bypass BigUint entirely for small moduli:
- Parse q_len, psi_len, n from the 32-byte ABI words
- If q_len <= 8: decode q, psi as u64 directly from bytes
- Construct FastNttParams (which internally selects Montgomery or u64)
- Decode coefficient vector directly as u64/u32
- Encode output directly from u64/u32

This eliminates all heap allocation for the common case.

## Architecture: Three Arithmetic Backends

```
q < 2^31   -->  MontData   (u32 Montgomery, no division)
q in [2^31, 2^63)  -->  U64Data    (u64 with u128 intermediate)
q >= 2^63  -->  BigUint    (arbitrary precision, heap-allocated)
```

Selection is automatic in `FastNttParams::new()` based on the modulus size. The precompile dispatch adds a fourth layer: it tries `FastNttParams` first and falls back to the BigUint `FieldParams` path.

## Performance Summary (Falcon-512, n=512, q=12289)

| Operation | BigUint | Fast u64 | Montgomery | Speedup |
|---|---|---|---|---|
| NTT forward | 2.98 ms | 4.81 us | 2.43 us | 1,226x |
| NTT inverse | 3.13 ms | 5.44 us | 2.20 us | 1,423x |
| Poly multiply | 9.97 ms | 15.9 us | 7.9 us | 1,262x |
| FALCON verify sim | 9.36 ms | 16.1 us | 7.45 us | 1,256x |
| Precompile NTT_FW | 3.15 ms | 30.2 us | 18.9 us | 167x |

## Future Optimization Opportunities

### SIMD Vectorization (estimated 4-8x additional)
The butterfly inner loop is amenable to SIMD: for small moduli like Falcon's q=12289, multiple coefficients can be packed into AVX2 (8x u32) or NEON (4x u32) registers. This would require platform-specific code paths with `#[cfg(target_arch)]`.

### Lazy Reduction
Following the paper's approach (Section 3, "Speeding up the NTT"), coefficients can be allowed to grow beyond [0, q) during intermediate butterfly stages, with reduction applied only when overflow threatens. For Falcon's 14-bit q with 32-bit arithmetic, this can eliminate several reduction steps per butterfly.

### Precompile Table Caching
Currently `FastNttParams` is reconstructed from calldata on every precompile call (~14us for table generation). A cache keyed on (q, n, psi) would amortize this cost across repeated calls with the same parameters.

## File Structure

- `src/field.rs` - BigUint field arithmetic, parameter validation
- `src/ntt.rs` - BigUint NTT (reference/fallback implementation)
- `src/fast.rs` - Optimized NTT with Montgomery/u64 backends
- `src/precompile.rs` - EVM precompile ABI: encode/decode/dispatch
- `src/ffi.rs` - C FFI for Go bindings
- `include/eth_ntt.h` - C header
- `go/ntt/` - Go bindings via CGo
