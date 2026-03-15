# Precompile API Reference

## Formats

### Raw format (generic)
Coefficients encoded as variable-length big-endian bytes with explicit headers specifying field parameters (q, n, psi). Works with any field.

### Compact format (Falcon-512 specific)
1024 bytes = 32 big-endian uint256 words. Each word packs 16 little-endian uint16 coefficients:

```
word[i] = coeff[0] | (coeff[1] << 16) | ... | (coeff[15] << 240)
```

Stored big-endian in memory (EVM native). Field params hardcoded: q=12289, n=512, psi=49.

---

## Generic Precompiles

### `0x12` — NTT_FW (Forward NTT)

**Input:**
```
q_len    (32 bytes BE)   — byte length of q
psi_len  (32 bytes BE)   — byte length of psi
n        (32 bytes BE)   — polynomial dimension
q        (q_len bytes)   — prime modulus, big-endian
psi      (psi_len bytes) — primitive 2n-th root of unity mod q
coeffs   (n × cb bytes)  — coefficients, big-endian (cb = ceil(bits(q)/8))
```

**Output:** `n × cb` bytes — NTT-transformed coefficients, big-endian.

**Gas:** 600

---

### `0x13` — NTT_INV (Inverse NTT)

Same input/output format as `0x12`. Computes the inverse NTT with scaling by n⁻¹ mod q.

**Gas:** 600

---

### `0x14` — VECMULMOD (Vector Modular Multiply)

**Input:**
```
q_len  (32 bytes BE)
n      (32 bytes BE)
q      (q_len bytes)
a      (n × cb bytes)   — first vector
b      (n × cb bytes)   — second vector
```

**Output:** `n × cb` bytes — `a[i] × b[i] mod q` for each i.

**Gas:** `k × log2(n) / 8` where k = next_power_of_two(bits(q))

---

### `0x15` — VECADDMOD (Vector Modular Add)

Same format as `0x14`. Computes `a[i] + b[i] mod q`.

**Gas:** `k × log2(n) / 32`

---

### `0x16` — SHAKE256

**Input:**
```
output_len  (32 bytes BE)  — desired output length
data        (var bytes)    — data to hash
```

**Output:** `output_len` bytes of SHAKE256(data).

**Gas:** `30 + 6 × ceil(len(data) / 32)` (same as KECCAK256)

---

## Falcon-512 Compact Precompiles

### `0x17` — NTT_FW_COMPACT

**Input:** 1024 bytes (compact format)

**Output:** 1024 bytes (compact format) — forward NTT of input.

**Gas:** 1000

---

### `0x18` — NTT_INV_COMPACT

**Input:** 1024 bytes (compact format)

**Output:** 1024 bytes (compact format) — inverse NTT of input.

**Gas:** 1000

---

### `0x19` — VECMULMOD_COMPACT

**Input:** 2048 bytes — two compact vectors concatenated: `a(1024) || b(1024)`

**Output:** 1024 bytes (compact format) — `a[i] × b[i] mod 12289`.

**Gas:** 200

---

### `0x1a` — SHAKE256_HTP (Hash-to-Point)

**Input:** `salt || message` (variable length, typically 40+ bytes)

**Output:** 1024 bytes (compact format) — 512 coefficients mod 12289 via SHAKE256 rejection sampling (threshold 61445).

**Gas:** `30 + 6 × ceil(input_len / 32)`

---

### `0x1b` — FALCON_NORM (LpNorm)

**Input:** 3072 bytes — three compact vectors: `s1(1024) || s2(1024) || hashed(1024)`

**Output:** 32 bytes — `0x00..01` if `||(hashed - s1) mod q||² + ||s2||² < 34034726`, else `0x00..00`.

**Gas:** 400

---

### `0x1c` — FALCON_VERIFY

Full Falcon-512 signature verification in a single call. Performs SHAKE256 hash-to-point, forward NTT, pointwise multiply, inverse NTT, and centered L2 norm check.

Follows standard precompile conventions: flat big-endian arrays, no custom packing.

**Input:**
```
s2       (1024 bytes)  — signature polynomial s2, 512 × uint16 big-endian
ntth     (1024 bytes)  — public key in NTT domain, 512 × uint16 big-endian
salt_msg (var bytes)   — nonce (40 bytes) || message (remainder of input)
```

Each coefficient is a 2-byte big-endian unsigned integer (max value 12288).

**Output:** 32 bytes — `0x0000...0001` if signature is valid, `0x0000...0000` if invalid. Same convention as `bn256Pairing` (`0x08`).

**Gas:** 2800

**Example:**
```
Input:  [s2_0_hi, s2_0_lo, s2_1_hi, s2_1_lo, ..., s2_511_hi, s2_511_lo,
         ntth_0_hi, ntth_0_lo, ..., ntth_511_hi, ntth_511_lo,
         nonce_byte_0, ..., nonce_byte_39, msg_byte_0, ...]
Output: 0x0000000000000000000000000000000000000000000000000000000000000001
```

---

## Generalized Precompiles

### LpNorm (Rust API, address TBD)

Centered L2 norm check for any lattice-based signature scheme.

**Input:**
```
q      (32 bytes BE) — field modulus
n      (32 bytes BE) — dimension
bound  (32 bytes BE) — squared norm bound
cb     (32 bytes BE) — coefficient byte width (2 for Falcon, 4 for Dilithium)
s1     (n × cb bytes, BE) — first component
s2     (n × cb bytes, BE) — second component
hashed (n × cb bytes, BE) — hash-to-point result
```

**Output:** 32 bytes — `0x00..01` if `||(hashed - s1) mod q||² + ||s2||² < bound`, else `0x00..00`.

---

## Benchmarks (Apple M4, Rust native)

| Precompile | Time | Gas (350 Mgas/s) |
|---|---|---|
| NTT_FW | 2.8 µs | 1000 |
| NTT_INV | 2.8 µs | 1000 |
| VECMULMOD | 590 ns | 200 |
| SHAKE256_HTP | 1.8 µs | 600 |
| FALCON_NORM | 1.0 µs | 400 |
| **FALCON_VERIFY** | **8.1 µs** | **2800** |
