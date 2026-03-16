# Benchmarks

Measured on Kurtosis devnet (Erigon + Lighthouse, Osaka fork). 16,090 fuzz iterations, 0 failures.

## Transaction cost

| Contract | Total Gas | Overhead | Verification | Verification Time |
|---|---|---|---|---|
| NTT | 210,441 | 109,175 | 101,266 | 8.1 us |
| NTTWithLpNorm | 98,780 | 97,114 | 1,666 | 8.1 us |
| DirectVerify | 98,780 | 95,980 | 2,800 | 8.1 us |

- **Total Gas**: charged to sender
- **Overhead**: base tx + calldata + cold STATICCALLs + on-chain EVM code (calldatacopy, memory, norm loop etc.)
- **Verification**: gas spent doing the actual Falcon-512 math inside precompiles
- **Verification Time**: wall-clock time for the cryptography in Rust (same for all three)

## Overhead breakdown

| Component | NTT | NTTWithLpNorm | DirectVerify |
|---|---|---|---|
| Base tx | 21,000 | 21,000 | 21,000 |
| Calldata (2,117 B) | 31,100 | 31,100 | 31,100 |
| Cold STATICCALLs | 10,400 (4x) | 13,000 (5x) | 2,600 (1x) |
| On-chain norm loop | ~100,000 | 0 | 0 |
| EVM glue | ~46,675 | ~32,014 | ~41,280 |

## Comparison

| Scheme | Verification Gas | Total Tx Gas | Post-quantum |
|---|---|---|---|
| ECDSA (ecrecover) | 3,000 | ~28,000 | No |
| **Falcon-512 (DirectVerify)** | **2,800** | **98,780** | **Yes** |
| BLS12-381 pairing (1 pair) | 43,000 | ~65,000 | No |

Falcon-512 verification is cheaper than ecrecover. The higher total tx gas is due to larger calldata (2 KB vs 128 bytes for ECDSA).
