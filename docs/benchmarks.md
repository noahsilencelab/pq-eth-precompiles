# Benchmarks

On-chain gas measurements from Kurtosis devnet (Erigon + Lighthouse, Osaka fork).

## Contract comparison

| Contract | Runtime | Deploy Gas | Verify Gas | Precompile Gas | Precompile Calls |
|---|---|---|---|---|---|
| FalconVerifierNTT | 322B | 122,572 | 210,261 | 1,266 | 4 |
| FalconVerifierNTTWithLpNorm | 322B | 122,572 | 210,261 | 1,266 | 4 |
| **FalconVerifierDirectVerify** | **25B** | **58,586** | **98,750** | **2,800** | **1** |

All contracts verified with 16,090 fuzz iterations, 0 failures.

## Gas breakdown: FalconVerifierDirectVerify (98,750 gas)

This contract does one `calldatacopy` + one `staticcall` to FALCON_VERIFY at `0x17`.

| Component | Gas | % | Notes |
|---|---|---|---|
| Base transaction | 21,000 | 21.3% | Fixed EIP-2718 cost, unavoidable |
| Calldata intrinsic | 31,100 | 31.5% | 16 gas/nonzero byte, 4 gas/zero byte for 2,117 bytes |
| Cold address access | 2,600 | 2.6% | EIP-2929: first STATICCALL to 0x17 |
| FALCON_VERIFY execution | 2,800 | 2.8% | NTT + SHAKE256 + VECMUL + norm check in Rust |
| EVM bytecode | ~400 | 0.4% | calldatacopy + staticcall + return (3 opcodes) |
| Memory expansion | ~200 | 0.2% | Expand to ~2KB for precompile input |
| *Accounting overlap* | *~40,650* | *41.2%* | *Calldata intrinsic counted in both tx receipt and execution trace* |

**The actual cryptography is 2.8% of total gas.** The rest is Ethereum's fixed costs for accepting a transaction and reading its data.

### What each cost means

- **Base transaction (21k)**: Every Ethereum transaction pays this. Cannot be reduced.
- **Calldata intrinsic (31k)**: The cost of including 2,117 bytes in a block. Falcon-512 requires sending two 1,024-byte polynomials + a 40-byte nonce + message. This is the dominant cost.
- **Cold address access (2.6k)**: First time the contract calls address 0x17 in a transaction. Would be 100 gas if warm (EIP-2930 access list), but the access list itself costs ~2,400 gas, so net savings are negligible.
- **FALCON_VERIFY (2.8k)**: The precompile does all the math — SHAKE256 hash-to-point (1.8us), forward NTT (2.8us), pointwise multiply (0.6us), inverse NTT (2.8us), and norm check (1.0us). Priced at 350 Mgas/s throughput target.
- **EVM bytecode (~400)**: The contract itself is 25 bytes: copy calldata to memory, call precompile, return result.

## Gas breakdown: FalconVerifierNTT (210,261 gas)

This contract calls four generic precompiles and runs the norm check on-chain.

| Component | Gas | % | Notes |
|---|---|---|---|
| Base transaction | 21,000 | 10.0% | Fixed |
| Calldata intrinsic | 31,100 | 14.8% | Same data as DirectVerify |
| 4x cold address access | 10,400 | 4.9% | 0x12, 0x13, 0x14, 0x16 at 2,600 each |
| NTT_FW (0x12) | 600 | 0.3% | Forward NTT |
| VECMULMOD (0x14) | 18 | 0.0% | Pointwise multiply |
| NTT_INV (0x13) | 600 | 0.3% | Inverse NTT |
| SHAKE256 (0x16) | 48 | 0.0% | Hash-to-point |
| On-chain norm loop | ~100,000 | 47.6% | 512 iterations of mod + mul + add in EVM |
| EVM overhead | ~46,500 | 22.1% | Memory expansion, calldatacopy, header construction |

**The on-chain norm loop is 47.6% of total gas.** This is why FalconVerifierDirectVerify is 2x cheaper — it moves the norm check into the precompile.

## Precompile execution times (Rust native, Apple M4)

| Precompile | Address | Time | Gas | Operation |
|---|---|---|---|---|
| NTT_FW | 0x12 | 2.8 us | 600 | Forward Number Theoretic Transform |
| NTT_INV | 0x13 | 2.8 us | 600 | Inverse NTT with scaling |
| VECMULMOD | 0x14 | 590 ns | variable | Element-wise modular multiply |
| VECADDMOD | 0x15 | 590 ns | variable | Element-wise modular add |
| SHAKE256 | 0x16 | 1.8 us | variable | SHAKE256 extendable output |
| **FALCON_VERIFY** | **0x17** | **8.1 us** | **2,800** | **Full Falcon-512 verification** |

Gas prices target 350 Mgas/s throughput.

## Comparison with existing signature schemes

| Scheme | Precompile | Gas | Post-quantum |
|---|---|---|---|
| ECDSA (ecrecover) | 0x01 | 3,000 | No |
| **Falcon-512** | **0x17** | **2,800** | **Yes** |
| BLS12-381 pairing (1 pair) | 0x0f | 43,000 | No |
| On-chain ECDSA (no precompile) | — | ~300,000 | No |

Falcon-512 verification via precompile is cheaper than ecrecover.

## Calldata cost analysis

| Field | Bytes | Gas (16/nonzero, 4/zero) | % of calldata |
|---|---|---|---|
| s2 (signature polynomial) | 1,024 | ~15,800 | 51% |
| ntth (public key in NTT domain) | 1,024 | ~14,600 | 47% |
| nonce | 40 | ~600 | 2% |
| message (typical) | ~29 | ~100 | 0.3% |
| **Total** | **~2,117** | **~31,100** | **100%** |

The public key `ntth` costs ~15k gas per call. A contract that stores the key would save this, reducing verify gas to ~83k.
