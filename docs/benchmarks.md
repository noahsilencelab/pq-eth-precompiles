# Benchmarks

Measured on Kurtosis devnet (Erigon + Lighthouse, Osaka fork). 16,090 fuzz iterations, 0 failures.

## Transaction cost

Total gas charged to the sender, including base tx fee, calldata, and execution.

| Contract | Verify Gas | Runtime Size | Deploy Gas | Precompile Calls |
|---|---|---|---|---|
| FalconVerifierNTT | 210,441 | 322 B | 122,572 | 4 (0x12, 0x13, 0x14, 0x16) |
| FalconVerifierNTTWithLpNorm | 98,780 | 238 B | 104,396 | 5 (0x12, 0x13, 0x14, 0x16, 0x18) |
| FalconVerifierDirectVerify | 98,780 | 25 B | 58,586 | 1 (0x17) |

All three take the same calldata: `s2(1024) | ntth(1024) | salt_msg(~69)` = 2,117 bytes.

## Verification cost

Gas spent on the actual signature verification, excluding base tx (21,000) and calldata intrinsic (~31,100).

| Contract | Execution Gas | Precompile Gas | On-chain norm | EVM overhead | Crypto % |
|---|---|---|---|---|---|
| FalconVerifierNTT | 158,341 | 1,266 | ~100,000 | ~57,075 | 0.8% |
| FalconVerifierNTTWithLpNorm | 46,680 | 1,666 | 0 | ~45,014 | 3.6% |
| FalconVerifierDirectVerify | 46,680 | 2,800 | 0 | ~43,880 | 6.0% |

*Execution Gas = Verify Gas - base tx (21,000) - calldata intrinsic (~31,100)*

### What limits each contract

- **FalconVerifierNTT**: The on-chain norm loop (512 iterations of `mod` + `mul` + `add`) costs ~100k gas — the same math takes 1 microsecond in Rust.

- **FalconVerifierNTTWithLpNorm**: The norm loop is replaced by LP_NORM at 0x18 (400 gas). The remaining overhead is 5 cold address accesses (5 × 2,600 = 13,000) plus memory management.

- **FalconVerifierDirectVerify**: One precompile call does everything. The 43k overhead is 1 cold address access (2,600) + memory + calldata intrinsic double-counting in the trace.

### Fixed costs (same for all contracts)

| Cost | Gas | Why |
|---|---|---|
| Base transaction | 21,000 | EIP-2718, every tx pays this |
| Calldata (2,117 bytes) | ~31,100 | 16 gas/nonzero byte, 4 gas/zero byte |
| **Total fixed** | **~52,100** | **Cannot be reduced** |

## Comparison

| Scheme | Gas | Precompile | Post-quantum |
|---|---|---|---|
| ECDSA recovery | 3,000 | ecrecover (0x01) | No |
| **Falcon-512** | **2,800** | **FALCON_VERIFY (0x17)** | **Yes** |
| BLS12-381 pairing | 43,000 | 0x0f | No |
