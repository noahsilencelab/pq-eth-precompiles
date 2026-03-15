# Kurtosis Devnet + Falcon-512 Verification

End-to-end Falcon-512 post-quantum signature verification on Ethereum using NTT precompiles, running on a local Kurtosis devnet with custom Erigon.

## Architecture

```
                Python fuzzer
                    │
                    ▼ (eth_call / eth_sendRawTransaction)
            ┌───────────────┐
            │  Kurtosis EL  │  Custom Erigon with precompiles:
            │  (Erigon)     │  0x12-0x15: generic NTT/VEC/ADD
            │               │  0x17-0x1a: Falcon-512 compact format
            │               │  0x1b: LpNorm (generalized lattice norm)
            └───────┬───────┘
                    │ staticcall
                    ▼
            ┌───────────────┐
            │  Yul V4       │  116 bytes runtime
            │  (on-chain)   │  5 precompile calls, ~98k gas
            └───────────────┘
```

## Prerequisites

- Docker
- [Kurtosis CLI](https://docs.kurtosis.com/install/)
- Python 3.10+ with: `pip install web3 py-solc-x pqcrypto eth-abi`
- Solidity compiler: `pip install solc-select && solc-select install 0.8.26 && solc-select use 0.8.26`
- Erigon source at `../erigon/` (clone from https://github.com/erigontech/erigon)

## Quick Start

### 1. Launch the devnet

```bash
cd kurtosis/devnet
bash launch.sh
```

This builds a custom Erigon Docker image with NTT precompiles and starts a Kurtosis enclave with Lighthouse CL + Erigon EL, Osaka fork active at genesis.

### 2. Run the fuzzer

```bash
RPC_URL=http://127.0.0.1:<PORT> python3 kurtosis/scripts/falcon_fuzz.py
```

The fuzzer:
- Deploys both a Solidity oracle (ZKNOX_falcon) and the Yul V4 contract
- Generates random Falcon-512 keypairs and signatures
- **First byte of fuzz input even** → invalid signature (wrong msg / corrupted s2 / wrong key)
- **First byte odd** → valid signature
- Cross-checks Solidity oracle vs Yul V4 vs Python reference
- Runs at ~87 iterations/sec via `eth_call`

### 3. Run the demo

```bash
RPC_URL=http://127.0.0.1:<PORT> python3 kurtosis/scripts/falcon_demo.py
```

Deploys the ZKNOX_falcon Solidity contract, signs messages with pqcrypto, verifies on-chain.

## Contracts

| Contract | File | Gas | Runtime | Strategy |
|---|---|---|---|---|
| FalconVerifierDirectVerify | `contracts/FalconVerifierDirectVerify.yul` | **97k** | 25B | Single FALCON_VERIFY call |
| FalconVerifierNTTWithLpNorm | `contracts/FalconVerifierNTTWithLpNorm.yul` | 98k | 116B | NTT precompiles + LpNorm |
| FalconVerifierNTT | `contracts/FalconVerifierNTT.yul` | 180k | 266B | NTT precompiles + on-chain norm |

## Precompiles

| Address | Name | Input | Output | Gas |
|---|---|---|---|---|
| 0x12 | NTT_FW | q_len\|psi_len\|n\|q\|psi\|coeffs | coeffs | 600 |
| 0x13 | NTT_INV | (same as NTT_FW) | coeffs | 600 |
| 0x14 | VECMULMOD | q_len\|n\|q\|a\|b | result | variable |
| 0x15 | VECADDMOD | (same as VECMULMOD) | result | variable |
| 0x16 | SHAKE256 | outlen(32)\|data | output | 30 + 6×words |
| 0x17 | FALCON_VERIFY | s2(1024)\|ntth(1024)\|salt_msg | 32B bool | 2800 |

See [docs/precompiles.md](../docs/precompiles.md) for full API reference.

## Gas Breakdown (FalconVerifierDirectVerify, ~97k total)

| Component | Gas | % |
|---|---|---|
| Base tx | 21,000 | 21.6% |
| Calldata (2.1KB) | ~30,600 | 31.5% |
| Cold STATICCALL | 2,600 | 2.7% |
| FALCON_VERIFY | 2,800 | 2.9% |
| EVM overhead | ~40,000 | 41.3% |

The actual cryptography is **2.9%** of total gas.

## Tear Down

```bash
kurtosis enclave rm -f falcon-devnet
```
