# ML-DSA Wallet POC

Small ML-DSA verifier/executor POC for this testnet's precompile flow.

High-level flow:

1. Generate an ML-DSA-44 keypair off-chain.
2. Deploy `MLDSAWallet` as a generic runtime-key verifier/executor.
3. Build an operation payload off-chain and sign `0x0000 || keccak256(operation)` with ML-DSA.
4. Relay a normal Ethereum transaction to `MLDSAWallet.execute(...)`, passing the ML-DSA public key at runtime.
5. The wallet calls the ML-DSA precompile at `0x1b`.
6. If valid, the wallet executes the target call and increments the nonce tracked for `keccak256(publicKey)`.

## Layout

- `sol/MLDSAWallet.sol`: runtime-key verifier/executor with per-key nonces
- `sol/DemoRecipient.sol`: simple target contract for the POC action
- `rust/src/bin/keygen.rs`: generate an ML-DSA-44 keypair locally
- `rust/src/bin/deploy.rs`: deploy `DemoRecipient` and `MLDSAWallet`
- `rust/src/bin/verify_deployment.rs`: check deployment state and optional per-key nonce
- `rust/src/bin/execute_pq_tx.rs`: sign an operation and relay it through the verifier
- `exec.sh`: tiny shell wrapper with `keygen`, `deploy`, `verify`, and `execute` subcommands

## Requirements

- `solc` 0.8.25+ on your path
- `cast` on your path
- Rust / Cargo

## Rust Tools

The helper lives under `rust/`

Available binaries:

- `keygen`
- `deploy`
- `verify_deployment`
- `execute_pq_tx`

Build them with:

```bash
cargo build --offline --manifest-path ./rust/Cargo.toml
```

Examples:

```bash
./rust/target/debug/keygen

RPC_URL=http://65.109.17.230:33952 PRIVATE_KEY=... \
  ./rust/target/debug/deploy

RPC_URL=http://65.109.17.230:33952 \
  ./rust/target/debug/verify_deployment

RPC_URL=http://65.109.17.230:33952 \
  ./rust/target/debug/execute_pq_tx --dry-run-only
```

## One-Command Wrapper

From inside `./ml-dsa_wallet`:

```bash
./exec.sh keygen
RPC_URL=http://65.109.17.230:33952 PRIVATE_KEY=... ./exec.sh deploy
RPC_URL=http://65.109.17.230:33952 ./exec.sh verify
RPC_URL=http://65.109.17.230:33952 ./exec.sh execute --dry-run-only
RPC_URL=http://65.109.17.230:33952 PRIVATE_KEY=... ./exec.sh execute --note "hello from phone wallet"
```

## 1. Generate ML-DSA keys

```bash
./exec.sh keygen
```

This writes:

- `ml-dsa_wallet/state/ml_dsa_keypair.json`

## 2. Deploy contracts

Set your relayer key and RPC:

```bash
export RPC_URL=http://65.109.17.230:33952
export PRIVATE_KEY=...
./exec.sh deploy
```

This writes:

- `ml-dsa_wallet/state/deployment.json`

The deploy step does not require the ML-DSA keypair because the contract does not store a public key on-chain.

## 3. Verify deployment

```bash
./exec.sh verify
```

If `state/ml_dsa_keypair.json` exists, `verify` also shows the current nonce for that runtime public key.

## 4. Execute a PQ-authorized wallet action

Dry run first:

```bash
./exec.sh execute --dry-run-only
```

Send the real transaction:

```bash
./exec.sh execute --note "hello from phone wallet"
```

## Signed payload

The wallet signs the digest:

```text
keccak256(abi.encode(
  chainId,
  walletAddress,
  keccak256(publicKey),
  nonce,
  target,
  value,
  keccak256(calldata),
  deadline
))
```

The ML-DSA signature is produced over:

```text
0x0000 || digest
```

This matches the repo's ML-DSA verification convention for `ml_dsa_44`.
