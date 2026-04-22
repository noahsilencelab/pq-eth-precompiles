# Falcon Probe

Small helper project for probing the live Falcon precompiles from this repo.

It does two things:

1. `src/main.rs` generates a real Falcon-512 keypair and signature, then prints:
   - message
   - public key
   - signature
   - decoded nonce
   - decoded public key polynomial `h`
   - decoded signature polynomial `s2`
2. `check_live_precompile.py` calls the live precompiles:
   - `0x12` for `NTT(h)`
   - `0x17` for `FALCON_VERIFY`

## Build

```bash
cargo run --offline --manifest-path falcon_probe/Cargo.toml
```

## Check a live RPC

```bash
python3 falcon_probe/check_live_precompile.py \
  --rpc http://65.109.17.230:33952
```

The checker expects the compiled binary at:

`falcon_probe/target/debug/falcon_probe`
