use ml_dsa_wallet_tools::{
    cast_abi_encode, cast_call, cast_calldata, cast_keccak, cast_send, chain_id, ensure_0x,
    flag_value, has_flag, latest_block_timestamp, load_json, state_dir, string_field, strip_0x,
    Result,
};
use pqcrypto_dilithium::dilithium2;
use pqcrypto_traits::sign::{DetachedSignature as _, SecretKey as _};
use std::path::PathBuf;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let rpc_url = flag_value(&args, "--rpc")
        .or_else(|| std::env::var("RPC_URL").ok())
        .ok_or("missing --rpc or RPC_URL")?;
    let private_key =
        flag_value(&args, "--private-key").or_else(|| std::env::var("PRIVATE_KEY").ok());
    let deployment_path = flag_value(&args, "--deployment")
        .map(PathBuf::from)
        .unwrap_or_else(|| state_dir().join("deployment.json"));
    let key_file = flag_value(&args, "--key-file")
        .map(PathBuf::from)
        .unwrap_or_else(|| state_dir().join("ml_dsa_keypair.json"));
    let note =
        flag_value(&args, "--note").unwrap_or_else(|| "hello from ML-DSA wallet".to_string());
    let deadline_seconds = flag_value(&args, "--deadline-seconds")
        .map(|value| value.parse::<u64>())
        .transpose()?
        .unwrap_or(3600);
    let dry_run_only = has_flag(&args, "--dry-run-only");

    if !dry_run_only && private_key.is_none() {
        return Err("missing --private-key or PRIVATE_KEY".into());
    }

    let deployment = load_json(&deployment_path)?;
    let key_data = load_json(&key_file)?;
    let wallet = string_field(&deployment, "wallet_address")?;
    let target = string_field(&deployment, "demo_recipient_address")?;
    let public_key_hex = ensure_0x(string_field(&key_data, "public_key_hex")?);
    let key_hash = cast_keccak(&public_key_hex)?;

    let nonce = cast_call(
        &rpc_url,
        wallet,
        "nonces(bytes32)(uint256)",
        &[key_hash.clone()],
    )?
    .parse::<u64>()?;
    let current_chain_id = chain_id(&rpc_url)?;

    let stored_chain_id = deployment["chain_id"].as_u64().unwrap_or(current_chain_id);
    if stored_chain_id != current_chain_id {
        return Err(format!(
            "deployment chain id {} does not match current chain id {}",
            stored_chain_id, current_chain_id
        )
        .into());
    }

    let deadline = latest_block_timestamp(&rpc_url)? + deadline_seconds;
    let value = 0u64;

    let target_calldata = cast_calldata("setNote(string)", &[note.clone()])?;
    let calldata_hash = cast_keccak(&target_calldata)?;

    let encoded = cast_abi_encode(
        "f(uint256,address,bytes32,uint256,address,uint256,bytes32,uint256)",
        &[
            current_chain_id.to_string(),
            wallet.to_string(),
            key_hash.clone(),
            nonce.to_string(),
            target.to_string(),
            value.to_string(),
            calldata_hash.clone(),
            deadline.to_string(),
        ],
    )?;
    let digest = cast_keccak(&encoded)?;
    let message_hex = format!("0x0000{}", strip_0x(&digest));

    let secret_key_hex = string_field(&key_data, "secret_key_hex")?;
    let secret_key_bytes = hex::decode(secret_key_hex)?;
    let secret_key = dilithium2::SecretKey::from_bytes(&secret_key_bytes)?;
    let message_bytes = hex::decode(strip_0x(&message_hex))?;

    let signature = dilithium2::detached_sign(&message_bytes, &secret_key);
    let signature_hex = format!("0x{}", hex::encode(signature.as_bytes()));

    println!("Wallet nonce: {}", nonce);
    println!("Runtime ML-DSA public key hash: {}", key_hash);
    println!("Target calldata: {}", target_calldata);
    println!("Operation digest: {}", digest);
    println!("Verification message: {}", message_hex);
    println!("Signature length: {} bytes", signature.as_bytes().len());

    let call_result = cast_call(
        &rpc_url,
        wallet,
        "execute(bytes,address,uint256,bytes,uint256,bytes)(bytes)",
        &[
            public_key_hex.clone(),
            target.to_string(),
            value.to_string(),
            target_calldata.clone(),
            deadline.to_string(),
            signature_hex.clone(),
        ],
    )?;
    println!("eth_call simulation result: {}", call_result);

    if dry_run_only {
        return Ok(());
    }

    let receipt = cast_send(
        &rpc_url,
        private_key.as_deref().unwrap(),
        wallet,
        "execute(bytes,address,uint256,bytes,uint256,bytes)",
        &[
            public_key_hex,
            target.to_string(),
            value.to_string(),
            target_calldata,
            deadline.to_string(),
            signature_hex,
        ],
        None,
    )?;
    println!(
        "Transaction hash: {}",
        string_field(&receipt, "transactionHash")?
    );

    let updated_nonce = cast_call(&rpc_url, wallet, "nonces(bytes32)(uint256)", &[key_hash])?;
    let note = cast_call(&rpc_url, target, "note()(string)", &[])?;
    let count = cast_call(&rpc_url, target, "count()(uint256)", &[])?;
    let last_caller = cast_call(&rpc_url, target, "lastCaller()(address)", &[])?;

    println!("Updated nonce for runtime key: {}", updated_nonce);
    println!("Recipient note: {}", note);
    println!("Recipient count: {}", count);
    println!("Recipient last caller: {}", last_caller);
    Ok(())
}
