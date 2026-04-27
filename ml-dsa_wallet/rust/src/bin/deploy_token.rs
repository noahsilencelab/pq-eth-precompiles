use ml_dsa_wallet_tools::{
    cast_abi_encode, cast_send_create, chain_id, compile_contracts, flag_value, load_json,
    save_json, state_dir, string_field, Result,
};
use serde_json::{json, Value};
use std::path::PathBuf;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let rpc_url = flag_value(&args, "--rpc")
        .or_else(|| std::env::var("RPC_URL").ok())
        .ok_or("missing --rpc or RPC_URL")?;
    let private_key = flag_value(&args, "--private-key")
        .or_else(|| std::env::var("PRIVATE_KEY").ok())
        .ok_or("missing --private-key or PRIVATE_KEY")?;
    let out_path = flag_value(&args, "--out")
        .map(PathBuf::from)
        .unwrap_or_else(|| state_dir().join("deployment.json"));
    let token_name =
        flag_value(&args, "--token-name").unwrap_or_else(|| "PQ Demo Token".to_string());
    let token_symbol = flag_value(&args, "--token-symbol").unwrap_or_else(|| "PQT".to_string());
    let token_decimals =
        flag_value(&args, "--token-decimals").unwrap_or_else(|| "18".to_string());
    let token_supply = flag_value(&args, "--token-supply")
        .unwrap_or_else(|| "1000000000000000000000".to_string());

    let wallet_address = if let Some(wallet) = flag_value(&args, "--wallet") {
        wallet
    } else {
        let existing = load_json(&out_path)?;
        string_field(&existing, "wallet_address")?.to_string()
    };

    let compiled = compile_contracts()?;
    let token_bin = compiled
        .get("SimpleERC20")
        .ok_or("SimpleERC20 bin missing from solc output")?;

    let token_ctor = cast_abi_encode(
        "constructor(string,string,uint8,uint256,address)",
        &[
            token_name.clone(),
            token_symbol.clone(),
            token_decimals.clone(),
            token_supply.clone(),
            wallet_address.clone(),
        ],
    )?;
    let token_creation = format!("0x{}{}", token_bin, &token_ctor[2..]);
    let token_receipt = cast_send_create(&rpc_url, &private_key, &token_creation)?;

    let mut payload = if out_path.exists() {
        load_json(&out_path)?
    } else {
        json!({})
    };
    let object = payload
        .as_object_mut()
        .ok_or("deployment metadata must be a JSON object")?;

    object.insert("chain_id".to_string(), Value::from(chain_id(&rpc_url)?));
    object.insert("rpc_url".to_string(), Value::from(rpc_url));
    object.insert("wallet_address".to_string(), Value::from(wallet_address));
    object.insert(
        "token_address".to_string(),
        Value::from(string_field(&token_receipt, "contractAddress")?),
    );
    object.insert(
        "token_deploy_tx".to_string(),
        Value::from(string_field(&token_receipt, "transactionHash")?),
    );
    object.insert("token_name".to_string(), Value::from(token_name));
    object.insert("token_symbol".to_string(), Value::from(token_symbol));
    object.insert("token_decimals".to_string(), Value::from(token_decimals));
    object.insert("token_supply".to_string(), Value::from(token_supply));

    save_json(&out_path, &payload)?;

    println!("Using MLDSAWallet at {}", string_field(&payload, "wallet_address")?);
    println!("SimpleERC20 deployed at {}", string_field(&payload, "token_address")?);
    println!("Updated deployment metadata at {}", out_path.display());
    Ok(())
}
