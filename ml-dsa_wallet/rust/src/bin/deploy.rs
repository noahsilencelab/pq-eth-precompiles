use ml_dsa_wallet_tools::{
    cast_send_create, chain_id, compile_contracts, flag_value, save_json, state_dir, string_field,
    Result,
};
use serde_json::json;
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

    let compiled = compile_contracts()?;
    let wallet_bin = compiled
        .get("MLDSAWallet")
        .ok_or("MLDSAWallet bin missing from solc output")?;
    let recipient_bin = compiled
        .get("DemoRecipient")
        .ok_or("DemoRecipient bin missing from solc output")?;

    let wallet_creation = format!("0x{}", wallet_bin);
    let recipient_creation = format!("0x{}", recipient_bin);

    let recipient_receipt = cast_send_create(&rpc_url, &private_key, &recipient_creation)?;
    let wallet_receipt = cast_send_create(&rpc_url, &private_key, &wallet_creation)?;

    let payload = json!({
        "chain_id": chain_id(&rpc_url)?,
        "rpc_url": rpc_url,
        "wallet_address": string_field(&wallet_receipt, "contractAddress")?,
        "demo_recipient_address": string_field(&recipient_receipt, "contractAddress")?,
        "wallet_deploy_tx": string_field(&wallet_receipt, "transactionHash")?,
        "demo_recipient_deploy_tx": string_field(&recipient_receipt, "transactionHash")?,
    });
    save_json(&out_path, &payload)?;

    println!(
        "DemoRecipient deployed at {}",
        string_field(&payload, "demo_recipient_address")?
    );
    println!("MLDSAWallet deployed at {}", string_field(&payload, "wallet_address")?);
    println!("Wrote deployment metadata to {}", out_path.display());
    Ok(())
}
