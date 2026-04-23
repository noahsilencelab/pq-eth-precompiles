use ml_dsa_wallet_tools::{ensure_state_dir, save_json, state_dir, Result};
use pqcrypto_dilithium::dilithium2;
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};
use serde_json::json;
use std::path::PathBuf;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let out_path = args
        .windows(2)
        .find(|window| window[0] == "--out")
        .map(|window| PathBuf::from(&window[1]))
        .unwrap_or_else(|| state_dir().join("ml_dsa_keypair.json"));

    ensure_state_dir()?;
    let (pk, sk) = dilithium2::keypair();
    let payload = json!({
        "scheme": "ml_dsa_44",
        "public_key_hex": hex::encode(pk.as_bytes()),
        "secret_key_hex": hex::encode(sk.as_bytes()),
        "public_key_length": pk.as_bytes().len(),
        "secret_key_length": sk.as_bytes().len(),
    });
    save_json(&out_path, &payload)?;

    println!("Wrote ML-DSA keypair to {}", out_path.display());
    println!("Public key length: {} bytes", pk.as_bytes().len());
    println!("Secret key length: {} bytes", sk.as_bytes().len());
    Ok(())
}
