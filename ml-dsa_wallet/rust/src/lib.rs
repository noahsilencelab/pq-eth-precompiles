use serde_json::Value;
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn wallet_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate lives under ml-dsa_wallet/rust")
        .to_path_buf()
}

pub fn source_dir() -> PathBuf {
    wallet_root().join("sol")
}

pub fn state_dir() -> PathBuf {
    wallet_root().join("state")
}

pub fn ensure_state_dir() -> Result<PathBuf> {
    let dir = state_dir();
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

pub fn run_command(program: &str, args: &[String], cwd: Option<&Path>) -> Result<String> {
    let mut command = Command::new(program);
    command.args(args);
    if let Some(dir) = cwd {
        command.current_dir(dir);
    }
    let output = command.output()?;
    if !output.status.success() {
        return Err(format!(
            "{} {:?} failed with status {}: {}",
            program,
            args,
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

pub fn save_json(path: &Path, value: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

pub fn load_json(path: &Path) -> Result<Value> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

pub fn string_field<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string field `{key}`").into())
}

pub fn compile_contracts() -> Result<HashMap<String, String>> {
    let src_dir = source_dir();
    let output = run_command(
        "solc",
        &[
            "--optimize".to_string(),
            "--combined-json".to_string(),
            "abi,bin".to_string(),
            src_dir.join("MLDSAWallet.sol").display().to_string(),
            src_dir.join("DemoRecipient.sol").display().to_string(),
        ],
        Some(&wallet_root()),
    )?;

    let parsed: Value = serde_json::from_str(&output)?;
    let mut contracts = HashMap::new();
    for (key, value) in parsed["contracts"]
        .as_object()
        .ok_or("solc combined-json missing `contracts`")?
    {
        let contract_name = key
            .rsplit(':')
            .next()
            .ok_or("invalid solc contract key")?
            .to_string();
        let bin = value["bin"]
            .as_str()
            .ok_or("contract missing `bin`")?
            .to_string();
        contracts.insert(contract_name, bin);
    }
    Ok(contracts)
}

pub fn cast_output(args: &[String]) -> Result<String> {
    run_command("cast", args, Some(&wallet_root()))
}

pub fn cast_calldata(signature: &str, args: &[String]) -> Result<String> {
    let mut cmd = vec!["calldata".to_string(), signature.to_string()];
    cmd.extend(args.iter().cloned());
    cast_output(&cmd)
}

pub fn cast_abi_encode(signature: &str, args: &[String]) -> Result<String> {
    let mut cmd = vec!["abi-encode".to_string(), signature.to_string()];
    cmd.extend(args.iter().cloned());
    cast_output(&cmd)
}

pub fn cast_keccak(data_hex: &str) -> Result<String> {
    cast_output(&["keccak".to_string(), data_hex.to_string()])
}

pub fn cast_call(rpc_url: &str, to: &str, signature: &str, args: &[String]) -> Result<String> {
    let mut cmd = vec![
        "call".to_string(),
        "--rpc-url".to_string(),
        rpc_url.to_string(),
        to.to_string(),
        signature.to_string(),
    ];
    cmd.extend(args.iter().cloned());
    cast_output(&cmd)
}

pub fn cast_send(
    rpc_url: &str,
    private_key: &str,
    to: &str,
    signature: &str,
    args: &[String],
    value: Option<&str>,
) -> Result<Value> {
    let mut cmd = vec![
        "send".to_string(),
        "--json".to_string(),
        "--rpc-url".to_string(),
        rpc_url.to_string(),
        "--private-key".to_string(),
        private_key.to_string(),
    ];
    if let Some(amount) = value {
        cmd.push("--value".to_string());
        cmd.push(amount.to_string());
    }
    cmd.push(to.to_string());
    cmd.push(signature.to_string());
    cmd.extend(args.iter().cloned());
    Ok(serde_json::from_str(&cast_output(&cmd)?)?)
}

pub fn cast_send_create(rpc_url: &str, private_key: &str, creation_code: &str) -> Result<Value> {
    let cmd = vec![
        "send".to_string(),
        "--json".to_string(),
        "--rpc-url".to_string(),
        rpc_url.to_string(),
        "--private-key".to_string(),
        private_key.to_string(),
        "--create".to_string(),
        creation_code.to_string(),
    ];
    Ok(serde_json::from_str(&cast_output(&cmd)?)?)
}

pub fn cast_rpc(rpc_url: &str, method: &str, raw_params: Option<&str>) -> Result<Value> {
    let mut cmd = vec![
        "rpc".to_string(),
        "--rpc-url".to_string(),
        rpc_url.to_string(),
        method.to_string(),
    ];
    if let Some(params) = raw_params {
        cmd.push(params.to_string());
        cmd.push("--raw".to_string());
    }
    let output = cast_output(&cmd)?;
    let parsed = match serde_json::from_str::<Value>(&output) {
        Ok(value) => value,
        Err(_) => Value::String(output),
    };

    if parsed.get("result").is_some() || parsed.get("error").is_some() {
        Ok(parsed)
    } else {
        Ok(json!({ "result": parsed }))
    }
}

pub fn hex_to_u64(hex_value: &str) -> Result<u64> {
    Ok(u64::from_str_radix(hex_value.trim_start_matches("0x"), 16)?)
}

pub fn chain_id(rpc_url: &str) -> Result<u64> {
    let value = cast_rpc(rpc_url, "eth_chainId", None)?;
    hex_to_u64(string_field(&value, "result")?)
}

pub fn latest_block_timestamp(rpc_url: &str) -> Result<u64> {
    let value = cast_rpc(rpc_url, "eth_getBlockByNumber", Some("[\"latest\", false]"))?;
    let block = value["result"].as_object().ok_or("missing latest block result")?;
    let timestamp = block
        .get("timestamp")
        .and_then(Value::as_str)
        .ok_or("missing block timestamp")?;
    hex_to_u64(timestamp)
}

pub fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|window| window[0] == flag)
        .map(|window| window[1].clone())
}

pub fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|arg| arg == flag)
}

pub fn ensure_0x(value: &str) -> String {
    if value.starts_with("0x") {
        value.to_string()
    } else {
        format!("0x{value}")
    }
}

pub fn strip_0x(value: &str) -> &str {
    value.strip_prefix("0x").unwrap_or(value)
}
