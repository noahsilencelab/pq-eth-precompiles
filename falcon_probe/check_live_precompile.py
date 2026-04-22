#!/usr/bin/env python3
import argparse
import json
import subprocess
import urllib.request
from pathlib import Path


def rpc(url: str, method: str, params):
    req = urllib.request.Request(
        url,
        data=json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        ).encode(),
        headers={"content-type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode())


def word(value: int) -> bytes:
    return value.to_bytes(32, "big")


def parse_probe_output(text: str) -> dict[str, bytes]:
    values = {}
    for line in text.strip().splitlines():
        key, value = line.split("=", 1)
        values[key] = bytes.fromhex(value.strip())
    return values


def main() -> None:
    parser = argparse.ArgumentParser(description="Probe live Falcon PQ precompiles")
    parser.add_argument("--rpc", required=True, help="Ethereum JSON-RPC URL")
    parser.add_argument(
        "--message",
        default="hello from falcon probe",
        help="Message to sign and verify",
    )
    args = parser.parse_args()

    here = Path(__file__).resolve().parent
    probe = here / "target" / "debug" / "falcon_probe"

    if not probe.exists():
        raise SystemExit(
            "falcon_probe binary not found. Run: cargo run --offline --manifest-path "
            f"{here / 'Cargo.toml'}"
        )

    probe_out = subprocess.check_output([str(probe), args.message], text=True)
    values = parse_probe_output(probe_out)

    msg = values["msg_hex"]
    nonce = values["nonce_hex"]
    h = values["h_hex"]
    s2 = values["s2_hex"]

    ntt_input = word(512) + word(12289) + word(49) + h
    ntt_resp = rpc(
        args.rpc,
        "eth_call",
        [{"to": "0x0000000000000000000000000000000000000012", "data": "0x" + ntt_input.hex()}, "latest"],
    )
    ntth = bytes.fromhex(ntt_resp["result"][2:])

    valid_input = s2 + ntth + nonce + msg
    valid_resp = rpc(
        args.rpc,
        "eth_call",
        [{"to": "0x0000000000000000000000000000000000000017", "data": "0x" + valid_input.hex()}, "latest"],
    )

    wrong_msg = msg + b" but wrong"
    wrong_input = s2 + ntth + nonce + wrong_msg
    wrong_resp = rpc(
        args.rpc,
        "eth_call",
        [{"to": "0x0000000000000000000000000000000000000017", "data": "0x" + wrong_input.hex()}, "latest"],
    )

    print(f"message: {msg.decode(errors='replace')}")
    print(f"nonce_len: {len(nonce)}")
    print(f"s2_len: {len(s2)}")
    print(f"ntth_len: {len(ntth)}")
    print(f"valid_result: {valid_resp['result']}")
    print(f"wrong_result: {wrong_resp['result']}")
    print(f"valid_bool: {valid_resp['result'].endswith('1')}")
    print(f"wrong_bool: {wrong_resp['result'].endswith('1')}")


if __name__ == "__main__":
    main()
