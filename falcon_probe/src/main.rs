use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};

fn decode_pubkey_14bit(pk_bytes: &[u8]) -> Vec<u16> {
    assert_eq!(pk_bytes.len(), 897);
    assert_eq!(pk_bytes[0], 0x09);

    let bits = &pk_bytes[1..];
    let mut byte_pos = 0usize;
    let mut bit_pos = 0usize;
    let mut h = Vec::with_capacity(512);

    for _ in 0..512 {
        let mut val = 0u16;
        for _ in 0..14 {
            val = (val << 1) | (((bits[byte_pos] >> (7 - bit_pos)) & 1) as u16);
            bit_pos += 1;
            if bit_pos == 8 {
                bit_pos = 0;
                byte_pos += 1;
            }
        }
        h.push(val);
    }

    h
}

fn decode_signature(sig_bytes: &[u8]) -> (Vec<u8>, Vec<u16>) {
    let nonce = sig_bytes[1..41].to_vec();
    let comp = &sig_bytes[41..];
    let mut byte_pos = 0usize;
    let mut bit_pos = 0usize;

    let mut read_bit = || -> u8 {
        let bit = (comp[byte_pos] >> (7 - bit_pos)) & 1;
        bit_pos += 1;
        if bit_pos == 8 {
            bit_pos = 0;
            byte_pos += 1;
        }
        bit
    };

    let mut s2 = Vec::with_capacity(512);
    for _ in 0..512 {
        let sign = read_bit();
        let mut low = 0u16;
        for _ in 0..7 {
            low = (low << 1) | read_bit() as u16;
        }
        let mut high = 0u16;
        loop {
            let bit = read_bit();
            if bit == 1 {
                break;
            }
            high += 1;
        }
        let magnitude = (high << 7) | low;
        if sign == 1 {
            s2.push(12289u16 - magnitude);
        } else {
            s2.push(magnitude);
        }
    }

    (nonce, s2)
}

fn hex_bytes(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn hex_u16s(data: &[u16]) -> String {
    let mut out = String::with_capacity(data.len() * 4);
    for x in data {
        out.push_str(&format!("{:04x}", x));
    }
    out
}

fn main() {
    let msg = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "hello from falcon probe".to_string())
        .into_bytes();

    let (pk, sk) = falcon512::keypair();
    let sig = falcon512::detached_sign(&msg, &sk);

    let h = decode_pubkey_14bit(pk.as_bytes());
    let (nonce, s2) = decode_signature(sig.as_bytes());

    println!("msg_hex={}", hex_bytes(&msg));
    println!("pk_hex={}", hex_bytes(pk.as_bytes()));
    println!("sig_hex={}", hex_bytes(sig.as_bytes()));
    println!("nonce_hex={}", hex_bytes(&nonce));
    println!("h_hex={}", hex_u16s(&h));
    println!("s2_hex={}", hex_u16s(&s2));
}
