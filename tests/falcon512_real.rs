use eth_ntt::{ntt_fw, ntt_inv, vec_mul_mod, FieldParams};
use num_bigint::BigUint;
use num_traits::Zero;
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

const Q: u64 = 12289;
const N: usize = 512;
const NONCE_LEN: usize = 40;
const L2_BOUND: u64 = 34034726;

fn falcon512_params() -> FieldParams {
    let q = BigUint::from(Q);
    let psi = BigUint::from(49u64);
    FieldParams::new(q, N, psi).unwrap()
}

struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    bit_pos: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_pos: 0,
            bit_pos: 0,
        }
    }

    fn read_bit(&mut self) -> Option<u8> {
        if self.byte_pos >= self.data.len() {
            return None;
        }
        let bit = (self.data[self.byte_pos] >> (7 - self.bit_pos)) & 1;
        self.bit_pos += 1;
        if self.bit_pos == 8 {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }
        Some(bit)
    }

    fn read_bits(&mut self, n: u8) -> Option<u32> {
        let mut val = 0u32;
        for _ in 0..n {
            val = (val << 1) | self.read_bit()? as u32;
        }
        Some(val)
    }
}

fn decode_pubkey(pk_bytes: &[u8]) -> Vec<BigUint> {
    assert_eq!(pk_bytes.len(), 897, "FALCON-512 public key must be 897 bytes");
    assert_eq!(
        pk_bytes[0], 0x09,
        "header must be 0x00 + log2(512) = 0x09"
    );

    let mut reader = BitReader::new(&pk_bytes[1..]);
    let mut h = Vec::with_capacity(N);
    for _ in 0..N {
        let val = reader.read_bits(14).expect("truncated public key");
        assert!((val as u64) < Q, "h coefficient out of range");
        h.push(BigUint::from(val));
    }
    h
}

fn decode_signature(sig_bytes: &[u8]) -> (Vec<u8>, Vec<BigUint>) {
    assert!(sig_bytes.len() >= 1 + NONCE_LEN + 1, "signature too short");

    let header = sig_bytes[0];
    let logn = header & 0x0F;
    assert_eq!(logn, 9, "expected logn=9 for FALCON-512");
    let fmt = header & 0xF0;
    assert!(
        fmt == 0x30 || fmt == 0x20,
        "unexpected signature format flag: 0x{:02x}",
        fmt
    );

    let nonce = sig_bytes[1..1 + NONCE_LEN].to_vec();
    let comp_data = &sig_bytes[1 + NONCE_LEN..];

    let mut reader = BitReader::new(comp_data);
    let mut s2 = Vec::with_capacity(N);

    for _ in 0..N {
        let sign = reader.read_bit().expect("truncated signature");
        let low = reader.read_bits(7).expect("truncated signature");

        let mut high = 0u32;
        loop {
            let bit = reader.read_bit().expect("truncated signature");
            if bit == 1 {
                break;
            }
            high += 1;
            assert!(high <= 15, "unary code too long (corrupt signature)");
        }

        let magnitude = (high << 7) | low;

        if sign == 1 {
            assert!(magnitude != 0, "negative zero in signature encoding");
            s2.push(BigUint::from(Q - magnitude as u64));
        } else {
            s2.push(BigUint::from(magnitude as u64));
        }
    }

    (nonce, s2)
}

fn hash_to_point(nonce: &[u8], message: &[u8]) -> Vec<BigUint> {
    let mut hasher = Shake256::default();
    hasher.update(nonce);
    hasher.update(message);
    let mut reader = hasher.finalize_xof();

    let threshold: u16 = 61445;

    let mut c = Vec::with_capacity(N);
    while c.len() < N {
        let mut buf = [0u8; 2];
        reader.read(&mut buf);
        let t = ((buf[0] as u16) << 8) | (buf[1] as u16);
        if t < threshold {
            c.push(BigUint::from((t % Q as u16) as u64));
        }
    }
    c
}

fn squared_norm(poly: &[BigUint]) -> BigUint {
    let q = BigUint::from(Q);
    let half_q = BigUint::from(Q / 2);
    poly.iter()
        .map(|c| {
            let centered = if c > &half_q { &q - c } else { c.clone() };
            &centered * &centered
        })
        .fold(BigUint::zero(), |acc, x| acc + x)
}

fn verify_falcon512_with_ntt(
    pk_bytes: &[u8],
    sig_bytes: &[u8],
    message: &[u8],
) -> Result<(), String> {
    let params = falcon512_params();
    let q = &params.q;

    let h = decode_pubkey(pk_bytes);

    let (nonce, s2) = decode_signature(sig_bytes);

    let c = hash_to_point(&nonce, message);

    let ntt_h = ntt_fw(&h, &params);
    let ntt_s2 = ntt_fw(&s2, &params);
    let ntt_product = vec_mul_mod(&ntt_s2, &ntt_h, q);
    let t = ntt_inv(&ntt_product, &params);

    let s1: Vec<BigUint> = c
        .iter()
        .zip(t.iter())
        .map(|(ci, ti)| {
            if ci >= ti {
                (ci - ti) % q
            } else {
                q - ((ti - ci) % q)
            }
        })
        .collect();

    let norm_s1 = squared_norm(&s1);
    let norm_s2 = squared_norm(&s2);
    let total_norm = &norm_s1 + &norm_s2;
    let bound = BigUint::from(L2_BOUND);

    if total_norm > bound {
        return Err(format!(
            "norm check failed: ||(s1,s2)||² = {} > {} = β²",
            total_norm, bound
        ));
    }

    Ok(())
}

#[test]
fn falcon512_real_sign_and_verify() {
    let message = b"Hello, post-quantum Ethereum!";

    let (pk, sk) = falcon512::keypair();
    let sig = falcon512::detached_sign(message, &sk);

    falcon512::verify_detached_signature(&sig, message, &pk)
        .expect("library verification must pass");

    verify_falcon512_with_ntt(pk.as_bytes(), sig.as_bytes(), message)
        .expect("NTT-based verification must pass for a valid signature");
}

#[test]
fn falcon512_real_multiple_messages() {
    let (pk, sk) = falcon512::keypair();

    let messages: &[&[u8]] = &[
        b"",
        b"a",
        b"The quick brown fox jumps over the lazy dog",
        &[0u8; 1024],
        &(0..=255).collect::<Vec<u8>>(),
    ];

    for (i, msg) in messages.iter().enumerate() {
        let sig = falcon512::detached_sign(msg, &sk);

        falcon512::verify_detached_signature(&sig, msg, &pk)
            .unwrap_or_else(|_| panic!("library verify failed for message {}", i));

        verify_falcon512_with_ntt(pk.as_bytes(), sig.as_bytes(), msg)
            .unwrap_or_else(|e| panic!("NTT verify failed for message {}: {}", i, e));
    }
}

#[test]
fn falcon512_real_wrong_message_fails() {
    let message = b"correct message";
    let wrong = b"wrong message";

    let (pk, sk) = falcon512::keypair();
    let sig = falcon512::detached_sign(message, &sk);

    assert!(
        falcon512::verify_detached_signature(&sig, wrong, &pk).is_err(),
        "library must reject wrong message"
    );

    let result = verify_falcon512_with_ntt(pk.as_bytes(), sig.as_bytes(), wrong);
    assert!(
        result.is_err(),
        "NTT-based verification must reject wrong message"
    );
}

#[test]
fn falcon512_real_multiple_keypairs() {
    let message = b"testing multiple keypairs";

    for _ in 0..3 {
        let (pk, sk) = falcon512::keypair();
        let sig = falcon512::detached_sign(message, &sk);

        falcon512::verify_detached_signature(&sig, message, &pk).unwrap();
        verify_falcon512_with_ntt(pk.as_bytes(), sig.as_bytes(), message).unwrap();
    }
}

#[test]
fn falcon512_real_wrong_key_fails() {
    let message = b"test message";

    let (pk1, sk1) = falcon512::keypair();
    let (pk2, _sk2) = falcon512::keypair();
    let sig = falcon512::detached_sign(message, &sk1);

    verify_falcon512_with_ntt(pk1.as_bytes(), sig.as_bytes(), message).unwrap();

    let result = verify_falcon512_with_ntt(pk2.as_bytes(), sig.as_bytes(), message);
    assert!(
        result.is_err(),
        "NTT verification must reject signature under wrong public key"
    );
}

#[test]
fn falcon512_pubkey_decode_roundtrip() {
    let (pk, _sk) = falcon512::keypair();
    let h = decode_pubkey(pk.as_bytes());

    assert_eq!(h.len(), N);
    let q = BigUint::from(Q);
    for (i, coeff) in h.iter().enumerate() {
        assert!(coeff < &q, "h[{}] = {} out of range [0, {})", i, coeff, Q);
    }
}

#[test]
fn falcon512_signature_decode_valid() {
    let message = b"decode test";
    let (_pk, sk) = falcon512::keypair();
    let sig = falcon512::detached_sign(message, &sk);

    let (nonce, s2) = decode_signature(sig.as_bytes());

    assert_eq!(nonce.len(), NONCE_LEN);
    assert_eq!(s2.len(), N);

    let q = BigUint::from(Q);
    for (i, coeff) in s2.iter().enumerate() {
        assert!(coeff < &q, "s2[{}] = {} out of range", i, coeff);
    }

    let norm = squared_norm(&s2);
    assert!(
        norm < BigUint::from(L2_BOUND),
        "s2 alone has norm {} which exceeds bound",
        norm
    );
}

#[test]
fn falcon512_hash_to_point_deterministic() {
    let nonce = [42u8; NONCE_LEN];
    let msg = b"determinism test";

    let c1 = hash_to_point(&nonce, msg);
    let c2 = hash_to_point(&nonce, msg);

    assert_eq!(c1, c2);
    assert_eq!(c1.len(), N);

    let q = BigUint::from(Q);
    for coeff in &c1 {
        assert!(coeff < &q);
    }
}
