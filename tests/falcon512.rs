use eth_ntt::{
    decode_output, encode_ntt_input, encode_vec_input, ntt_fw, ntt_fw_precompile, ntt_inv,
    ntt_inv_precompile, ntt_vecaddmod_precompile, ntt_vecmulmod_precompile, vec_add_mod,
    vec_mul_mod, FieldParams,
};
use num_bigint::BigUint;
use num_traits::{One, Zero};

const FALCON_Q: u64 = 12289;
const FALCON_N: usize = 512;

fn falcon512_params() -> FieldParams {
    let q = BigUint::from(FALCON_Q);
    let g = BigUint::from(11u64);
    let exp = (&q - BigUint::one()) / BigUint::from(2u64 * FALCON_N as u64);
    let psi = g.modpow(&exp, &q);
    FieldParams::new(q, FALCON_N, psi).unwrap()
}

fn schoolbook_mul(f: &[BigUint], g: &[BigUint], q: &BigUint, n: usize) -> Vec<BigUint> {
    let mut result = vec![BigUint::zero(); n];
    for i in 0..n {
        for j in 0..n {
            let prod = (&f[i] * &g[j]) % q;
            if i + j < n {
                result[i + j] = (&result[i + j] + &prod) % q;
            } else {
                let idx = i + j - n;
                result[idx] = (q + &result[idx] - &prod) % q;
            }
        }
    }
    result
}

fn poly_add(a: &[BigUint], b: &[BigUint], q: &BigUint) -> Vec<BigUint> {
    a.iter().zip(b.iter()).map(|(ai, bi)| (ai + bi) % q).collect()
}

fn squared_norm(poly: &[BigUint], q: &BigUint) -> BigUint {
    let half_q = q / BigUint::from(2u64);
    poly.iter()
        .map(|c| {
            let centered = if c > &half_q { q - c } else { c.clone() };
            &centered * &centered
        })
        .fold(BigUint::zero(), |acc, x| acc + x)
}

#[test]
fn falcon512_params_valid() {
    let p = falcon512_params();
    assert_eq!(p.q, BigUint::from(FALCON_Q));
    assert_eq!(p.n, FALCON_N);

    assert_eq!(
        &p.q % BigUint::from(2u64 * FALCON_N as u64),
        BigUint::one()
    );

    let psi_1024 = p.psi.modpow(&BigUint::from(1024u64), &p.q);
    assert_eq!(psi_1024, BigUint::one(), "ψ^1024 must be 1 mod q");

    let psi_512 = p.psi.modpow(&BigUint::from(512u64), &p.q);
    assert_eq!(psi_512, &p.q - BigUint::one(), "ψ^512 must be -1 mod q");

    let omega = p.omega();
    let omega_512 = omega.modpow(&BigUint::from(512u64), &p.q);
    assert_eq!(omega_512, BigUint::one());
    let omega_256 = omega.modpow(&BigUint::from(256u64), &p.q);
    assert_ne!(omega_256, BigUint::one(), "ω must be primitive");
}

#[test]
fn falcon512_ntt_roundtrip_zeros() {
    let p = falcon512_params();
    let a = vec![BigUint::zero(); FALCON_N];
    let ntt_a = ntt_fw(&a, &p);
    let recovered = ntt_inv(&ntt_a, &p);
    assert_eq!(a, recovered);
}

#[test]
fn falcon512_ntt_roundtrip_ones() {
    let p = falcon512_params();
    let a = vec![BigUint::one(); FALCON_N];
    let ntt_a = ntt_fw(&a, &p);
    let recovered = ntt_inv(&ntt_a, &p);
    assert_eq!(a, recovered);
}

#[test]
fn falcon512_ntt_roundtrip_sequential() {
    let p = falcon512_params();
    let a: Vec<BigUint> = (0..FALCON_N)
        .map(|i| BigUint::from(i as u64))
        .collect();
    let recovered = ntt_inv(&ntt_fw(&a, &p), &p);
    assert_eq!(a, recovered);
}

#[test]
fn falcon512_ntt_roundtrip_random_like() {
    let p = falcon512_params();
    let q = &p.q;
    let mut seed: u64 = 0xDEADBEEF;
    let a: Vec<BigUint> = (0..FALCON_N)
        .map(|_| {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            BigUint::from(seed % FALCON_Q)
        })
        .collect();

    let recovered = ntt_inv(&ntt_fw(&a, &p), &p);
    for i in 0..FALCON_N {
        assert_eq!(
            &a[i] % q,
            recovered[i],
            "mismatch at index {i}"
        );
    }
}

#[test]
fn falcon512_ntt_roundtrip_max_coefficients() {
    let p = falcon512_params();
    let a: Vec<BigUint> = vec![BigUint::from(FALCON_Q - 1); FALCON_N];
    let recovered = ntt_inv(&ntt_fw(&a, &p), &p);
    assert_eq!(a, recovered);
}

#[test]
fn falcon512_polymul_constant() {
    let p = falcon512_params();
    let q = &p.q;

    let mut f = vec![BigUint::zero(); FALCON_N];
    f[0] = BigUint::from(42u64);
    let mut g = vec![BigUint::zero(); FALCON_N];
    g[0] = BigUint::from(7u64);

    let ntt_f = ntt_fw(&f, &p);
    let ntt_g = ntt_fw(&g, &p);
    let product = ntt_inv(&vec_mul_mod(&ntt_f, &ntt_g, q), &p);

    assert_eq!(product[0], BigUint::from(294u64));
    for i in 1..FALCON_N {
        assert_eq!(product[i], BigUint::zero(), "non-constant term at {i}");
    }
}

#[test]
fn falcon512_polymul_x_shift() {
    let p = falcon512_params();
    let q = &p.q;

    let mut f = vec![BigUint::zero(); FALCON_N];
    f[1] = BigUint::one();
    let mut g = vec![BigUint::zero(); FALCON_N];
    g[FALCON_N - 1] = BigUint::one();

    let ntt_f = ntt_fw(&f, &p);
    let ntt_g = ntt_fw(&g, &p);
    let product = ntt_inv(&vec_mul_mod(&ntt_f, &ntt_g, q), &p);

    assert_eq!(product[0], BigUint::from(FALCON_Q - 1));
    for i in 1..FALCON_N {
        assert_eq!(product[i], BigUint::zero());
    }
}

#[test]
fn falcon512_polymul_vs_schoolbook() {
    let p = falcon512_params();
    let q = &p.q;
    let n = FALCON_N;

    let f: Vec<BigUint> = (0..n)
        .map(|i| {
            let val = ((i * 7 + 3) % 7) as i64 - 3;
            if val >= 0 {
                BigUint::from(val as u64)
            } else {
                &p.q - BigUint::from((-val) as u64)
            }
        })
        .collect();
    let g: Vec<BigUint> = (0..n)
        .map(|i| {
            let val = ((i * 13 + 5) % 7) as i64 - 3;
            if val >= 0 {
                BigUint::from(val as u64)
            } else {
                &p.q - BigUint::from((-val) as u64)
            }
        })
        .collect();

    let ntt_f = ntt_fw(&f, &p);
    let ntt_g = ntt_fw(&g, &p);
    let ntt_product = ntt_inv(&vec_mul_mod(&ntt_f, &ntt_g, q), &p);

    let schoolbook_product = schoolbook_mul(&f, &g, q, n);

    assert_eq!(ntt_product, schoolbook_product);
}

#[test]
fn falcon512_signature_verification() {
    let p = falcon512_params();
    let q = &p.q;
    let n = FALCON_N;

    let mut seed: u64 = 0xCAFEBABE;
    let h: Vec<BigUint> = (0..n)
        .map(|_| {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            BigUint::from(seed % FALCON_Q)
        })
        .collect();

    let s2: Vec<BigUint> = (0..n)
        .map(|i| {
            let val = ((i * 3 + 1) % 5) as i64 - 2;
            if val >= 0 {
                BigUint::from(val as u64)
            } else {
                q - BigUint::from((-val) as u64)
            }
        })
        .collect();

    let ntt_h = ntt_fw(&h, &p);
    let ntt_s2 = ntt_fw(&s2, &p);
    let ntt_s2h = vec_mul_mod(&ntt_s2, &ntt_h, q);
    let s2h = ntt_inv(&ntt_s2h, &p);

    let s1: Vec<BigUint> = (0..n)
        .map(|i| {
            let val = ((i * 7 + 2) % 5) as i64 - 2;
            if val >= 0 {
                BigUint::from(val as u64)
            } else {
                q - BigUint::from((-val) as u64)
            }
        })
        .collect();
    let c = poly_add(&s1, &s2h, q);

    let ntt_s2_v = ntt_fw(&s2, &p);
    let ntt_h_v = ntt_fw(&h, &p);
    let ntt_s2h_v = vec_mul_mod(&ntt_s2_v, &ntt_h_v, q);
    let s2h_v = ntt_inv(&ntt_s2h_v, &p);

    let s1_recovered: Vec<BigUint> = c
        .iter()
        .zip(s2h_v.iter())
        .map(|(ci, si)| {
            if ci >= si {
                (ci - si) % q
            } else {
                q - ((si - ci) % q)
            }
        })
        .collect();

    assert_eq!(s1, s1_recovered, "Verifier must recover s1 exactly");

    let norm_s1 = squared_norm(&s1, q);
    let norm_s2 = squared_norm(&s2, q);
    let total_norm = &norm_s1 + &norm_s2;

    let falcon512_bound = BigUint::from(34034726u64);
    assert!(
        total_norm <= falcon512_bound,
        "Signature norm {} exceeds FALCON-512 bound {}",
        total_norm,
        falcon512_bound
    );
}

#[test]
fn falcon512_ntt_linearity() {
    let p = falcon512_params();
    let q = &p.q;

    let a: Vec<BigUint> = (0..FALCON_N)
        .map(|i| BigUint::from((i * 3) as u64 % FALCON_Q))
        .collect();
    let b: Vec<BigUint> = (0..FALCON_N)
        .map(|i| BigUint::from((i * 7 + 100) as u64 % FALCON_Q))
        .collect();

    let sum = vec_add_mod(&a, &b, q);
    let ntt_sum = ntt_fw(&sum, &p);

    let ntt_a = ntt_fw(&a, &p);
    let ntt_b = ntt_fw(&b, &p);
    let sum_of_ntts = vec_add_mod(&ntt_a, &ntt_b, q);

    assert_eq!(ntt_sum, sum_of_ntts, "NTT must be linear");
}

#[test]
fn falcon512_precompile_full_roundtrip() {
    let p = falcon512_params();
    let q = &p.q;
    let cb = p.coeff_byte_len();

    let f: Vec<BigUint> = (0..FALCON_N)
        .map(|i| BigUint::from((i * 11 + 1) as u64 % FALCON_Q))
        .collect();
    let g: Vec<BigUint> = (0..FALCON_N)
        .map(|i| BigUint::from((i * 13 + 7) as u64 % FALCON_Q))
        .collect();

    let fw_f_input = encode_ntt_input(&p, &f);
    let (gas_f, fw_f_out) = ntt_fw_precompile(&fw_f_input).unwrap();
    assert_eq!(gas_f, 600);

    let fw_g_input = encode_ntt_input(&p, &g);
    let (gas_g, fw_g_out) = ntt_fw_precompile(&fw_g_input).unwrap();
    assert_eq!(gas_g, 600);

    let ntt_f = decode_output(&fw_f_out, FALCON_N, cb);
    let ntt_g = decode_output(&fw_g_out, FALCON_N, cb);

    let mul_input = encode_vec_input(q, FALCON_N, &ntt_f, &ntt_g);
    let (mul_gas, mul_out) = ntt_vecmulmod_precompile(&mul_input).unwrap();
    assert_eq!(mul_gas, 18);

    let ntt_product = decode_output(&mul_out, FALCON_N, cb);

    let inv_input = encode_ntt_input(&p, &ntt_product);
    let (inv_gas, inv_out) = ntt_inv_precompile(&inv_input).unwrap();
    assert_eq!(inv_gas, 600);

    let product = decode_output(&inv_out, FALCON_N, cb);

    let expected = schoolbook_mul(&f, &g, q, FALCON_N);
    assert_eq!(product, expected);

    let total_gas = gas_f + gas_g + mul_gas + inv_gas;
    assert_eq!(total_gas, 1818);
}

#[test]
fn falcon512_vecadd_precompile() {
    let p = falcon512_params();
    let q = &p.q;
    let cb = p.coeff_byte_len();

    let a: Vec<BigUint> = (0..FALCON_N)
        .map(|i| BigUint::from(FALCON_Q - 1 - i as u64 % FALCON_Q))
        .collect();
    let b: Vec<BigUint> = (0..FALCON_N)
        .map(|i| BigUint::from(i as u64 + 1))
        .collect();

    let input = encode_vec_input(q, FALCON_N, &a, &b);
    let (gas, output) = ntt_vecaddmod_precompile(&input).unwrap();
    assert_eq!(gas, 4);

    let result = decode_output(&output, FALCON_N, cb);

    for i in 0..FALCON_N {
        let expected = (&a[i] + &b[i]) % q;
        assert_eq!(result[i], expected, "mismatch at index {i}");
    }
}

#[test]
fn falcon512_verify_via_precompiles() {
    let p = falcon512_params();
    let q = &p.q;
    let cb = p.coeff_byte_len();
    let n = FALCON_N;

    let mut seed: u64 = 0x12345678;
    let lcg = |s: &mut u64| -> u64 {
        *s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
        *s % FALCON_Q
    };

    let h: Vec<BigUint> = (0..n).map(|_| BigUint::from(lcg(&mut seed))).collect();
    let s2: Vec<BigUint> = (0..n)
        .map(|i| {
            let v = (i % 3) as i64 - 1;
            if v >= 0 {
                BigUint::from(v as u64)
            } else {
                q - BigUint::one()
            }
        })
        .collect();

    let s1: Vec<BigUint> = (0..n)
        .map(|i| {
            let v = ((i + 1) % 3) as i64 - 1;
            if v >= 0 {
                BigUint::from(v as u64)
            } else {
                q - BigUint::one()
            }
        })
        .collect();

    let s2h = {
        let ntt_s2 = ntt_fw(&s2, &p);
        let ntt_h = ntt_fw(&h, &p);
        ntt_inv(&vec_mul_mod(&ntt_s2, &ntt_h, q), &p)
    };
    let c = poly_add(&s1, &s2h, q);

    let (_, fw_s2_out) = ntt_fw_precompile(&encode_ntt_input(&p, &s2)).unwrap();
    let ntt_s2 = decode_output(&fw_s2_out, n, cb);

    let (_, fw_h_out) = ntt_fw_precompile(&encode_ntt_input(&p, &h)).unwrap();
    let ntt_h = decode_output(&fw_h_out, n, cb);

    let (_, mul_out) = ntt_vecmulmod_precompile(&encode_vec_input(q, n, &ntt_s2, &ntt_h)).unwrap();
    let ntt_prod = decode_output(&mul_out, n, cb);

    let (_, inv_out) = ntt_inv_precompile(&encode_ntt_input(&p, &ntt_prod)).unwrap();
    let s2h_recovered = decode_output(&inv_out, n, cb);

    let s1_recovered: Vec<BigUint> = c
        .iter()
        .zip(s2h_recovered.iter())
        .map(|(ci, si)| {
            if ci >= si {
                (ci - si) % q
            } else {
                q - ((si - ci) % q)
            }
        })
        .collect();

    assert_eq!(s1, s1_recovered, "Verifier must recover s1");

    let norm = &squared_norm(&s1_recovered, q) + &squared_norm(&s2, q);
    let bound = BigUint::from(34034726u64);
    assert!(norm <= bound, "norm {norm} exceeds FALCON-512 bound {bound}");
}
