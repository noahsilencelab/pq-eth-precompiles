use crate::fast::{self, FastNttParams};
use crate::precompile::PrecompileError;
use std::slice;

// ─── EVM compact format helpers ───
// Compact: 1024 bytes = 32 big-endian uint256 words, each packing 16 LE uint16 coefficients.
// Word layout: byte[30-2j..31-2j] = coeff[j] as big-endian uint16 (for j=0..15).

const FALCON_Q: u64 = 12289;
const FALCON_N: usize = 512;
const FALCON_PSI: u64 = 49;
const COMPACT_SIZE: usize = 1024; // 32 words × 32 bytes

fn unpack_compact(data: &[u8]) -> Option<Vec<u64>> {
    if data.len() != COMPACT_SIZE { return None; }
    let mut coeffs = Vec::with_capacity(FALCON_N);
    for w in 0..32 {
        let word_start = w * 32;
        for j in 0..16 {
            let hi = data[word_start + 30 - j * 2] as u64;
            let lo = data[word_start + 31 - j * 2] as u64;
            coeffs.push(hi * 256 + lo);
        }
    }
    Some(coeffs)
}

fn pack_compact(coeffs: &[u64]) -> Vec<u8> {
    let mut out = vec![0u8; COMPACT_SIZE];
    for w in 0..32 {
        let word_start = w * 32;
        for j in 0..16 {
            let c = coeffs[w * 16 + j];
            out[word_start + 30 - j * 2] = (c >> 8) as u8;
            out[word_start + 31 - j * 2] = (c & 0xff) as u8;
        }
    }
    out
}

fn error_code(e: PrecompileError) -> i32 {
    match e {
        PrecompileError::InputTooShort => -1,
        PrecompileError::InvalidParams(_) => -2,
        PrecompileError::BadLength => -3,
        PrecompileError::Overflow(_) => -4,
    }
}

fn write_output(output: Vec<u8>, out_ptr: *mut *mut u8, out_len: *mut usize) {
    let boxed = output.into_boxed_slice();
    let len = boxed.len();
    let ptr = Box::into_raw(boxed) as *mut u8;
    unsafe {
        *out_ptr = ptr;
        *out_len = len;
    }
}

// ─── Precompile entry points ───

#[no_mangle]
pub unsafe extern "C" fn eth_ntt_fw_precompile(
    input: *const u8,
    input_len: usize,
    output_out: *mut *mut u8,
    output_len_out: *mut usize,
) -> i32 {
    let input = slice::from_raw_parts(input, input_len);
    match crate::ntt_fw_precompile(input) {
        Ok(output) => {
            write_output(output, output_out, output_len_out);
            0
        }
        Err(e) => error_code(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn eth_ntt_inv_precompile(
    input: *const u8,
    input_len: usize,
    output_out: *mut *mut u8,
    output_len_out: *mut usize,
) -> i32 {
    let input = slice::from_raw_parts(input, input_len);
    match crate::ntt_inv_precompile(input) {
        Ok(output) => {
            write_output(output, output_out, output_len_out);
            0
        }
        Err(e) => error_code(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn eth_ntt_vecmulmod_precompile(
    input: *const u8,
    input_len: usize,
    output_out: *mut *mut u8,
    output_len_out: *mut usize,
) -> i32 {
    let input = slice::from_raw_parts(input, input_len);
    match crate::ntt_vecmulmod_precompile(input) {
        Ok(output) => {
            write_output(output, output_out, output_len_out);
            0
        }
        Err(e) => error_code(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn eth_ntt_vecaddmod_precompile(
    input: *const u8,
    input_len: usize,
    output_out: *mut *mut u8,
    output_len_out: *mut usize,
) -> i32 {
    let input = slice::from_raw_parts(input, input_len);
    match crate::ntt_vecaddmod_precompile(input) {
        Ok(output) => {
            write_output(output, output_out, output_len_out);
            0
        }
        Err(e) => error_code(e),
    }
}

// ─── Compact-format Falcon-512 precompiles ───

#[no_mangle]
pub unsafe extern "C" fn eth_ntt_fw_compact(
    input: *const u8, input_len: usize,
    output_out: *mut *mut u8, output_len_out: *mut usize,
) -> i32 {
    let data = slice::from_raw_parts(input, input_len);
    let coeffs = match unpack_compact(data) { Some(c) => c, None => return -1 };
    let params = match FastNttParams::new(FALCON_Q, FALCON_N, FALCON_PSI) {
        Ok(p) => p, Err(_) => return -2,
    };
    let result = fast::ntt_fw_fast(&coeffs, &params);
    write_output(pack_compact(&result), output_out, output_len_out);
    0
}

#[no_mangle]
pub unsafe extern "C" fn eth_ntt_inv_compact(
    input: *const u8, input_len: usize,
    output_out: *mut *mut u8, output_len_out: *mut usize,
) -> i32 {
    let data = slice::from_raw_parts(input, input_len);
    let coeffs = match unpack_compact(data) { Some(c) => c, None => return -1 };
    let params = match FastNttParams::new(FALCON_Q, FALCON_N, FALCON_PSI) {
        Ok(p) => p, Err(_) => return -2,
    };
    let result = fast::ntt_inv_fast(&coeffs, &params);
    write_output(pack_compact(&result), output_out, output_len_out);
    0
}

#[no_mangle]
pub unsafe extern "C" fn eth_ntt_vecmulmod_compact(
    input: *const u8, input_len: usize,
    output_out: *mut *mut u8, output_len_out: *mut usize,
) -> i32 {
    if input_len != 2 * COMPACT_SIZE { return -1; }
    let data = slice::from_raw_parts(input, input_len);
    let a = match unpack_compact(&data[..COMPACT_SIZE]) { Some(c) => c, None => return -1 };
    let b = match unpack_compact(&data[COMPACT_SIZE..]) { Some(c) => c, None => return -1 };
    let result = fast::vec_mul_mod_fast(&a, &b, FALCON_Q);
    write_output(pack_compact(&result), output_out, output_len_out);
    0
}

/// SHAKE256 hash-to-point: input = salt||msg, output = 1024 bytes compact
#[no_mangle]
pub unsafe extern "C" fn eth_ntt_shake256_htp(
    input: *const u8, input_len: usize,
    output_out: *mut *mut u8, output_len_out: *mut usize,
) -> i32 {
    use sha3::{Shake256, digest::{ExtendableOutput, Update}};
    let data = slice::from_raw_parts(input, input_len);
    let mut hasher = Shake256::default();
    hasher.update(data);
    let mut reader = hasher.finalize_xof();
    let mut coeffs = Vec::with_capacity(FALCON_N);
    let mut buf = [0u8; 2];
    while coeffs.len() < FALCON_N {
        use sha3::digest::XofReader;
        reader.read(&mut buf);
        let t = (buf[0] as u64) * 256 + buf[1] as u64;
        if t < 61445 {
            coeffs.push(t % FALCON_Q);
        }
    }
    write_output(pack_compact(&coeffs), output_out, output_len_out);
    0
}

/// Falcon-512 norm check on compact data.
/// Input: s1_compact(1024) || s2_compact(1024) || hashed_compact(1024) = 3072 bytes
/// Output: 32 bytes: 0x00..01 if norm < sigBound, 0x00..00 otherwise
#[no_mangle]
pub unsafe extern "C" fn eth_ntt_falcon_norm(
    input: *const u8, input_len: usize,
    output_out: *mut *mut u8, output_len_out: *mut usize,
) -> i32 {
    if input_len != 3 * COMPACT_SIZE { return -1; }
    let data = slice::from_raw_parts(input, input_len);
    let s1 = match unpack_compact(&data[0..COMPACT_SIZE]) { Some(c) => c, None => return -1 };
    let s2 = match unpack_compact(&data[COMPACT_SIZE..2*COMPACT_SIZE]) { Some(c) => c, None => return -1 };
    let hashed = match unpack_compact(&data[2*COMPACT_SIZE..]) { Some(c) => c, None => return -1 };

    const SIG_BOUND: u64 = 34034726;
    const QS1: u64 = 6144;
    let mut norm: u64 = 0;
    for i in 0..FALCON_N {
        let mut d = (hashed[i] + FALCON_Q - s1[i]) % FALCON_Q;
        if d > QS1 { d = FALCON_Q - d; }
        norm += d * d;

        let mut s = s2[i];
        if s > QS1 { s = FALCON_Q - s; }
        norm += s * s;
    }

    let mut result = vec![0u8; 32];
    if norm < SIG_BOUND {
        result[31] = 1;
    }
    write_output(result, output_out, output_len_out);
    0
}

#[no_mangle]
pub unsafe extern "C" fn eth_ntt_free_buffer(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        let _ = Box::from_raw(slice::from_raw_parts_mut(ptr, len));
    }
}

// ─── Fast direct API ───

#[no_mangle]
pub unsafe extern "C" fn eth_ntt_fast_params_new(
    q: u64,
    n: usize,
    psi: u64,
) -> *mut FastNttParams {
    match FastNttParams::new(q, n, psi) {
        Ok(params) => Box::into_raw(Box::new(params)),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn eth_ntt_fast_params_free(params: *mut FastNttParams) {
    if !params.is_null() {
        drop(Box::from_raw(params));
    }
}

#[no_mangle]
pub unsafe extern "C" fn eth_ntt_fast_params_q(params: *const FastNttParams) -> u64 {
    (*params).q
}

#[no_mangle]
pub unsafe extern "C" fn eth_ntt_fast_params_n(params: *const FastNttParams) -> usize {
    (*params).n
}

#[no_mangle]
pub unsafe extern "C" fn eth_ntt_fast_params_coeff_bytes(params: *const FastNttParams) -> usize {
    (*params).coeff_bytes
}

#[no_mangle]
pub unsafe extern "C" fn eth_ntt_fw(
    params: *const FastNttParams,
    input: *const u64,
    output: *mut u64,
    n: usize,
) {
    let params = &*params;
    let input = slice::from_raw_parts(input, n);
    let result = fast::ntt_fw_fast(input, params);
    std::ptr::copy_nonoverlapping(result.as_ptr(), output, n);
}

#[no_mangle]
pub unsafe extern "C" fn eth_ntt_inv(
    params: *const FastNttParams,
    input: *const u64,
    output: *mut u64,
    n: usize,
) {
    let params = &*params;
    let input = slice::from_raw_parts(input, n);
    let result = fast::ntt_inv_fast(input, params);
    std::ptr::copy_nonoverlapping(result.as_ptr(), output, n);
}

#[no_mangle]
pub unsafe extern "C" fn eth_ntt_vec_mul_mod(
    a: *const u64,
    b: *const u64,
    output: *mut u64,
    n: usize,
    q: u64,
) {
    let a = slice::from_raw_parts(a, n);
    let b = slice::from_raw_parts(b, n);
    let result = fast::vec_mul_mod_fast(a, b, q);
    std::ptr::copy_nonoverlapping(result.as_ptr(), output, n);
}

#[no_mangle]
pub unsafe extern "C" fn eth_ntt_vec_add_mod(
    a: *const u64,
    b: *const u64,
    output: *mut u64,
    n: usize,
    q: u64,
) {
    let a = slice::from_raw_parts(a, n);
    let b = slice::from_raw_parts(b, n);
    let result = fast::vec_add_mod_fast(a, b, q);
    std::ptr::copy_nonoverlapping(result.as_ptr(), output, n);
}
