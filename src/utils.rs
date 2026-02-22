#![allow(dead_code)]
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

#[inline]
pub fn xor_bytes(dst: &mut [u8], src: &[u8]) {
    let len = std::cmp::min(dst.len(), src.len());
    let mut i = 0;

    #[cfg(target_arch = "x86_64")]
    if is_x86_feature_detected!("avx2") {
        unsafe {
            while i + 32 <= len {
                let d_ptr = dst.as_mut_ptr().add(i) as *mut __m256i;
                let s_ptr = src.as_ptr().add(i) as *const __m256i;
                let d_val = _mm256_loadu_si256(d_ptr);
                let s_val = _mm256_loadu_si256(s_ptr);
                let res = _mm256_xor_si256(d_val, s_val);
                _mm256_storeu_si256(d_ptr, res);
                i += 32;
            }
        }
    }

    while i + 8 <= len {
        let d_chunk = u64::from_ne_bytes(dst[i..i+8].try_into().unwrap());
        let s_chunk = u64::from_ne_bytes(src[i..i+8].try_into().unwrap());
        let res = d_chunk ^ s_chunk;
        dst[i..i+8].copy_from_slice(&res.to_ne_bytes());
        i += 8;
    }

    for j in i..len {
        dst[j] ^= src[j];
    }
} 
