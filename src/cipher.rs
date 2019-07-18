use std::ffi::{ CStr, CString };
use std::os::raw::c_char;
use std::iter::repeat;
use std::slice;

use crypto::chacha20poly1305::ChaCha20Poly1305;
use crypto::aead::{AeadEncryptor, AeadDecryptor};

use rand::{thread_rng, Rng};

// returned cipher text size is plain text size + 8 bytes nonce + 16 key size
#[no_mangle]
pub extern "C" fn encrypt(key: *mut u8, plain_text: *mut u8, plain_text_len: usize) -> *mut u8 {
    let key = unsafe {
        slice::from_raw_parts(key, 16) // we assume key always 16 bytes
    };

    let plain_text = unsafe {
        slice::from_raw_parts(plain_text, plain_text_len)
    };

    let mut nonce = [0u8; 8];
    thread_rng().fill(&mut nonce[..]);

    let mut out_tag = [0u8; 16];
    let mut cipher_text: Vec<u8> = repeat(0).take(plain_text.len()).collect();

    let mut chacha20 = ChaCha20Poly1305::new(key, &nonce, b""); // use empty aad data
    chacha20.encrypt(plain_text, &mut cipher_text, &mut out_tag);
    cipher_text.extend_from_slice(&nonce);
    cipher_text.extend_from_slice(&out_tag);

    let mut boxed_slice = cipher_text.into_boxed_slice();
    let buffer: *mut u8 = boxed_slice.as_mut_ptr();

    std::mem::forget(boxed_slice);

    buffer
}

#[no_mangle]
pub extern "C" fn decrypt(key: *mut u8, cipher_text: *mut u8, cipher_text_len: usize) -> *mut u8 {
    let key = unsafe {
        slice::from_raw_parts(key, 16) // we assume key always 16 bytes
    };

    let cipher_text = unsafe {
        slice::from_raw_parts(cipher_text, cipher_text_len)
    };

    let cipher_text_len = cipher_text.len();

    let mut plain_text: Vec<u8> = repeat(0).take(cipher_text_len - 8 - 16).collect();
    let tag = cipher_text[cipher_text_len - 16..].to_vec();
    let nonce = cipher_text[cipher_text_len - 16 - 8..cipher_text_len - 16].to_vec();
    let cipher_text = cipher_text[..cipher_text_len - 8 - 16].to_vec();

    let mut chacha20 = ChaCha20Poly1305::new(key, &nonce, b""); // use empty aad data
    chacha20.decrypt(&cipher_text, &mut plain_text, &tag);
    let mut boxed_slice = plain_text.into_boxed_slice();
    let buffer: *mut u8 = boxed_slice.as_mut_ptr();

    std::mem::forget(boxed_slice);

    buffer
}

#[no_mangle]
pub extern "C" fn dealloc_rust_buffer(buf: *mut u8, len: usize) {
    unsafe {
        Vec::from_raw_parts(buf, len, len);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::iter::repeat;

    #[test]
    fn test_cipher() {
        let mut plain_text = [98u8; 10];
        let mut key = repeat(1u8).take(16).collect::<Vec<u8>>();

        let cipher_text_ptr = encrypt(key.as_mut_ptr(), plain_text.as_mut_ptr(), 10);
        let decryped_ptr = decrypt(key.as_mut_ptr(), cipher_text_ptr, 34);
        dealloc_rust_buffer(cipher_text_ptr, 34);
        dealloc_rust_buffer(decryped_ptr, 34);
    }
}