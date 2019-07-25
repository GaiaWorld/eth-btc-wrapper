use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::iter::repeat;

use crypto::aes_gcm::AesGcm;
use crypto::aes::KeySize;
use crypto::aead::{AeadEncryptor, AeadDecryptor};

use hex::{encode, decode};

// returned cipher text size is plain text size + 8 bytes nonce + 16 key size
#[no_mangle]
pub extern "C" fn rust_encrypt(key: *const c_char, nonce: *const c_char ,aad: *const c_char, plain_text: *const c_char, out_cipher_text: *mut *mut c_char) -> i32 {
    assert!(!key.is_null() && !plain_text.is_null() && !out_cipher_text.is_null() && !nonce.is_null());

    let key = unsafe {
        match decode(CStr::from_ptr(key).to_str().unwrap()) {
            Ok(k) => k,
            Err(_) => return -1,
        }
    };

    let nonce = unsafe {
        match decode(CStr::from_ptr(nonce).to_str().unwrap()) {
            Ok(n) => n,
            Err(_) => return -1,
        }
    };

    let plain_text = unsafe {
        match decode(CStr::from_ptr(plain_text).to_str().unwrap()) {
            Ok(p) => p,
            Err(_) => return -1,
        }
    };

    let aad = unsafe {
        if aad.is_null() {
            vec![]
        } else {
            match decode(CStr::from_ptr(aad).to_str().unwrap()) {
                Ok(a) => a,
                Err(_) => return -1,
            }
        }
    };

    let mut out_tag = [0u8; 16];
    let mut cipher_text: Vec<u8> = repeat(0).take(plain_text.len()).collect();

    let mut aes_gcm = AesGcm::new(KeySize::KeySize128, &key, &nonce, &aad); // use empty aad data
    aes_gcm.encrypt(&plain_text, &mut cipher_text, &mut out_tag);
    cipher_text.extend_from_slice(&out_tag);

    unsafe {
        *out_cipher_text = CString::new(encode(&cipher_text)).unwrap().into_raw();
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn rust_decrypt(key: *const c_char, nonce: *const c_char, aad: *const c_char, cipher_text: *const c_char, out_plain_text: *mut *mut c_char) -> i32 {
    assert!(!key.is_null() && !cipher_text.is_null() && !out_plain_text.is_null() && !nonce.is_null());

    let key = unsafe {
        match decode(CStr::from_ptr(key).to_str().unwrap()) {
            Ok(k) => k,
            Err(_) => return -1,
        }
    };

    let nonce = unsafe {
        match decode(CStr::from_ptr(nonce).to_str().unwrap()) {
            Ok(n) => n,
            Err(_) => return -1,
        }
    };

    let cipher_text = unsafe {
        match decode(CStr::from_ptr(cipher_text).to_str().unwrap()) {
            Ok(c) => c,
            Err(_) => return -1,
        }
    };

    let aad = unsafe {
        if aad.is_null() {
            vec![]
        } else {
            match decode(CStr::from_ptr(aad).to_str().unwrap()) {
                Ok(a) => a,
                Err(_) => return -1,
            }
        }
    };

    let cipher_text_len = cipher_text.len();

    let mut plain_text: Vec<u8> = repeat(0).take(cipher_text_len - 16).collect();
    let tag = cipher_text[cipher_text_len - 16..].to_vec();
    let cipher_text = cipher_text[..cipher_text_len - 16].to_vec();

    let mut aes_gcm = AesGcm::new(KeySize::KeySize128, &key, &nonce, &aad); // use empty aad data
    aes_gcm.decrypt(&cipher_text, &mut plain_text, &tag);

    unsafe {
        *out_plain_text = CString::new(encode(&plain_text)).unwrap().into_raw();
    }

    return 0;
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
    use std::mem::MaybeUninit;

    #[test]
    fn test_cipher() {
        let input = encode("ab".as_bytes());
        println!("input: {:?}", decode(&input).unwrap());
        let plain_text = CString::new(input.clone()).unwrap().into_raw();

        let nonce = CString::new("ed77b0e43daccec06c41f472").unwrap().into_raw();

        let key = CString::new("b058d2931f46abb2a6062abcddf61d75").unwrap().into_raw();
        let aad = CString::new("a7e0f8").unwrap().into_raw();

        let out_cipher_text = MaybeUninit::<*mut c_char>::uninit().as_mut_ptr();
        let out_plain_text = MaybeUninit::<*mut c_char>::uninit().as_mut_ptr();

        rust_encrypt(key, nonce, aad, plain_text, out_cipher_text);

        unsafe {
            let out_cipher = CString::from_raw(*out_cipher_text);
            println!("out_cipher: {:?}", out_cipher);

            rust_decrypt(key, nonce, aad, *out_cipher_text, out_plain_text);

            let out_plain = CString::from_raw(*out_plain_text);
            let output = decode(out_plain.to_str().unwrap()).unwrap();
            println!("out_plain: {:?}", output);
            assert_eq!(output, [97, 98]);
        }
    }

    #[test]
    fn test_rust_crypto() {
        let key = decode("b058d2931f46abb2a6062abcddf61d75").unwrap();
        let nonce = decode("ed77b0e43daccec06c41f472").unwrap();
        let aad = decode("a7e0f8").unwrap();
        let mut cipher_text = vec![0,0];
        let mut out_tag = vec![0u8; 16];
        let plain_text = vec![97,98];

        let mut aes_gcm = AesGcm::new(KeySize::KeySize128, &key, &nonce, &aad); // use empty aad data
        aes_gcm.encrypt(&plain_text, &mut cipher_text, &mut out_tag);

        println!("cipher_text: {:?}", encode(cipher_text));
        println!("out_tag: {:?}", encode(out_tag));
    }
}