use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use hex::{encode, decode};
use ring::aead::{SealingKey, OpeningKey, seal_in_place, open_in_place, AES_128_GCM, Nonce, Aad};

// returned cipher text size is plain text size + 8 bytes nonce + 16 key size
#[no_mangle]
pub extern "C" fn rust_encrypt(
    key: *const c_char,
    nonce: *const c_char,
    aad: *const c_char,
    plain_text: *const c_char,
    out_cipher_text: *mut *mut c_char,
) -> i32 {
    assert!(
        !key.is_null() && !plain_text.is_null() && !out_cipher_text.is_null() && !nonce.is_null()
    );

    let key = unsafe {
        match decode(CStr::from_ptr(key).to_str().unwrap()) {
            Ok(k) => k,
            Err(_) => return -1,
        }
    };

    let nonce = unsafe {
        match decode(CStr::from_ptr(nonce).to_str().unwrap()) {
            Ok(n) => match Nonce::try_assume_unique_for_key(&n) {
                Ok(nonce) => nonce,
                Err(_) => return -1,
            },
            Err(_) => return -1,
        }
    };

    let mut plain_text = unsafe {
        match decode(CStr::from_ptr(plain_text).to_str().unwrap()) {
            Ok(p) => p,
            Err(_) => return -1,
        }
    };

    plain_text.extend_from_slice(&[0; 16]);

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

    let aad = Aad::from(&aad);

    match SealingKey::new(&AES_128_GCM, &key) {
        Ok(sealing_key) => {
            if let Err(_) = seal_in_place(&sealing_key, nonce, aad, &mut plain_text, 16) {
                return -1;
            }
        },
        Err(_) => return -1,
    }

    unsafe {
        *out_cipher_text = CString::new(encode(&plain_text)).unwrap().into_raw();
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn rust_decrypt(
    key: *const c_char,
    nonce: *const c_char,
    aad: *const c_char,
    cipher_text: *const c_char,
    out_plain_text: *mut *mut c_char,
) -> i32 {
    assert!(
        !key.is_null() && !cipher_text.is_null() && !out_plain_text.is_null() && !nonce.is_null()
    );

    let key = unsafe {
        match decode(CStr::from_ptr(key).to_str().unwrap()) {
            Ok(k) => k,
            Err(_) => return -1,
        }
    };

    let nonce = unsafe {
        match decode(CStr::from_ptr(nonce).to_str().unwrap()) {
            Ok(n) => match Nonce::try_assume_unique_for_key(&n) {
                Ok(nonce) => nonce,
                Err(_) => return -1,
            },
            Err(_) => return -1,
        }
    };

    let mut cipher_text = unsafe {
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

    let aad = Aad::from(&aad);

    match OpeningKey::new(&AES_128_GCM, &key) {
        Ok(opening_key) => {
            if let Err(_) = open_in_place(&opening_key, nonce, aad, 0, &mut cipher_text) {
                return -1;
            }
        },
        Err(_) => return -1,
    }

    unsafe {
        *out_plain_text = CString::new(encode(&cipher_text[..cipher_text.len() - 16])).unwrap().into_raw();
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
    fn test_ring() {
        let sealing_key = SealingKey::new(&AES_128_GCM, &decode("b058d2931f46abb2a6062abcddf61d75").unwrap()).unwrap();
        let nonce = Nonce::try_assume_unique_for_key(&decode("ed77b0e43daccec06c41f472").unwrap()).unwrap();
        let ad = decode("a7e0f8").unwrap();
        let aad = Aad::from(&ad);
        let mut in_out = vec![97u8, 98, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
        let out_suffix_capacity = 16;
        match seal_in_place(&sealing_key, nonce, aad, &mut in_out, out_suffix_capacity) {
            Ok(len) => println!("encrypted len: {:?}", len),
            Err(e) => {
                println!("error: {:?}", e);
            }
        }

        println!("in_out: {:?}", encode(&in_out));

        let opening_key = OpeningKey::new(&AES_128_GCM, &decode("b058d2931f46abb2a6062abcddf61d75").unwrap()).unwrap();
        let nonce = Nonce::try_assume_unique_for_key(&decode("ed77b0e43daccec06c41f472").unwrap()).unwrap();
        let aad = Aad::from(&ad);

        match open_in_place(&opening_key, nonce, aad, 0, &mut in_out) {
            Ok(len) => println!("encrypted len: {:?}", len),
            Err(e) => {
                println!("error: {:?}", e);
            }
        }

        println!("decrypted: {:?}", encode(in_out));
    }

    #[test]
    fn test_cipher() {
        let input = encode("ab".as_bytes());
        println!("input: {:?}", decode(&input).unwrap());
        let plain_text = CString::new(input.clone()).unwrap().into_raw();

        let nonce = CString::new("ed77b0e43daccec06c41f472").unwrap().into_raw();

        let key = CString::new("b058d2931f46abb2a6062abcddf61d75")
            .unwrap()
            .into_raw();
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
}
