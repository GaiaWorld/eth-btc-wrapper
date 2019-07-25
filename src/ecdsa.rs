use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use secp256k1::{Secp256k1, Message, SecretKey};
use hex::{decode, encode};

#[no_mangle]
pub extern "C" fn rust_sign(priv_key: *const c_char, msg: *const c_char, signature: *mut *mut c_char) -> i32 {
    assert!(!priv_key.is_null() && !msg.is_null() && !signature.is_null());

    let priv_key = unsafe {
        match decode(CStr::from_ptr(priv_key).to_str().unwrap()) {
            Ok(pk) => pk,
            Err(_) => return -1,
        }
    };

    let msg = unsafe {
        match decode(CStr::from_ptr(msg).to_str().unwrap()) {
            Ok(m) => m,
            Err(_) => return -1,
        }
    };

    let message = match Message::from_slice(&msg) {
        Ok(m) => m,
        Err(_) => return -1,
    };

    let secp = Secp256k1::new();
    let sec_key = match SecretKey::from_slice(&priv_key) {
        Ok(sk) => sk,
        Err(_) => return -1,
    };

    let sig = secp.sign(&message, &sec_key).serialize_der();

    unsafe {
        *signature = CString::new(encode(&sig)).unwrap().into_raw();
    }

    return 0;
}

#[cfg(test)]
mod test {
    use super::*;
    use std::mem::MaybeUninit;

    #[test]
    fn test_sign() {
        let priv_key = CString::new(encode(&[1u8; 32])).unwrap().into_raw();
        let msg = CString::new(encode(&[2u8; 32])).unwrap().into_raw();

        let signature = MaybeUninit::<*mut c_char>::uninit().as_mut_ptr();

        rust_sign(priv_key, msg, signature);

        unsafe {
            let sign = CString::from_raw(*signature);
            println!("signature: {:?}", sign);
        }
    }
}