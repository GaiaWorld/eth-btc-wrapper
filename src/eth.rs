use std::os::raw::c_char;
use std::ffi::{ CStr, CString };
use std::ptr;

use ethereum_tx_sign::RawTransaction;
use ethereum_types::{ U256, H160, H256 };
use hex::{ encode, decode };

#[repr(C)]
pub struct eth_tx_meta {
    nonce: *const c_char,
    to: *const c_char,
    value: *const c_char,
    gas: *const c_char,
    gas_price: *const c_char,
    data: *const c_char,
    priv_key: *const c_char,
    chain_id: u8,
}

#[no_mangle]
pub extern "C" fn build_signed_eth_tx(tx: *const eth_tx_meta) -> *mut c_char {
    unsafe {
        let tx = &*tx;

        if tx.nonce.is_null()
            || tx.to.is_null()
            || tx.value.is_null()
            || tx.gas.is_null()
            || tx.gas_price.is_null()
            || tx.priv_key.is_null() {
                return ptr::null_mut();
            }

        let nonce = String::from_utf8_lossy(CStr::from_ptr(tx.nonce).to_bytes()).to_string();
        let nonce = U256::from(decode(nonce).unwrap().as_slice());

        let to = String::from_utf8_lossy(CStr::from_ptr(tx.to).to_bytes()).to_string();
        let to = Some(H160::from(decode(to).unwrap().as_slice()));

        let value = String::from_utf8_lossy(CStr::from_ptr(tx.value).to_bytes()).to_string();
        let value = U256::from(decode(value).unwrap().as_slice());

        let gas = String::from_utf8_lossy(CStr::from_ptr(tx.gas).to_bytes()).to_string();
        let gas = U256::from(decode(gas).unwrap().as_slice());

        let gas_price = String::from_utf8_lossy(CStr::from_ptr(tx.gas_price).to_bytes()).to_string();
        let gas_price = U256::from(decode(gas_price).unwrap().as_slice());

        let priv_key = String::from_utf8_lossy(CStr::from_ptr(tx.priv_key).to_bytes()).to_string();
        let priv_key = H256::from(decode(priv_key).unwrap().as_slice());

        let data = if tx.data.is_null() {
            vec![]
        } else {
            CStr::from_ptr(tx.data).to_bytes().to_vec()
        };

        let raw_tx = RawTransaction {
            nonce,
            to,
            value,
            gas,
            gas_price,
            data,
        };

        let sig = encode(raw_tx.sign(&priv_key, &tx.chain_id));
        CString::new(sig).unwrap().into_raw()
    }
}

#[no_mangle]
pub extern "C" fn free_cstring(raw: *mut c_char) {
    unsafe {
        CString::from_raw(raw);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn build_tx() {
        let nonce = CStr::from_bytes_with_nul(b"c6\0").unwrap().as_ptr();
        let to = CStr::from_bytes_with_nul(b"14571A8f98301DB5dC5c7640A9C7f6CA5BEaB338\0").unwrap().as_ptr();
        let value = CStr::from_bytes_with_nul(b"6666\0").unwrap().as_ptr();
        let gas_price = CStr::from_bytes_with_nul(b"14a817c800\0").unwrap().as_ptr();
        let gas = CStr::from_bytes_with_nul(b"6208\0").unwrap().as_ptr();
        let data = vec![1i8; 11].as_ptr();
        let priv_key = CStr::from_bytes_with_nul(b"abd952e991fb40a146291e6c537fc0db0d1b6de0a815df11efb7e73e1e50daf8\0").unwrap().as_ptr();
        // ropsten
        let chain_id = 3;

        let tx_meta = eth_tx_meta {
            nonce,
            to,
            value,
            gas,
            gas_price,
            data,
            priv_key,
            chain_id,
        };

        let sig = build_signed_eth_tx(&tx_meta);
        unsafe {
            let cstring = CString::from_raw(sig as *mut c_char);
            println!("signed_tx: {:?}", cstring);
        }
    }
}
