use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use ethabi::{Contract, Token};
use ethereum_tx_sign::RawTransaction;
use ethereum_types::{H160, H256, U256};
use hex::{decode, encode};
use primitive_types;

use bip39::{Language, Mnemonic, MnemonicType, Seed};
use tiny_hderive::bip32::ExtendedPrivKey;

use ethsign::SecretKey;

use secp256k1::{PublicKey as SecpPublickey, Secp256k1, SecretKey as Secp256SecKey};

#[no_mangle]
pub extern "C" fn dealloc_rust_cstring(cstring: *mut c_char) {
    unsafe {
        CString::from_raw(cstring);
    }
}

#[no_mangle]
pub extern "C" fn eth_from_mnemonic(
    mnemonic: *const c_char,
    language: *const c_char,
    address: *mut *mut c_char,
    priv_key: *mut *mut c_char,
    master_seed: *mut *mut c_char,
) -> i32 {
    assert!(
        !mnemonic.is_null()
            && !language.is_null()
            && !address.is_null()
            && !priv_key.is_null()
            && !master_seed.is_null()
    );
    let mnemonic = unsafe { CStr::from_ptr(mnemonic).to_str().unwrap() };

    let language = unsafe {
        match CStr::from_ptr(language).to_str().unwrap() {
            "english" => Language::English,
            "chinese_simplified" => Language::ChineseSimplified,
            "chinese_traditional" => Language::ChineseTraditional,
            _ => return -1,
        }
    };

    let seed = Seed::new(&Mnemonic::from_phrase(mnemonic, language).unwrap(), "");
    let ext = ExtendedPrivKey::derive(seed.as_bytes(), "m/44'/60'/0'/0/0").unwrap();
    let privte_key = SecretKey::from_raw(&ext.secret()).unwrap();

    unsafe {
        let addr = "0x".to_string() + &encode(privte_key.public().address());
        *address = CString::new(addr).unwrap().into_raw();
        *priv_key = CString::new(encode(ext.secret())).unwrap().into_raw();
        *master_seed = CString::new(encode(seed)).unwrap().into_raw();
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn eth_generate(
    strength: u32,
    language: *const c_char,
    address: *mut *mut c_char,
    priv_key: *mut *mut c_char,
    master_seed: *mut *mut c_char,
    mnemonic: *mut *mut c_char,
) -> i32 {
    assert!(
        !language.is_null()
            && !address.is_null()
            && !priv_key.is_null()
            && !master_seed.is_null()
            && !mnemonic.is_null()
    );
    if strength % 32 != 0 || strength < 128 {
        return -1;
    }

    let strength = {
        match (strength + strength / 32) / 11 {
            12 => MnemonicType::Words12,
            15 => MnemonicType::Words15,
            18 => MnemonicType::Words18,
            21 => MnemonicType::Words21,
            24 => MnemonicType::Words24,
            _ => return -1,
        }
    };

    let language = unsafe {
        let lan = CStr::from_ptr(language).to_str().unwrap();
        if lan == "english" {
            Language::English
        } else if lan == "chinese_simplified" {
            Language::ChineseSimplified
        } else if lan == "chinese_traditional" {
            Language::ChineseTraditional
        } else {
            return -1;
        }
    };

    let mn = Mnemonic::new(strength, language);
    let phrase = mn.phrase();

    let seed = Seed::new(&Mnemonic::from_phrase(phrase, language).unwrap(), "");
    let ext = ExtendedPrivKey::derive(seed.as_bytes(), "m/44'/60'/0'/0/0").unwrap();
    let privte_key = SecretKey::from_raw(&ext.secret()).unwrap();

    unsafe {
        let addr = "0x".to_string() + &encode(privte_key.public().address());
        *address = CString::new(addr).unwrap().into_raw();
        *priv_key = CString::new(encode(ext.secret())).unwrap().into_raw();
        *master_seed = CString::new(encode(seed)).unwrap().into_raw();
        *mnemonic = CString::new(phrase).unwrap().into_raw();
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn eth_sign_raw_transaction(
    chain_id: u8,
    nonce: *const c_char,
    to: *const c_char,
    value: *const c_char,
    gas: *const c_char,
    gas_price: *const c_char,
    data: *const c_char,
    priv_key: *const c_char,
    tx_hash: *mut *mut c_char,
    serialized: *mut *mut c_char,
) -> i32 {
    assert!(
        !nonce.is_null()
            && !to.is_null()
            && !value.is_null()
            && !gas.is_null()
            && !gas_price.is_null()
            && !priv_key.is_null()
            && !tx_hash.is_null()
            && !serialized.is_null()
    );

    let nonce = U256::from(
        decode(unsafe { CStr::from_ptr(nonce).to_str().unwrap() })
            .unwrap()
            .as_slice(),
    );
    let to = Some(H160::from(
        decode(unsafe { CStr::from_ptr(to).to_str().unwrap() })
            .unwrap()
            .as_slice(),
    ));
    let value = U256::from(
        decode(unsafe { CStr::from_ptr(value).to_str().unwrap() })
            .unwrap()
            .as_slice(),
    );
    let gas = U256::from(
        decode(unsafe { CStr::from_ptr(gas).to_str().unwrap() })
            .unwrap()
            .as_slice(),
    );
    let gas_price = U256::from(
        decode(unsafe { CStr::from_ptr(gas_price).to_str().unwrap() })
            .unwrap()
            .as_slice(),
    );
    let priv_key = H256::from(
        decode(unsafe { CStr::from_ptr(priv_key).to_str().unwrap() })
            .unwrap()
            .as_slice(),
    );

    let data = if data.is_null() {
        vec![]
    } else {
        decode(unsafe { CStr::from_ptr(data).to_str().unwrap() }).unwrap()
    };

    let raw_tx = RawTransaction {
        nonce,
        to,
        value,
        gas,
        gas_price,
        data,
    };

    let (hash, sig) = raw_tx.sign(&priv_key, &chain_id);

    unsafe {
        *tx_hash = CString::new(encode(hash)).unwrap().into_raw();
        *serialized = CString::new(encode(sig)).unwrap().into_raw();
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn eth_select_wallet(
    language: *const c_char,
    master_seed: *const c_char,
    index: u32,
    address: *mut *mut c_char,
    priv_key: *mut *mut c_char,
) -> i32 {
    assert!(!master_seed.is_null() && !address.is_null() && !priv_key.is_null());

    let master_seed = unsafe { decode(CStr::from_ptr(master_seed).to_str().unwrap()).unwrap() };

    let _language = unsafe {
        match CStr::from_ptr(language).to_str().unwrap() {
            "english" => Language::English,
            "chinese_simplified" => Language::ChineseSimplified,
            "chinese_traditional" => Language::ChineseTraditional,
            _ => return -1,
        }
    };

    let derive_path = format!("m/44'/60'/0'/0/{:?}", index);

    let ext = ExtendedPrivKey::derive(&master_seed, derive_path.as_str()).unwrap();
    let privte_key = SecretKey::from_raw(&ext.secret()).unwrap();

    unsafe {
        let addr = "0x".to_string() + &encode(privte_key.public().address());
        *address = CString::new(addr).unwrap().into_raw();
        *priv_key = CString::new(encode(ext.secret())).unwrap().into_raw();
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn get_public_key_by_mnemonic(
    mnemonic: *const c_char,
    language: *const c_char,
    public_key: *mut *mut c_char,
) -> i32 {
    assert!(!mnemonic.is_null() && !language.is_null() && !public_key.is_null());
    let language = unsafe {
        match CStr::from_ptr(language).to_str().unwrap() {
            "english" => Language::English,
            "chinese_simplified" => Language::ChineseSimplified,
            "chinese_traditional" => Language::ChineseTraditional,
            _ => return -1,
        }
    };

    let mnemonic = unsafe { CStr::from_ptr(mnemonic).to_str().unwrap() };

    let seed = Seed::new(&Mnemonic::from_phrase(mnemonic, language).unwrap(), "");
    let ext = ExtendedPrivKey::derive(seed.as_bytes(), "m/44'/60'/0'/0/0").unwrap();
    let secp = Secp256k1::new();
    let private_key = Secp256SecKey::from_slice(&ext.secret()).unwrap();
    let pub_key = &SecpPublickey::from_secret_key(&secp, &private_key).serialize_uncompressed()[..];

    unsafe {
        *public_key = CString::new(encode(pub_key)).unwrap().into_raw();
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn token_balance_call_data(addr: *const c_char) -> *mut c_char {
    unsafe {
        let addr = String::from_utf8_lossy(CStr::from_ptr(addr).to_bytes()).to_string();
        let addr = primitive_types::H160::from_slice(decode(addr).unwrap().as_slice());

        let contract = Contract::load(ERC20ABI.as_bytes()).unwrap();
        let function = contract.function("balanceOf").unwrap();
        let token = Token::Address(addr);
        let input = function.encode_input(&[token]);

        CString::new(input.unwrap()).unwrap().into_raw()
    }
}

#[no_mangle]
pub extern "C" fn token_transfer_call_data(
    addr_to: *const c_char,
    value: *const c_char,
) -> *mut c_char {
    unsafe {
        let addr_to = String::from_utf8_lossy(CStr::from_ptr(addr_to).to_bytes()).to_string();
        let addr_to = primitive_types::H160::from_slice(decode(addr_to).unwrap().as_slice());

        let value = String::from_utf8_lossy(CStr::from_ptr(value).to_bytes()).to_string();
        let value = primitive_types::U256::from(decode(value).unwrap().as_slice());

        let contract = Contract::load(ERC20ABI.as_bytes()).unwrap();
        let function = contract.function("transfer").unwrap();
        let addr_token = Token::Address(addr_to);
        let value_token = Token::Uint(primitive_types::U256::from(value));
        let input = function.encode_input(&[addr_token, value_token]);

        CString::new(input.unwrap()).unwrap().into_raw()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex::{decode, encode};
    use std::mem::MaybeUninit;

    #[test]
    fn test_get_public_key_by_mnemonic() {
        let m = CString::new(
            "lunar exercise inside defense accuse reopen symbol oak milk top chunk axis",
        )
        .unwrap()
        .into_raw();
        let lan = CString::new("english").unwrap().into_raw();

        let public_key = MaybeUninit::<*mut c_char>::uninit().as_mut_ptr();

        get_public_key_by_mnemonic(m, lan, public_key);

        unsafe {
            let pubkey = CString::from_raw(*public_key);
            println!("get public key by mnemonic: {:?}", pubkey);
        }
    }

    #[test]
    fn test_eth_select_wallet() {
        let language = CString::new("english").unwrap().into_raw();

        let addr = MaybeUninit::<*mut c_char>::uninit().as_mut_ptr();
        let master_seed = CString::new("76f1d5cf855301e7afdd294f8ec9459b59f1b323a11b23004762fc5cd5b4dec096825f63494760083eb9073c8fa137f1a9df6b426a20a77e0494e1a1a2a24dae").unwrap().into_raw();
        let priv_key = MaybeUninit::<*mut c_char>::uninit().as_mut_ptr();

        eth_select_wallet(language, master_seed, 0, addr, priv_key);

        unsafe {
            let address = CString::from_raw(*addr);
            let priv_key = CString::from_raw(*priv_key);

            println!("select wallet address: {:?}", address);
            println!("select wallet privakey: {:?}", priv_key);
        }
    }

    #[test]
    fn test_eth_generate() {
        let strength = 128;
        let language = CString::new("english").unwrap().into_raw();

        let addr = MaybeUninit::<*mut c_char>::uninit().as_mut_ptr();
        let master = MaybeUninit::<*mut c_char>::uninit().as_mut_ptr();
        let priv_key = MaybeUninit::<*mut c_char>::uninit().as_mut_ptr();
        let mn = MaybeUninit::<*mut c_char>::uninit().as_mut_ptr();

        eth_generate(strength, language, addr, priv_key, master, mn);

        unsafe {
            let addr = CString::from_raw(*addr);
            let master = CString::from_raw(*master);
            let priv_key = CString::from_raw(*priv_key);
            let mn = CString::from_raw(*mn);

            println!("addr: {:?}", addr);
            println!("master: {:?}", master);
            println!("priv_key: {:?}", priv_key);
            println!("mn: {:?}", mn);
        }
    }

    #[test]
    fn test_eth_from_mnemonic() {
        let m = CString::new(
            "lunar exercise inside defense accuse reopen symbol oak milk top chunk axis",
        )
        .unwrap();
        let lan = CString::new("english").unwrap();

        let addr = MaybeUninit::<*mut c_char>::uninit().as_mut_ptr();
        let master = MaybeUninit::<*mut c_char>::uninit().as_mut_ptr();
        let priv_key = MaybeUninit::<*mut c_char>::uninit().as_mut_ptr();

        unsafe {
            eth_from_mnemonic(m.into_raw(), lan.into_raw(), addr, priv_key, master);

            let addr = CString::from_raw(*addr as *mut c_char);
            let master = CString::from_raw(*master as *mut c_char);
            let priv_key = CString::from_raw(*priv_key as *mut c_char);

            assert_eq!(
                addr.to_str().unwrap(),
                "0x151ab25145928bf6dd013f6de3446fd6d67ad8c9"
            );
            assert_eq!(master.to_str().unwrap(), "065a6b481570379561574676ad61c96caf3e05ebd1d79c712f3dec938be73bbffd6ad02bd62ad90d1a9d6f00551134d480e1166fa8d0be2cc4d7132dd66a282c");
            assert_eq!(
                priv_key.to_str().unwrap(),
                "ff33ff993b1782d16427276a9cc966b8b995c118f0182243152a882b8d3e3faf"
            );
        }
    }

    #[test]
    fn mnemonic_to_privtekey() {
        // create a new randomly generated mnemonic phrase
        let mnemonic = Mnemonic::from_phrase(
            "lunar exercise inside defense accuse reopen symbol oak milk top chunk axis",
            Language::English,
        )
        .unwrap();

        // get the HD wallet seed
        let seed = Seed::new(&mnemonic, "");

        // get the HD wallet seed as raw bytes
        let seed_bytes: &[u8] = seed.as_bytes();

        let expected_prviate_key =
            decode("ff33ff993b1782d16427276a9cc966b8b995c118f0182243152a882b8d3e3faf").unwrap();

        let ext = ExtendedPrivKey::derive(seed_bytes, "m/44'/60'/0'/0/0").unwrap();
        println!("ext: {:?}", encode(ext.secret()));
        assert_eq!(ext.secret().to_vec(), expected_prviate_key);
    }

    #[test]
    fn test_ethereum_tx_sign() {
        let nonce = CStr::from_bytes_with_nul(b"c9\0").unwrap().as_ptr();
        let to = CStr::from_bytes_with_nul(b"14571A8f98301DB5dC5c7640A9C7f6CA5BEaB338\0")
            .unwrap()
            .as_ptr();
        let value = CStr::from_bytes_with_nul(b"6666\0").unwrap().as_ptr();
        let gas_price = CStr::from_bytes_with_nul(b"14a817c800\0").unwrap().as_ptr();
        let gas = CStr::from_bytes_with_nul(b"6208\0").unwrap().as_ptr();
        let data = CString::new("12345678").unwrap().into_raw();
        let priv_key = CStr::from_bytes_with_nul(
            b"abd952e991fb40a146291e6c537fc0db0d1b6de0a815df11efb7e73e1e50daf8\0",
        )
        .unwrap()
        .as_ptr();

        let tx_hash = MaybeUninit::<*mut c_char>::uninit().as_mut_ptr();
        let serialized = MaybeUninit::<*mut c_char>::uninit().as_mut_ptr();
        // ropsten
        let chain_id = 3;

        eth_sign_raw_transaction(
            chain_id, nonce, to, value, gas, gas_price, data, priv_key, tx_hash, serialized,
        );
        unsafe {
            let tx_hash = CString::from_raw(*tx_hash);
            let serialized = CString::from_raw(*serialized);

            println!("tx_hash: {:?}", tx_hash);
            println!("serialized: {:?}", serialized);
        }
    }
}

static ERC20ABI: &'static str = r#"
[
    {
        "constant": false,
        "inputs": [
            {
                "name": "_spender",
                "type": "address"
            },
            {
                "name": "_value",
                "type": "uint256"
            }
        ],
        "name": "approve",
        "outputs": [
            {
                "name": "success",
                "type": "bool"
            }
        ],
        "type": "function"
    },
    {
        "constant": true,
        "inputs": [],
        "name": "totalSupply",
        "outputs": [
            {
                "name": "total",
                "type": "uint256"
            }
        ],
        "type": "function"
    },
    {
        "constant": false,
        "inputs": [
            {
                "name": "_from",
                "type": "address"
            },
            {
                "name": "_to",
                "type": "address"
            },
            {
                "name": "_value",
                "type": "uint256"
            }
        ],
        "name": "transferFrom",
        "outputs": [
            {
                "name": "success",
                "type": "bool"
            }
        ],
        "type": "function"
    },
    {
        "constant": true,
        "inputs": [
            {
                "name": "_owner",
                "type": "address"
            }
        ],
        "name": "balanceOf",
        "outputs": [
            {
                "name": "balance",
                "type": "uint256"
            }
        ],
        "type": "function"
    },
    {
        "constant": false,
        "inputs": [
            {
                "name": "_to",
                "type": "address"
            },
            {
                "name": "_value",
                "type": "uint256"
            }
        ],
        "name": "transfer",
        "outputs": [
            {
                "name": "success",
                "type": "bool"
            }
        ],
        "type": "function"
    },
    {
        "constant": true,
        "inputs": [
            {
                "name": "_owner",
                "type": "address"
            },
            {
                "name": "_spender",
                "type": "address"
            }
        ],
        "name": "allowance",
        "outputs": [
            {
                "name": "remaining",
                "type": "uint256"
            }
        ],
        "type": "function"
    },
    {
        "anonymous": false,
        "inputs": [
            {
                "indexed": true,
                "name": "from",
                "type": "address"
            },
            {
                "indexed": true,
                "name": "to",
                "type": "address"
            },
            {
                "indexed": false,
                "name": "value",
                "type": "uint256"
            }
        ],
        "name": "Transfer",
        "type": "event"
    },
    {
        "anonymous": false,
        "inputs": [
            {
                "indexed": true,
                "name": "owner",
                "type": "address"
            },
            {
                "indexed": true,
                "name": "spender",
                "type": "address"
            },
            {
                "indexed": false,
                "name": "value",
                "type": "uint256"
            }
        ],
        "name": "Approval",
        "type": "event"
    }
]
"#;
