use std::os::raw::c_char;
use std::ffi::{ CStr, CString };
use std::ptr;
use bitcoin::blockdata::transaction::{
    TxIn, TxOut, Transaction, OutPoint
};
use bitcoin::blockdata::script::Script;
use bitcoin_hashes::{sha256d, Hash};
use hex::{encode, decode};
use bitcoin::util::psbt::serialize::Serialize;
use bitcoin::consensus::encode::Encodable;
use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::network::constants::Network;

use bip39::{Mnemonic, MnemonicType, Language, Seed};

#[no_mangle]
pub extern "C" fn btc_generate(strength: u32, network: *const c_char, language: *const c_char, pass_phrase: *const c_char, root_xpriv: *mut *mut c_char, mnemonic: *mut *mut c_char) -> i32 {
    assert!(!network.is_null() && !language.is_null() && !root_xpriv.is_null() && !pass_phrase.is_null() && !root_xpriv.is_null() && !mnemonic.is_null());

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
        match CStr::from_ptr(language).to_str().unwrap() {
            "english" => Language::English,
            "chinese_simplified" => Language::ChineseSimplified,
            "chinese_traditional" => Language::ChineseTraditional,
            _ => return -1,
        }
    };

    let network = unsafe {
        match CStr::from_ptr(network).to_str().unwrap() {
            "mainnet" => Network::Bitcoin,
            "testnet" => Network::Testnet,
            "regtest" => Network::Regtest,
            _ => return -1,
        }
    };

    let pass_phrase = unsafe {
        CStr::from_ptr(pass_phrase).to_str().unwrap()
    };

    let mn = Mnemonic::new(strength, language);
    let phrase = mn.phrase();

    let seed = Seed::new(&Mnemonic::from_phrase(phrase, language).unwrap(), pass_phrase);
    let extkey = ExtendedPrivKey::new_master(network, seed.as_bytes()).unwrap();

    unsafe {
        *root_xpriv = CString::new(extkey.to_string()).unwrap().into_raw();
        *mnemonic = CString::new(phrase).unwrap().into_raw();
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn btc_from_mnemonic(mnemonic: *const c_char, network: *const c_char, language: *const c_char, pass_phrase: *const c_char, root_xpriv: *mut *mut c_char, root_seed: *mut *mut c_char) -> i32 {
    let language = unsafe {
        match CStr::from_ptr(language).to_str().unwrap() {
            "english" => Language::English,
            "chinese_simplified" => Language::ChineseSimplified,
            "chinese_traditional" => Language::ChineseTraditional,
            _ => return -1,
        }
    };

    let network = unsafe {
        match CStr::from_ptr(network).to_str().unwrap() {
            "mainnet" => Network::Bitcoin,
            "testnet" => Network::Testnet,
            "regtest" => Network::Regtest,
            _ => return -1,
        }
    };

    let pass_phrase = unsafe {
        CStr::from_ptr(pass_phrase).to_str().unwrap()
    };

    let mnemonic = unsafe {
        CStr::from_ptr(mnemonic).to_str().unwrap()
    };

    let seed = Seed::new(&Mnemonic::from_phrase(mnemonic, language).unwrap(), pass_phrase);
    let extkey = ExtendedPrivKey::new_master(network, seed.as_bytes()).unwrap();

    unsafe {
        *root_xpriv = CString::new(extkey.to_string()).unwrap().into_raw();
        *root_seed = CString::new(encode(seed.as_bytes())).unwrap().into_raw();
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn btc_from_seed(seed: *const c_char, network: *const c_char, language: *const c_char, root_xpriv: *mut *mut c_char) -> i32 {
    unimplemented!();
}

#[no_mangle]
pub extern "C" fn btc_private_key_of(root_xpriv: *const c_char, priv_key: *mut *mut c_char) -> i32 {
    unimplemented!();
}

#[no_mangle]
pub extern "C" fn btc_build_raw_transaction_from_single_address(priv_key: *const c_char, output: *const c_char, fee: *const c_char, raw_tx: *mut *mut c_char, tx_hash: *mut *mut c_char) -> i32 {
    unimplemented!();
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;
    use std::mem::MaybeUninit;
    use secp256k1::key::SecretKey;
    use secp256k1::Message;
    use secp256k1::Secp256k1;

    use bitcoin::util::key::PrivateKey;
    use bitcoin::consensus::encode::serialize;

    #[test]
    fn test_btc_from_mnemonic() {
        let network = CString::new("testnet").unwrap().into_raw();
        let lanuage = CString::new("english").unwrap().into_raw();
        let pass_phrase = CString::new("").unwrap().into_raw();
        let mnemonic = CString::new("drum credit sport athlete mixed busy winter humor turtle auto snack abstract").unwrap().into_raw();

        let root_xpriv = MaybeUninit::<*mut c_char>::uninit().as_mut_ptr();
        let root_seed = MaybeUninit::<*mut c_char>::uninit().as_mut_ptr();

        btc_from_mnemonic(mnemonic, network, lanuage, pass_phrase, root_xpriv, root_seed);

        unsafe {
            let root_xpriv = CString::from_raw(*root_xpriv);
            let root_seed = CString::from_raw(*root_seed);

            println!("root_xpriv: {:?}", root_xpriv);
            println!("root_seed: {:?}", root_seed);
        }
    }

    #[test]
    fn test_btc_generate() {
        let strength = 128;
        let network = CString::new("testnet").unwrap().into_raw();
        let lanuage = CString::new("english").unwrap().into_raw();
        let pass_phrase = CString::new("").unwrap().into_raw();

        let root_xpriv = MaybeUninit::<*mut c_char>::uninit().as_mut_ptr();
        let mnemonic = MaybeUninit::<*mut c_char>::uninit().as_mut_ptr();

        btc_generate(strength, network, lanuage, pass_phrase, root_xpriv, mnemonic);

        unsafe {
            let root_xpriv = CString::from_raw(*root_xpriv);
            let mnemonic = CString::from_raw(*mnemonic);

            println!("root_xpriv: {:?}", root_xpriv);
            println!("mnemonic: {:?}", mnemonic);
        }
    }

    #[test]
    fn build_raw_tx() {
        let mut raw_tx = Transaction {
            version: 1,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint::from_str("964b06c7d65bc2966ffc089be06469cf3961fdae4253cb51fe158bf1696882a1:1").unwrap(),
                script_sig: Script::from(decode("76a9145477d7bfe9bdf17cea9f5b2ecacc7a2577723c7488ac").unwrap()),
                sequence: 0,
                witness: vec![],
            }, TxIn {
                previous_output: OutPoint::from_str("6c1fd83338c12326e9160d57a95198937a228b6c4f55e882792be19fe2038da5:1").unwrap(),
                script_sig: Script::from(decode("76a9145477d7bfe9bdf17cea9f5b2ecacc7a2577723c7488ac").unwrap()),
                sequence: 0,
                witness: vec![],
            }],
            output: vec![TxOut {
                value: 81243807,
                script_pubkey: Script::from(decode("76a9145477d7bfe9bdf17cea9f5b2ecacc7a2577723c7488ac").unwrap()),
            }, TxOut {
                value: 100000,
                script_pubkey: Script::from(decode("76a91402245e1265ca65f5ab6d70289f7bcfed6204810588ac").unwrap()),
            }],
        };

        let sig_hash = raw_tx.signature_hash(0, &Script::from(decode("76a9145477d7bfe9bdf17cea9f5b2ecacc7a2577723c7488ac").unwrap()), 1);

        let secp = Secp256k1::new();
        let msg = Message::from_slice(&sig_hash.into_inner()).unwrap();
        let sk = PrivateKey::from_wif("cRVuQd8qSuSRifRverDNAKmBGgDNDu55mV2gtyoBFT4gwHeuJFQ4").unwrap();
        let mut sig = secp.sign(&msg, &sk.key).serialize_der().as_ref().to_vec();

        println!("sig: {:?}", encode(&sig));

        raw_tx.input[0].script_sig = Script::from(sig);

        let sig_hash2 = raw_tx.signature_hash(1, &Script::from(decode("76a9145477d7bfe9bdf17cea9f5b2ecacc7a2577723c7488ac").unwrap()), 1);
        let msg2 = Message::from_slice(&sig_hash2.into_inner()).unwrap();
        let sig2 = secp.sign(&msg2, &sk.key).serialize_der().as_ref().to_vec();

        println!("sig2: {:?}", encode(&sig2));


        raw_tx.input[1].script_sig = Script::from(sig2);

        // let serialized = raw_tx.serialize();
        let serialized = serialize(&raw_tx);

        println!("serialized: {:?}", encode(serialized));
    }
}