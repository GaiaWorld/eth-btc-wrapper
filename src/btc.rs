use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::script::{Builder, Script};
use bitcoin::blockdata::transaction::{OutPoint, Transaction, TxIn, TxOut};
use bitcoin::network::constants::Network;
use bitcoin::util::base58::{check_encode_slice, from_check};
use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey};
use bitcoin::util::hash::BitcoinHash;
use bitcoin::util::key::{PrivateKey, PublicKey};
use bitcoin::util::psbt::serialize::Serialize;
use bitcoin_hashes::{hex::ToHex, ripemd160, sha256, Hash};
use hex::{decode, encode};
use std::convert::From;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::str::FromStr;

use secp256k1::Message;
use secp256k1::Secp256k1;

use bip39::{Language, Mnemonic, MnemonicType, Seed};

#[derive(Debug, Clone)]
struct SpentOut {
    pub value: u64,
    pub script_pubkey: Script,
}

impl From<SpentOut> for TxOut {
    fn from(so: SpentOut) -> Self {
        TxOut {
            value: so.value,
            script_pubkey: so.script_pubkey,
        }
    }
}

impl FromStr for SpentOut {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<SpentOut, Self::Err> {
        if let Some(index) = s.find(":") {
            Ok(SpentOut {
                value: s[index + 1..].parse::<u64>().unwrap(),
                script_pubkey: Script::from(decode(&s[..index]).unwrap()),
            })
        } else {
            Err("tx out format error")
        }
    }
}

#[no_mangle]
pub extern "C" fn btc_generate(
    strength: u32,
    network: *const c_char,
    language: *const c_char,
    pass_phrase: *const c_char,
    root_xpriv: *mut *mut c_char,
    mnemonic: *mut *mut c_char,
) -> i32 {
    assert!(
        !network.is_null()
            && !language.is_null()
            && !root_xpriv.is_null()
            && !pass_phrase.is_null()
            && !root_xpriv.is_null()
            && !mnemonic.is_null()
    );

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
            "livenet" => Network::Bitcoin,
            "testnet" => Network::Testnet,
            "regtest" => Network::Regtest,
            _ => return -1,
        }
    };

    let pass_phrase = unsafe { CStr::from_ptr(pass_phrase).to_str().unwrap() };

    let mn = Mnemonic::new(strength, language);
    let phrase = mn.phrase();

    let seed = Seed::new(
        &Mnemonic::from_phrase(phrase, language).unwrap(),
        pass_phrase,
    );
    let extkey = ExtendedPrivKey::new_master(network, seed.as_bytes()).unwrap();

    unsafe {
        *root_xpriv = CString::new(extkey.to_string()).unwrap().into_raw();
        *mnemonic = CString::new(phrase).unwrap().into_raw();
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn btc_from_mnemonic(
    mnemonic: *const c_char,
    network: *const c_char,
    language: *const c_char,
    pass_phrase: *const c_char,
    root_xpriv: *mut *mut c_char,
    root_seed: *mut *mut c_char,
) -> i32 {
    assert!(
        !mnemonic.is_null()
            && !network.is_null()
            && !language.is_null()
            && !pass_phrase.is_null()
            && !root_xpriv.is_null()
            && !root_seed.is_null()
    );
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
            "livenet" => Network::Bitcoin,
            "testnet" => Network::Testnet,
            "regtest" => Network::Regtest,
            _ => return -1,
        }
    };

    let pass_phrase = unsafe { CStr::from_ptr(pass_phrase).to_str().unwrap() };

    let mnemonic = unsafe { CStr::from_ptr(mnemonic).to_str().unwrap() };

    let seed = Seed::new(
        &Mnemonic::from_phrase(mnemonic, language).unwrap(),
        pass_phrase,
    );
    let extkey = ExtendedPrivKey::new_master(network, seed.as_bytes()).unwrap();

    unsafe {
        *root_xpriv = CString::new(extkey.to_string()).unwrap().into_raw();
        *root_seed = CString::new(encode(seed.as_bytes())).unwrap().into_raw();
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn btc_from_seed(
    seed: *const c_char,
    network: *const c_char,
    language: *const c_char,
    root_xpriv: *mut *mut c_char,
) -> i32 {
    assert!(!seed.is_null() && !network.is_null() && !language.is_null() && !root_xpriv.is_null());
    let _language = unsafe {
        match CStr::from_ptr(language).to_str().unwrap() {
            "english" => Language::English,
            "chinese_simplified" => Language::ChineseSimplified,
            "chinese_traditional" => Language::ChineseTraditional,
            _ => return -1,
        }
    };

    let network = unsafe {
        match CStr::from_ptr(network).to_str().unwrap() {
            "livenet" => Network::Bitcoin,
            "testnet" => Network::Testnet,
            "regtest" => Network::Regtest,
            _ => return -1,
        }
    };

    let seed = unsafe { CStr::from_ptr(seed).to_str().unwrap() };

    let extkey = ExtendedPrivKey::new_master(network, &decode(&seed).unwrap()).unwrap();
    unsafe {
        *root_xpriv = CString::new(extkey.to_string()).unwrap().into_raw();
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn btc_private_key_of(
    index: u32,
    root_xpriv: *const c_char,
    priv_key: *mut *mut c_char,
) -> i32 {
    assert!(!root_xpriv.is_null() && !priv_key.is_null());
    let root_xpriv = unsafe { CStr::from_ptr(root_xpriv).to_str().unwrap() };

    let secp = Secp256k1::new();
    let extkey = ExtendedPrivKey::from_str(root_xpriv).unwrap();

    let path = {
        match extkey.network {
            Network::Bitcoin => format!("m/44'/0'/0'/0/{:?}", index),
            Network::Testnet => format!("m/44'/1'/0'/0/{:?}", index),
            Network::Regtest => format!("m/44'/1'/0'/0/{:?}", index),
        }
    };

    let private_key = extkey
        .derive_priv(&secp, &DerivationPath::from_str(&path).unwrap())
        .unwrap()
        .private_key;

    unsafe {
        *priv_key = CString::new(private_key.to_wif()).unwrap().into_raw();
    }

    return 0;
}

// http://www.righto.com/2014/02/bitcoins-hard-way-using-raw-bitcoin.html
#[no_mangle]
pub extern "C" fn btc_build_raw_transaction_from_single_address(
    address: *const c_char,
    priv_key: *const c_char,
    input: *const c_char,
    output: *const c_char,
    raw_tx: *mut *mut c_char,
    tx_hash: *mut *mut c_char,
) -> i32 {
    assert!(
        !address.is_null()
            && !priv_key.is_null()
            && !input.is_null()
            && !output.is_null()
            && !raw_tx.is_null()
            && !tx_hash.is_null()
    );

    let secp = Secp256k1::new();
    let priv_key =
        unsafe { PrivateKey::from_wif(CStr::from_ptr(priv_key).to_str().unwrap()).unwrap() };

    let address =
        unsafe { from_check(CStr::from_ptr(address).to_str().unwrap()).unwrap()[1..].to_vec() };

    let public_key = priv_key.public_key(&secp);

    let input = unsafe { CStr::from_ptr(input).to_str().unwrap() };

    let output = unsafe { CStr::from_ptr(output).to_str().unwrap() };

    let previous_output = if let Some(_) = input.find(";") {
        input
            .split(";")
            .map(|tx| OutPoint::from_str(tx).unwrap())
            .collect::<Vec<OutPoint>>()
    } else {
        vec![OutPoint::from_str(input).unwrap()]
    };

    let default_script_sig = {
        let builder = Builder::new();
        builder
            .push_opcode(opcodes::all::OP_DUP)
            .push_opcode(opcodes::all::OP_HASH160)
            .push_slice(&address)
            .push_opcode(opcodes::all::OP_EQUALVERIFY)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script()
    };

    let txins = previous_output
        .iter()
        .map(|txin| TxIn {
            previous_output: txin.clone(),
            script_sig: default_script_sig.clone(),
            sequence: 0,
            witness: vec![],
        })
        .collect::<Vec<TxIn>>();

    let spent_out = if let Some(_) = output.find(";") {
        output
            .split(";")
            .map(|txout| SpentOut::from_str(txout).unwrap())
            .collect::<Vec<SpentOut>>()
    } else {
        vec![SpentOut::from_str(output).unwrap()]
    };

    let txouts = spent_out
        .iter()
        .map(|so| TxOut::from(so.clone()))
        .collect::<Vec<TxOut>>();

    let mut tx = Transaction {
        version: 1,
        lock_time: 0,
        input: txins.clone(),
        output: txouts,
    };

    let sig_hashes = txins
        .iter()
        .enumerate()
        .map(|(index, txin)| tx.signature_hash(index, &txin.script_sig, 1).into_inner())
        .collect::<Vec<_>>();

    let sigs = sig_hashes
        .iter()
        .map(|sig_hash| {
            let msg = Message::from_slice(&sig_hash.to_vec().as_slice()).unwrap();
            let mut sig = secp.sign(&msg, &priv_key.key).serialize_der();
            sig.push(1);
            sig
        })
        .collect::<Vec<_>>();

    let script_sigs = sigs
        .iter()
        .map(|sig| {
            let builder = Builder::new();
            builder.push_slice(sig).push_key(&public_key).into_script()
        })
        .collect::<Vec<_>>();

    script_sigs
        .into_iter()
        .enumerate()
        .for_each(|(index, script_sig)| {
            tx.input[index].script_sig = script_sig;
        });

    unsafe {
        *raw_tx = CString::new(encode(tx.serialize())).unwrap().into_raw();
        *tx_hash = CString::new(tx.bitcoin_hash().to_string())
            .unwrap()
            .into_raw();
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn btc_to_address(
    network: *const c_char,
    priv_key: *const c_char,
    address: *mut *mut c_char,
) -> i32 {
    assert!(!network.is_null() && !priv_key.is_null() && !address.is_null());

    let network = unsafe {
        match CStr::from_ptr(network).to_str().unwrap() {
            "livenet" => Network::Bitcoin,
            "testnet" => Network::Testnet,
            "regtest" => Network::Regtest,
            _ => return -1,
        }
    };

    let secp = Secp256k1::new();
    let priv_key =
        unsafe { PrivateKey::from_wif(CStr::from_ptr(priv_key).to_str().unwrap()).unwrap() };

    let public_key = PublicKey::from_private_key(&secp, &priv_key);
    let sha256_pub_key = sha256::Hash::hash(&public_key.to_bytes());
    let ripemd160_pub_key = ripemd160::Hash::hash(&decode(sha256_pub_key.to_hex()).unwrap());

    let btc_address = {
        let mut res = vec![];
        match network {
            Network::Bitcoin => res.push(0x00),
            _ => res.push(0x6F),
        }

        res.extend_from_slice(&decode(ripemd160_pub_key.to_hex()).unwrap());
        check_encode_slice(&res)
    };

    unsafe {
        *address = CString::new(btc_address).unwrap().into_raw();
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn btc_build_pay_to_pub_key_hash(
    address: *const c_char,
    script_pubkey: *mut *mut c_char,
) -> i32 {
    assert!(!address.is_null() && !script_pubkey.is_null());

    let address =
        unsafe { from_check(CStr::from_ptr(address).to_str().unwrap()).unwrap()[1..].to_vec() };

    let script = {
        let builder = Builder::new();
        builder
            .push_opcode(opcodes::all::OP_DUP)
            .push_opcode(opcodes::all::OP_HASH160)
            .push_slice(&address)
            .push_opcode(opcodes::all::OP_EQUALVERIFY)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script()
    };

    unsafe {
        *script_pubkey = CString::new(encode(&script.into_bytes()))
            .unwrap()
            .into_raw();
    }

    return 0;
}

#[cfg(test)]
mod test {
    use super::*;
    use hex::encode;
    use secp256k1::Message;
    use secp256k1::Secp256k1;
    use std::mem::MaybeUninit;
    use std::str::FromStr;

    use bitcoin::consensus::encode::serialize;
    use bitcoin::util::key::PrivateKey;

    #[test]
    fn test_btc_build_pay_to_pub_key_hash() {
        let address = CString::new("moDaczM8zMvxvM2GEQ5PC4o8S2iYhN1zZC")
            .unwrap()
            .into_raw();

        let script_pubkey = MaybeUninit::<*mut c_char>::uninit().as_mut_ptr();

        btc_build_pay_to_pub_key_hash(address, script_pubkey);

        unsafe {
            let script = CString::from_raw(*script_pubkey);
            println!("script: {:?}", script);
        }
    }

    #[test]
    fn test_btc_to_address() {
        let network = CString::new("testnet").unwrap().into_raw();
        let priv_key = CString::new("cRVuQd8qSuSRifRverDNAKmBGgDNDu55mV2gtyoBFT4gwHeuJFQ4")
            .unwrap()
            .into_raw();

        let address = MaybeUninit::<*mut c_char>::uninit().as_mut_ptr();

        btc_to_address(network, priv_key, address);

        unsafe {
            let address = CString::from_raw(*address);
            println!("address: {:?}", address);
        }
    }

    #[test]
    fn test_btc_build_raw_transaction_from_single_address() {
        let address = CString::new("moDaczM8zMvxvM2GEQ5PC4o8S2iYhN1zZC")
            .unwrap()
            .into_raw();
        let priv_key = CString::new("cRVuQd8qSuSRifRverDNAKmBGgDNDu55mV2gtyoBFT4gwHeuJFQ4")
            .unwrap()
            .into_raw();
        let input =
            CString::new("b59e6f24e6fcf4d8a396a8b9f92ccf83d242cc6ce3295ae024f8d58627f30cc5:0")
                .unwrap()
                .into_raw();
        let output = CString::new("76a91402245e1265ca65f5ab6d70289f7bcfed6204810588ac:1000000;76a9145477d7bfe9bdf17cea9f5b2ecacc7a2577723c7488ac:80233807").unwrap().into_raw();

        let tx_hash = MaybeUninit::<*mut c_char>::uninit().as_mut_ptr();
        let raw_tx = MaybeUninit::<*mut c_char>::uninit().as_mut_ptr();

        btc_build_raw_transaction_from_single_address(
            address, priv_key, input, output, raw_tx, tx_hash,
        );

        unsafe {
            let tx_hash = CStr::from_ptr(*tx_hash);
            let raw_tx = CStr::from_ptr(*raw_tx);

            println!("tx hash: {:?}", tx_hash);
            println!("raw tx: {:?}", raw_tx);
        }
    }

    #[test]
    fn test_btc_from_seed() {
        let seed = CString::new("780a5414809924cbbd4ad4e7fa41d5bfc70d465e2aa74b131abb06775b8f2fea1143fb88e3b724b26f89eed22b457b83730b63d186e5b437c98a09a45658aa07").unwrap().into_raw();
        let network = CString::new("testnet").unwrap().into_raw();
        let language = CString::new("english").unwrap().into_raw();

        let root_xpriv = MaybeUninit::<*mut c_char>::uninit().as_mut_ptr();

        btc_from_seed(seed, network, language, root_xpriv);

        unsafe {
            let root_xpriv = CString::from_raw(*root_xpriv);
            println!("root xpriv: {:?}", root_xpriv);
        }
    }

    #[test]
    fn test_btc_private_key_of() {
        let index = 0;
        let priv_key = MaybeUninit::<*mut c_char>::uninit().as_mut_ptr();
        let root_xpriv = CString::new("tprv8ZgxMBicQKsPeHCMLEwizg7ohLfdw9bvs5iPHBmvrQxvAEsaXb8S8oEMZWLbCKjvDAYJXeWp4SuXfMs8PiGawwZsM9sxyKQV6APtrJTKJwV").unwrap().into_raw();

        btc_private_key_of(index, root_xpriv, priv_key);
        unsafe {
            let priv_key = CString::from_raw(*priv_key);
            println!("priv_key: {:?}", priv_key);
        }
    }

    #[test]
    fn test_btc_from_mnemonic() {
        let network = CString::new("testnet").unwrap().into_raw();
        let lanuage = CString::new("english").unwrap().into_raw();
        let pass_phrase = CString::new("").unwrap().into_raw();
        let mnemonic = CString::new(
            "drum credit sport athlete mixed busy winter humor turtle auto snack abstract",
        )
        .unwrap()
        .into_raw();

        let root_xpriv = MaybeUninit::<*mut c_char>::uninit().as_mut_ptr();
        let root_seed = MaybeUninit::<*mut c_char>::uninit().as_mut_ptr();

        btc_from_mnemonic(
            mnemonic,
            network,
            lanuage,
            pass_phrase,
            root_xpriv,
            root_seed,
        );

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

        btc_generate(
            strength,
            network,
            lanuage,
            pass_phrase,
            root_xpriv,
            mnemonic,
        );

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
            input: vec![
                TxIn {
                    previous_output: OutPoint::from_str(
                        "964b06c7d65bc2966ffc089be06469cf3961fdae4253cb51fe158bf1696882a1:1",
                    )
                    .unwrap(),
                    script_sig: Script::new(),
                    sequence: 0,
                    witness: vec![],
                },
                TxIn {
                    previous_output: OutPoint::from_str(
                        "6c1fd83338c12326e9160d57a95198937a228b6c4f55e882792be19fe2038da5:1",
                    )
                    .unwrap(),
                    script_sig: Script::new(),
                    sequence: 0,
                    witness: vec![],
                },
            ],
            output: vec![
                TxOut {
                    value: 81243807,
                    script_pubkey: Script::from(
                        decode("76a9145477d7bfe9bdf17cea9f5b2ecacc7a2577723c7488ac").unwrap(),
                    ),
                },
                TxOut {
                    value: 100000,
                    script_pubkey: Script::from(
                        decode("76a91402245e1265ca65f5ab6d70289f7bcfed6204810588ac").unwrap(),
                    ),
                },
            ],
        };

        let sig_hash = raw_tx.signature_hash(
            0,
            &Script::from(decode("76a9145477d7bfe9bdf17cea9f5b2ecacc7a2577723c7488ac").unwrap()),
            1,
        );

        let secp = Secp256k1::new();
        let msg = Message::from_slice(&sig_hash.into_inner()).unwrap();
        let sk =
            PrivateKey::from_wif("cRVuQd8qSuSRifRverDNAKmBGgDNDu55mV2gtyoBFT4gwHeuJFQ4").unwrap();
        let pk = sk.public_key(&secp);
        println!(
            "pk: {:?}, len: {:?}",
            pk.to_string(),
            pk.to_string().len() / 2
        );
        let mut sig = secp.sign(&msg, &sk.key).serialize_der();
        sig.push(1);

        println!("sig: {:?}", encode(&sig));

        let b1 = Builder::new();
        let bb1 = b1.push_slice(&sig).push_key(&pk);

        // println!("bb1: {:?}", bb1.into_script().asm());

        raw_tx.input[0].script_sig = bb1.into_script();

        let sig_hash2 = raw_tx.signature_hash(
            1,
            &Script::from(decode("76a9145477d7bfe9bdf17cea9f5b2ecacc7a2577723c7488ac").unwrap()),
            1,
        );
        let msg2 = Message::from_slice(&sig_hash2.into_inner()).unwrap();
        let mut sig2 = secp.sign(&msg2, &sk.key).serialize_der();
        sig2.push(1);

        println!("sig2: {:?}", encode(&sig2));

        let b2 = Builder::new();
        let bb2 = b2.push_slice(&sig2).push_key(&pk);

        // println!("bb2: {:?}", bb2.into_script().asm());

        raw_tx.input[1].script_sig = bb2.into_script();

        // let serialized = raw_tx.serialize();
        let serialized = serialize(&raw_tx);

        println!("serialized: {:?}", encode(serialized));
        println!("txHash: {:?}", raw_tx.txid());
    }
}
