use bip322::verify_simple_encoded;
use candid::{candid_method, CandidType, Principal};
use delegation::der_encode_canister_sig_key;
use ic_cdk::{call, caller, query, trap, update};
use ic_cdk_macros::init;
use ic_certified_map::{AsHashTree, Hash};
use serde::Deserialize;
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};

use types::{GetDelegationResponse, SessionKey, SignedDelegation, Timestamp, UserKey};

use crate::delegation::update_root_hash;

mod delegation;
mod deps;
mod state;
mod storage;
mod types;

#[derive(CandidType, Deserialize)]
enum CustomSignature {
    // MetaMask(String, String, String), // account: String, message: String, signature: String
    Bip322(String, String, String), // address: String, message: String, signature: String
}

impl CustomSignature {
    // pub fn verify_message_and_gen_session_key(&self) {
    //     match self {
    //         CustomSignature::MetaMask(address, message, signature) => todo!(),
    //         CustomSignature::Bip322(address, message, signature) => todo!(),
    //     }
    // }

    pub fn get_address(&self) -> String {
        match self {
            CustomSignature::Bip322(address, _, _) => address.clone(),
        }
    }

    pub fn verify_message(&self) -> Result<String, String> {
        match self {
            CustomSignature::Bip322(address, message, signature) => {
                verify_simple_encoded(address, message, signature)
                    .map_err(|e| format!("Failed to verify signature: {:?}", e))?;

                Ok(message.clone())
            }
        }
    }
}

#[test]
pub fn test_bip322() {
    let r = verify_simple_encoded(
        "tb1q55gghpce6jgq8q78cfcnmkz8qq5ww3as8vn5ka", 
        "302a300506032b657003210082ca3c0e9da4922ac5b5573c70f6a9c510b4abe803b70417be4bedb70a0516e1", 
        "AkcwRAIgETJvfXNUVLWV7QlJ4ei6L+BSbJpRFRYGNYEqzDjvLUwCIDTZhAnJOevQZYK/ILTbMYYOUO14RrrIdKze4//xnqUxASECObrNci7VdNiGNvjXAPJ3nKQr6W9owgtPGEXahzXWSMA="
    );

    dbg!(&r);
}

const fn secs_to_nanos(secs: u64) -> u64 {
    secs * 1_000_000_000
}

const LABEL_ASSETS: &[u8] = b"http_assets";
const LABEL_SIG: &[u8] = b"sig";
// const METAMASK_CID: &str = "sp7ew-3yaaa-aaaak-qbtua-cai";

#[query]
async fn get_principal(address: String) -> Principal {
    let mut hasher = Sha256::new();
    hasher.update(address);
    let result = hasher.finalize().to_vec();
    let seed: [u8; 32] = result.try_into().expect("Failed to convert to [u8; 32]");
    let user_key = ByteBuf::from(der_encode_canister_sig_key(seed.to_vec()));

    let principal = Principal::self_authenticating(&user_key);

    principal
}

#[update]
#[candid_method]
async fn prepare_delegation(
    max_time_to_live: Option<u64>,
    sig: CustomSignature,
) -> Result<(UserKey, Timestamp), String> {
    // let mut seed = [0x00u8; 32];
    // let mut session_key = vec![];

    let key_message = sig.verify_message()?;

    let session_key: Vec<u8> = hex::decode(key_message)
        .map_err(|e| format!("Failed to decode key message: {:?}", e))?
        .try_into()
        .map_err(|_| "Failed to convert to [u8]")?;
    let caller_principal = caller();
    let session_key_principal = Principal::self_authenticating(&session_key);
    if caller_principal.ne(&session_key_principal)  {
        // return Err("Invalid Session Key".to_string());
        return Err(format!("Invalid Session Key: {:?} != {:?}", caller_principal.to_text(), session_key_principal.to_text()));
    }

    let seed = address_to_seed(&sig.get_address());

    Ok(
        delegation::prepare_delegation(seed.clone(), ByteBuf::from(session_key), max_time_to_live)
            .await,
    )
}

#[test]
pub fn test_seed() {
    let address = "tb1q55gghpce6jgq8q78cfcnmkz8qq5ww3as8vn5ka";
    let mut hasher = Sha256::new();
    hasher.update(address);
    // You should add a salt value here that is not known to third parties
    // otherwise the identity generated from this canister will have security vulnerabilities.
    // hasher.update([salt value]);
    let result = hasher.finalize().to_vec();
    let seed: [u8; 32] = result
        .try_into()
        .map_err(|_| "Failed to convert to [u8; 32]")
        .unwrap();

    dbg!(&seed);
}

#[candid_method]
#[query]
fn get_delegation(
    address: String,
    session_key: SessionKey,
    expiration: Timestamp,
) -> Result<SignedDelegation, String> {
    // self auth
    if caller() != Principal::self_authenticating(&session_key) {
        // trap("Invalid Session Key")
        return Err("Invalid Session Key".to_string());
    }
    delegation::get_delegation(address_to_seed(&address), session_key, expiration)
}

fn address_to_seed(address: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(address);
    let result = hasher.finalize().to_vec();
    result
        .try_into()
        .map_err(|_| "Failed to convert to [u8; 32]")
        .unwrap()
}

#[query]
fn whoami() -> Principal {
    caller()
}

#[test]
pub fn test_ss() {
    // test prepare delegation session key
    let sig = CustomSignature::Bip322(
        "tb1q55gghpce6jgq8q78cfcnmkz8qq5ww3as8vn5ka".to_string(), 
        "302a300506032b6570032100378305b183359fa11bab1fc19f052ddf970994e4f6da7c55264a55161ad64ed2".to_string(), 
        "AkgwRQIhAOJ5XoGOdazwuyAQe8VsXhBoLzXhXPFeTvqfIz3OxX7rAiBJS+Adl50iez4SmAxE1aWGIMhEoIcMIwWRXlb2HwXC7QEhAjm6zXIu1XTYhjb41wDyd5ykK+lvaMILTxhF2oc11kjA".to_string()
    );

    let key_message = sig.verify_message().unwrap();
    let session_key: Vec<u8> = hex::decode(key_message)
        .map_err(|e| format!("Failed to decode key message: {:?}", e))
        .unwrap()
        .try_into()
        .map_err(|_| "Failed to convert to [u8]")
        .unwrap();
    dbg!(&session_key);
    let p = Principal::self_authenticating(&session_key);

    dbg!(&p.to_text());

    let session_key: SessionKey = vec![
        48, 60, 48, 12, 6, 10, 43, 6, 1, 4, 1, 131, 184, 67, 1, 2, 3, 44, 0, 10, 128, 0, 0, 0, 0,
        16, 0, 5, 1, 1, 114, 162, 131, 169, 220, 95, 214, 232, 59, 69, 24, 188, 32, 184, 137, 181,
        70, 12, 178, 32, 107, 56, 160, 242, 51, 112, 221, 42, 80, 14, 64, 244,
    ]
    .into();
    let p = Principal::self_authenticating(&session_key);

    dbg!(&p.to_text());
}

#[test]
pub fn test_hex_encode() {
    let v = vec![
        48, 60, 48, 12, 6, 10, 43, 6, 1, 4, 1, 131, 184, 67, 1, 2, 3, 44, 0, 10, 128, 0, 0, 0, 0,
        16, 0, 5, 1, 1, 95, 64, 73, 22, 50, 86, 169, 149, 109, 121, 110, 245, 148, 105, 134, 225,
        175, 178, 102, 189, 208, 120, 234, 133, 213, 145, 177, 92, 138, 86, 116, 153,
    ];
    let s = hex::encode(v);
    dbg!(&s);
}

#[test]
pub fn test_session_key_to_principal() {
    let session_key: SessionKey = vec![
        48, 60, 48, 12, 6, 10, 43, 6, 1, 4, 1, 131, 184, 67, 1, 2, 3, 44, 0, 10, 128, 0, 0, 0, 0,
        16, 0, 5, 1, 1, 114, 162, 131, 169, 220, 95, 214, 232, 59, 69, 24, 188, 32, 184, 137, 181,
        70, 12, 178, 32, 107, 56, 160, 242, 51, 112, 221, 42, 80, 14, 64, 244,
    ]
    .into();
    let p = Principal::self_authenticating(&session_key);

    dbg!(&p.to_text());
}
//                                       0a800000000010000501015f4049163256a9956d796ef5946986e1afb266bdd078ea85d591b15c8a567499
// 303c300c060a2b0601040183b8430102032c000a800000000010000501015f4049163256a9956d796ef5946986e1afb266bdd078ea85d591b15c8a567499
#[init]
fn init() {
    update_root_hash();
}

// Enable Candid export
ic_cdk::export_candid!();
