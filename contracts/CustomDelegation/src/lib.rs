use candid::{candid_method, CandidType, Principal};
use ic_cdk::{call, caller, query, trap, update};
use ic_cdk_macros::init;
use ic_certified_map::{AsHashTree, Hash};
use serde::Deserialize;
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};

use types::{GetDelegationResponse, SessionKey, Timestamp, UserKey};

use crate::delegation::update_root_hash;

mod delegation;
mod deps;
mod state;
mod storage;
mod types;

#[derive(CandidType, Deserialize)]
enum CustomSignature {
    MetaMask(String, String, String), // account: String, message: String, signature: String
}

const fn secs_to_nanos(secs: u64) -> u64 {
    secs * 1_000_000_000
}

const LABEL_ASSETS: &[u8] = b"http_assets";
const LABEL_SIG: &[u8] = b"sig";
const METAMASK_CID: &str = "sp7ew-3yaaa-aaaak-qbtua-cai";

#[update]
#[candid_method]
async fn prepare_delegation(
    max_time_to_live: Option<u64>,
    sig: CustomSignature,
) -> (UserKey, Timestamp) {
    let mut seed = [0x00u8; 32];
    let mut session_key = vec![];

    match sig {
        CustomSignature::MetaMask(address, key, sig) => {
            let res: Result<(bool,), _> = call(
                Principal::from_text(METAMASK_CID).unwrap(),
                "verify_metamask_personal_sign",
                (address.clone(), key.clone(), sig.clone()),
            )
            .await;
            if !res.unwrap().0 {
                trap("Failed to verify signature")
            }
            session_key = hex::decode(key).unwrap().try_into().unwrap();
            if caller() != Principal::self_authenticating(session_key.clone()) {
                trap("Invalid Session Key")
            }
            let mut hasher = Sha256::new();
            hasher.update(hex::decode(address).unwrap());
            // You should add a salt value here that is not known to third parties
            // otherwise the identity generated from this canister will have security vulnerabilities.
            // hasher.update([salt value]);
            let result = hasher.finalize().to_vec();
            seed = result.try_into().unwrap();
        }
    }

    delegation::prepare_delegation(seed.clone(), ByteBuf::from(session_key), max_time_to_live).await
}

#[query]
#[candid_method]
fn get_delegation(
    seed: Hash,
    session_key: SessionKey,
    expiration: Timestamp,
) -> GetDelegationResponse {
    // self auth
    if caller() != Principal::self_authenticating(&session_key) {
        trap("Invalid Session Key")
    }
    delegation::get_delegation(seed.try_into().unwrap(), session_key, expiration)
}

#[init]
fn init() {
    update_root_hash();
}
