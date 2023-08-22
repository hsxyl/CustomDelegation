use crate::state::{init_salt, is_admin, salt};
use candid::{candid_method, CandidType, Principal};
use http::{HttpRequest, HttpResponse};
use ic_cdk::api::set_certified_data;
use ic_cdk::{call, caller, id, init, query, trap, update};
use ic_certified_map::{AsHashTree, Hash};
use serde::Deserialize;
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use types::{GetDelegationResponse, SessionKey, Timestamp, UserKey};

mod delegation;
mod hash;
mod http;
mod signature_map;
mod state;
mod storage;

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

#[query]
#[candid_method(query)]
fn http_request(req: HttpRequest) -> HttpResponse {
    http::http_request(req)
}

#[update]
#[candid_method(update)]
async fn http_request_update(req: HttpRequest) -> HttpResponse {
    let parts: Vec<&str> = req.url.split('?').collect();
    match parts[0] {
        "/prepare" => {
            let elems: HashMap<_, _> = req.headers.into_iter().collect();
            let account = elems.get("Account").unwrap();
            let msg = elems.get("Message").unwrap();
            let sig = elems.get("Signature").unwrap();

            let custom_sig =
                CustomSignature::MetaMask(account.to_string(), msg.to_string(), sig.to_string());
            let delegation_response = prepare_delegation(None, custom_sig).await;
            let body = candid::encode_one(delegation_response).unwrap();

            HttpResponse {
                status_code: 200,
                headers: vec![(
                    "Content-Type".to_string(),
                    "text/plain; version=0.0.4".to_string(),
                )],
                body: ByteBuf::from(body),
                upgrade: Some(true),
                streaming_strategy: None,
            }
        }
        _ => {
            let mut headers = vec![(
                "Content-Type".to_string(),
                "text/plain; version=0.0.4".to_string(),
            )];
            HttpResponse {
                status_code: 200,
                headers,
                body: ByteBuf::from(format!("Invalid Request")),
                upgrade: Some(true),
                streaming_strategy: None,
            }
        }
    }
}

#[init]
fn init() {
    update_root_hash();
}

fn update_root_hash() {
    use ic_certified_map::{fork_hash, labeled_hash};
    state::asset_hashes_and_sigs(|asset_hashes, sigs| {
        let prefixed_root_hash = fork_hash(
            // NB: Labels added in lexicographic order
            &labeled_hash(LABEL_ASSETS, &asset_hashes.root_hash()),
            &labeled_hash(LABEL_SIG, &sigs.root_hash()),
        );
        set_certified_data(&prefixed_root_hash[..]);
    })
}
