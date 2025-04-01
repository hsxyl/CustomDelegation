use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, HashMap};

use candid::{CandidType, Deserialize, Principal};
use ic_cdk::{call, caller, trap};
use ic_cdk::api::time;
use ic_certified_map::{Hash, RbTree};
use ic_stable_structures::DefaultMemoryImpl;

use crate::deps::http::HeaderField;
use crate::deps::signature_map::SignatureMap;
use crate::storage::{DEFAULT_RANGE_SIZE, Salt, Storage};
use crate::types::{Timestamp, UserNumber};

pub type Assets = HashMap<&'static str, (Vec<HeaderField>, &'static [u8])>;
pub type AssetHashes = RbTree<&'static str, Hash>;

thread_local! {
    static STATE: State = State::default();
    static ASSETS: RefCell<Assets> = RefCell::new(HashMap::default());
}

#[derive(Default)]
pub struct UsageMetrics {
    // number of prepare_delegation calls since last upgrade
    pub delegation_counter: u64,
}

#[derive(Clone, Default, CandidType, Deserialize, Eq, PartialEq, Debug)]
pub struct PersistentState {
    // Information related to the archive
    // Amount of cycles that need to be attached when II creates a canister
    pub canister_creation_cycles_cost: u64,
}

struct State {
    storage: RefCell<Storage<DefaultMemoryImpl>>,
    sigs: RefCell<SignatureMap>,
    asset_hashes: RefCell<AssetHashes>,
    last_upgrade_timestamp: Cell<Timestamp>,
    // additional usage metrics, NOT persisted across updates (but probably should be in the future)
    usage_metrics: RefCell<UsageMetrics>,
    // State that is temporarily persisted in stable memory during upgrades using
    // pre- and post-upgrade hooks.
    // This must remain small as it is serialized and deserialized on pre- and post-upgrade.
    // Be careful when making changes here, as II needs to be able to update and roll back.
    persistent_state: RefCell<PersistentState>,
    // Cache of the archive status (to make unwanted calls to deploy_archive cheap to dismiss).
    admins: RefCell<BTreeSet<Principal>>,
    authed_public_key: RefCell<BTreeMap<String, Vec<u8>>>,
}

impl Default for State {
    fn default() -> Self {
        const FIRST_USER_ID: UserNumber = 10_000;
        Self {
            storage: RefCell::new(Storage::new(
                (
                    FIRST_USER_ID,
                    FIRST_USER_ID.saturating_add(DEFAULT_RANGE_SIZE),
                ),
                DefaultMemoryImpl::default(),
            )),
            sigs: RefCell::new(SignatureMap::default()),
            asset_hashes: RefCell::new(AssetHashes::default()),
            last_upgrade_timestamp: Cell::new(0),
            usage_metrics: RefCell::new(UsageMetrics::default()),
            persistent_state: RefCell::new(PersistentState::default()),
            admins: RefCell::new(BTreeSet::from_iter(vec![Principal::from_text(
                "k3yy7-nod3f-b2bia-scivs-bct6f-c2pgd-eyfdp-edaux-saxj4-i663m-bqe",
            )
            .unwrap()])),
            authed_public_key: RefCell::new(BTreeMap::new()),
        }
    }
}

// Checks if salt is empty and calls `init_salt` to set it.
pub async fn ensure_salt_set() {
    let salt = STATE.with(|s| s.storage.borrow().salt().cloned());
    if salt.is_none() {
        init_salt().await;
    }

    STATE.with(|s| {
        if s.storage.borrow().salt().is_none() {
            trap("Salt is not set. Try calling init_salt() to set it");
        }
    });
}

pub async fn init_salt() {
    STATE.with(|s| {
        if s.storage.borrow().salt().is_some() {
            trap("Salt already set");
        }
    });

    let res: Vec<u8> = match call(Principal::management_canister(), "raw_rand", ()).await {
        Ok((res,)) => res,
        Err((_, err)) => trap(&format!("failed to get salt: {}", err)),
    };
    let salt: Salt = res[..].try_into().unwrap_or_else(|_| {
        trap(&format!(
            "expected raw randomness to be of length 32, got {}",
            res.len()
        ));
    });

    STATE.with(|s| {
        let mut store = s.storage.borrow_mut();
        store.update_salt(salt); // update_salt() traps if salt has already been set
    });
}

pub fn auth_address(address: String, seed: Vec<u8>) {
    STATE.with(|s| {
        let mut map = s.authed_public_key.borrow_mut();
        let _ = map.insert(address, seed);
    })
}

pub fn check_if_public_key_authed(public_key: String) -> Option<Vec<u8>> {
    STATE.with(|s| {
        let map = s.authed_public_key.borrow();
        let res = map.get(public_key.as_str()).and_then(|v| Some(v.clone()));
        res
    })
}

pub fn salt() -> [u8; 32] {
    STATE
        .with(|s| s.storage.borrow().salt().cloned())
        .unwrap_or_else(|| trap("Salt is not set. Try calling init_salt() to set it"))
}

pub fn set_salt(salt: [u8; 32]) {
    STATE.with(|s| {
        let mut store = s.storage.borrow_mut();
        store.update_salt(salt);
    })
}

pub fn initialize_from_stable_memory() {
    STATE.with(|s| {
        s.last_upgrade_timestamp.set(time() as u64);
        match Storage::from_memory(DefaultMemoryImpl::default()) {
            Some(storage) => {
                s.storage.replace(storage);
            }
            None => {
                s.storage.borrow_mut().flush();
            }
        }
    });
}

pub fn save_persistent_state() {
    STATE.with(|s| {
        s.storage
            .borrow_mut()
            .write_persistent_state(&s.persistent_state.borrow());
    })
}

pub fn load_persistent_state() {
    STATE.with(|s| {
        let storage = s.storage.borrow();
        match storage.read_persistent_state() {
            Ok(loaded_state) => *s.persistent_state.borrow_mut() = loaded_state,
            Err(err) => trap(&format!(
                "failed to recover persistent state! Err: {:?}",
                err
            )),
        }
    })
}

pub fn is_admin() -> bool {
    STATE.with(|s| {
        let admins = s.admins.borrow();
        admins.contains(&caller())
    })
}

pub fn assets<R>(f: impl FnOnce(&Assets) -> R) -> R {
    ASSETS.with(|assets| f(&*assets.borrow()))
}

pub fn assets_and_hashes_mut<R>(f: impl FnOnce(&mut Assets, &mut AssetHashes) -> R) -> R {
    ASSETS.with(|assets| {
        STATE.with(|s| f(&mut *assets.borrow_mut(), &mut *s.asset_hashes.borrow_mut()))
    })
}

pub fn asset_hashes_and_sigs<R>(f: impl FnOnce(&AssetHashes, &SignatureMap) -> R) -> R {
    STATE.with(|s| f(&*s.asset_hashes.borrow(), &*s.sigs.borrow()))
}

pub fn signature_map<R>(f: impl FnOnce(&SignatureMap) -> R) -> R {
    STATE.with(|s| f(&*s.sigs.borrow()))
}

pub fn signature_map_mut<R>(f: impl FnOnce(&mut SignatureMap) -> R) -> R {
    STATE.with(|s| f(&mut *s.sigs.borrow_mut()))
}

pub fn storage<R>(f: impl FnOnce(&Storage<DefaultMemoryImpl>) -> R) -> R {
    STATE.with(|s| f(&*s.storage.borrow()))
}

pub fn storage_mut<R>(f: impl FnOnce(&mut Storage<DefaultMemoryImpl>) -> R) -> R {
    STATE.with(|s| f(&mut *s.storage.borrow_mut()))
}

pub fn usage_metrics<R>(f: impl FnOnce(&UsageMetrics) -> R) -> R {
    STATE.with(|s| f(&*s.usage_metrics.borrow()))
}

pub fn usage_metrics_mut<R>(f: impl FnOnce(&mut UsageMetrics) -> R) -> R {
    STATE.with(|s| f(&mut *s.usage_metrics.borrow_mut()))
}

pub fn last_upgrade_timestamp() -> Timestamp {
    STATE.with(|s| s.last_upgrade_timestamp.get())
}

pub fn persistent_state<R>(f: impl FnOnce(&PersistentState) -> R) -> R {
    STATE.with(|s| f(&*s.persistent_state.borrow()))
}

pub fn persistent_state_mut<R>(f: impl FnOnce(&mut PersistentState) -> R) -> R {
    STATE.with(|s| f(&mut *s.persistent_state.borrow_mut()))
}
