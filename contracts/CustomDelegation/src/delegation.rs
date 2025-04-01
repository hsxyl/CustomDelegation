use std::collections::HashMap;
use std::io::Read;

use candid::Principal;
use ic_cdk::{id, trap};
use ic_cdk::api::{data_certificate, set_certified_data, time};
use ic_certified_map::{Hash, HashTree};
use ic_certified_map::AsHashTree;
use serde::Serialize;
use serde_bytes::ByteBuf;

use crate::{LABEL_ASSETS, LABEL_SIG, secs_to_nanos, state};
use crate::deps::hash;
use crate::deps::signature_map::SignatureMap;
use crate::state::AssetHashes;
use crate::types::{
    Delegation, FrontendHostname, GetDelegationResponse, PublicKey, SessionKey, SignedDelegation,
    Timestamp, UserKey, UserNumber,
};

// 30 mins
const DEFAULT_EXPIRATION_PERIOD_NS: u64 = secs_to_nanos(30 * 60);
// 30 days
const MAX_EXPIRATION_PERIOD_NS: u64 = secs_to_nanos(30 * 24 * 60 * 60);

// 1 min
const DEFAULT_SIGNATURE_EXPIRATION_PERIOD_NS: u64 = secs_to_nanos(60);

pub async fn prepare_delegation(
    seed: Hash, // public key sha256 hash
    session_key: SessionKey,
    max_time_to_live: Option<u64>,
) -> (UserKey, Timestamp) {
    // must be called before the first await because it requires caller()

    prune_expired_signatures();

    let delta = u64::min(
        max_time_to_live.unwrap_or(DEFAULT_EXPIRATION_PERIOD_NS),
        MAX_EXPIRATION_PERIOD_NS,
    );
    let expiration = (time() as u64).saturating_add(delta);

    state::signature_map_mut(|sigs| {
        add_signature(sigs, session_key, seed, expiration);
    });
    update_root_hash();
    state::usage_metrics_mut(|metrics| {
        metrics.delegation_counter += 1;
    });
    (
        ByteBuf::from(der_encode_canister_sig_key(seed.to_vec())),
        expiration,
    )
}

pub fn get_delegation(
    seed: Hash,
    session_key: SessionKey,
    expiration: Timestamp,
) -> Result<SignedDelegation, String>{
    state::asset_hashes_and_sigs(|asset_hashes, sigs| {
        let signature =  get_signature(asset_hashes, sigs, session_key.clone(), seed, expiration)?;
        let signature_delegation = SignedDelegation {
            delegation: Delegation {
                pubkey: session_key,
                expiration,
                targets: None,
            },
            signature: ByteBuf::from(signature),
        };

        Ok(signature_delegation)
    })
}

pub fn get_principal(user_number: UserNumber, frontend: FrontendHostname) -> Principal {
    let seed = calculate_seed(user_number, &frontend);
    let public_key = der_encode_canister_sig_key(seed.to_vec());
    Principal::self_authenticating(&public_key)
}

pub fn update_root_hash() {
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

fn calculate_seed(user_number: UserNumber, frontend: &FrontendHostname) -> Hash {
    let salt = state::salt();

    let mut blob: Vec<u8> = vec![];
    blob.push(salt.len() as u8);
    blob.extend_from_slice(&salt);

    let user_number_str = user_number.to_string();
    let user_number_blob = user_number_str.bytes();
    blob.push(user_number_blob.len() as u8);
    blob.extend(user_number_blob);

    blob.push(frontend.bytes().len() as u8);
    blob.extend(frontend.bytes());

    hash::hash_bytes(blob)
}

pub fn der_encode_canister_sig_key(seed: Vec<u8>) -> Vec<u8> {
    let my_canister_id: Vec<u8> = id().as_ref().to_vec();
    let mut bitstring: Vec<u8> = vec![];
    bitstring.push(my_canister_id.len() as u8);
    bitstring.extend(my_canister_id);
    bitstring.extend(seed);

    let mut der: Vec<u8> = vec![];
    // sequence of length 17 + the bit string length
    der.push(0x30);
    der.push(17 + bitstring.len() as u8);
    der.extend(vec![
        // sequence of length 12 for the OID
        0x30, 0x0C, // OID 1.3.6.1.4.1.56387.1.2
        0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xB8, 0x43, 0x01, 0x02,
    ]);
    // BIT string of given length
    der.push(0x03);
    der.push(1 + bitstring.len() as u8);
    der.push(0x00);
    der.extend(bitstring);
    der
}

fn delegation_signature_msg_hash(d: &Delegation) -> Hash {
    use hash::Value;

    let mut m = HashMap::new();
    m.insert("pubkey", Value::Bytes(d.pubkey.as_slice()));
    m.insert("expiration", Value::U64(d.expiration));
    if let Some(targets) = d.targets.as_ref() {
        let mut arr = Vec::with_capacity(targets.len());
        for t in targets.iter() {
            arr.push(Value::Bytes(t.as_ref()));
        }
        m.insert("targets", Value::Array(arr));
    }
    let map_hash = hash::hash_of_map(m);
    hash::hash_with_domain(b"ic-request-auth-delegation", &map_hash)
}

fn get_signature(
    asset_hashes: &AssetHashes,
    sigs: &SignatureMap,
    pk: PublicKey,
    seed: Hash,
    expiration: Timestamp,
) -> Result<Vec<u8>, String> {
    let certificate = data_certificate().ok_or(
        "data certificate is only available in query calls".to_string(),
    )?;
    // let certificate = data_certificate().unwrap_or_else(|| {
    //     // trap("data certificate is only available in query calls");
    //     return std::result::Result::Err("data certificate is only available in query calls".to_string());
    // });
    let msg_hash = delegation_signature_msg_hash(&Delegation {
        pubkey: pk,
        expiration,
        targets: None,
    });
    let witness = sigs.witness(hash::hash_bytes(seed), msg_hash).ok_or(
        "signature not found".to_string(),
    )?;

    let witness_hash = witness.reconstruct();
    let root_hash = sigs.root_hash();
    if witness_hash != root_hash {
        trap(&format!(
            "internal error: signature map computed an invalid hash tree, witness hash is {}, root hash is {}",
            hex::encode(&witness_hash),
            hex::encode(&root_hash)
        ));
    }

    let tree = ic_certified_map::fork(
        HashTree::Pruned(ic_certified_map::labeled_hash(
            LABEL_ASSETS,
            &asset_hashes.root_hash(),
        )),
        ic_certified_map::labeled(&LABEL_SIG[..], witness),
    );

    #[derive(Serialize)]
    struct Sig<'a> {
        certificate: ByteBuf,
        tree: HashTree<'a>,
    }

    let sig = Sig {
        certificate: ByteBuf::from(certificate),
        tree,
    };

    let mut cbor = serde_cbor::ser::Serializer::new(Vec::new());
    cbor.self_describe().map_err(
        |e| format!("failed to serialize CBOR: {}", e),
    )?;
    sig.serialize(&mut cbor).map_err(
        |e| format!("failed to serialize CBOR: {}", e),
    )?;
    Ok(cbor.into_inner())
}

fn add_signature(sigs: &mut SignatureMap, pk: PublicKey, seed: Hash, expiration: Timestamp) {
    let msg_hash = delegation_signature_msg_hash(&Delegation {
        pubkey: pk,
        expiration,
        targets: None,
    });
    let expires_at = (time() as u64).saturating_add(DEFAULT_SIGNATURE_EXPIRATION_PERIOD_NS);
    sigs.put(hash::hash_bytes(seed), msg_hash, expires_at);
}

/// Removes a batch of expired signatures from the signature map.
///
/// This function is supposed to piggy back on update calls to
/// amortize the cost of tree pruning.  Each operation on the signature map
/// will prune at most MAX_SIGS_TO_PRUNE other signatures.
pub fn prune_expired_signatures() {
    const MAX_SIGS_TO_PRUNE: usize = 10;
    let num_pruned =
        state::signature_map_mut(|sigs| sigs.prune_expired(time() as u64, MAX_SIGS_TO_PRUNE));
    if num_pruned > 0 {
        update_root_hash();
    }
}


#[test]
pub fn test_hex() {
    let raw_str = r#"
    {
        "0": 217,
        "1": 217,
        "2": 247,
        "3": 162,
        "4": 107,
        "5": 99,
        "6": 101,
        "7": 114,
        "8": 116,
        "9": 105,
        "10": 102,
        "11": 105,
        "12": 99,
        "13": 97,
        "14": 116,
        "15": 101,
        "16": 89,
        "17": 1,
        "18": 215,
        "19": 217,
        "20": 217,
        "21": 247,
        "22": 162,
        "23": 100,
        "24": 116,
        "25": 114,
        "26": 101,
        "27": 101,
        "28": 131,
        "29": 1,
        "30": 131,
        "31": 1,
        "32": 131,
        "33": 1,
        "34": 130,
        "35": 4,
        "36": 88,
        "37": 32,
        "38": 38,
        "39": 125,
        "40": 16,
        "41": 139,
        "42": 130,
        "43": 81,
        "44": 73,
        "45": 200,
        "46": 137,
        "47": 34,
        "48": 127,
        "49": 34,
        "50": 12,
        "51": 162,
        "52": 1,
        "53": 19,
        "54": 140,
        "55": 230,
        "56": 33,
        "57": 195,
        "58": 28,
        "59": 124,
        "60": 60,
        "61": 241,
        "62": 116,
        "63": 17,
        "64": 126,
        "65": 112,
        "66": 21,
        "67": 17,
        "68": 11,
        "69": 183,
        "70": 131,
        "71": 2,
        "72": 72,
        "73": 99,
        "74": 97,
        "75": 110,
        "76": 105,
        "77": 115,
        "78": 116,
        "79": 101,
        "80": 114,
        "81": 131,
        "82": 1,
        "83": 130,
        "84": 4,
        "85": 88,
        "86": 32,
        "87": 42,
        "88": 18,
        "89": 156,
        "90": 41,
        "91": 223,
        "92": 63,
        "93": 73,
        "94": 49,
        "95": 111,
        "96": 55,
        "97": 126,
        "98": 161,
        "99": 166,
        "100": 23,
        "101": 231,
        "102": 255,
        "103": 200,
        "104": 244,
        "105": 201,
        "106": 124,
        "107": 195,
        "108": 117,
        "109": 239,
        "110": 167,
        "111": 32,
        "112": 194,
        "113": 167,
        "114": 59,
        "115": 43,
        "116": 80,
        "117": 194,
        "118": 10,
        "119": 131,
        "120": 1,
        "121": 131,
        "122": 1,
        "123": 130,
        "124": 4,
        "125": 88,
        "126": 32,
        "127": 129,
        "128": 146,
        "129": 243,
        "130": 251,
        "131": 168,
        "132": 43,
        "133": 3,
        "134": 50,
        "135": 116,
        "136": 103,
        "137": 157,
        "138": 73,
        "139": 56,
        "140": 242,
        "141": 216,
        "142": 155,
        "143": 211,
        "144": 245,
        "145": 64,
        "146": 188,
        "147": 97,
        "148": 184,
        "149": 186,
        "150": 145,
        "151": 72,
        "152": 174,
        "153": 59,
        "154": 166,
        "155": 226,
        "156": 90,
        "157": 248,
        "158": 218,
        "159": 131,
        "160": 2,
        "161": 74,
        "162": 128,
        "163": 0,
        "164": 0,
        "165": 0,
        "166": 0,
        "167": 16,
        "168": 0,
        "169": 5,
        "170": 1,
        "171": 1,
        "172": 131,
        "173": 1,
        "174": 131,
        "175": 1,
        "176": 131,
        "177": 2,
        "178": 78,
        "179": 99,
        "180": 101,
        "181": 114,
        "182": 116,
        "183": 105,
        "184": 102,
        "185": 105,
        "186": 101,
        "187": 100,
        "188": 95,
        "189": 100,
        "190": 97,
        "191": 116,
        "192": 97,
        "193": 130,
        "194": 3,
        "195": 88,
        "196": 32,
        "197": 6,
        "198": 167,
        "199": 166,
        "200": 247,
        "201": 37,
        "202": 166,
        "203": 182,
        "204": 174,
        "205": 110,
        "206": 158,
        "207": 73,
        "208": 209,
        "209": 83,
        "210": 5,
        "211": 116,
        "212": 217,
        "213": 137,
        "214": 184,
        "215": 160,
        "216": 252,
        "217": 167,
        "218": 66,
        "219": 40,
        "220": 24,
        "221": 7,
        "222": 22,
        "223": 6,
        "224": 182,
        "225": 51,
        "226": 216,
        "227": 130,
        "228": 182,
        "229": 130,
        "230": 4,
        "231": 88,
        "232": 32,
        "233": 135,
        "234": 28,
        "235": 181,
        "236": 126,
        "237": 133,
        "238": 131,
        "239": 249,
        "240": 195,
        "241": 37,
        "242": 118,
        "243": 132,
        "244": 218,
        "245": 22,
        "246": 4,
        "247": 208,
        "248": 149,
        "249": 91,
        "250": 227,
        "251": 28,
        "252": 104,
        "253": 39,
        "254": 12,
        "255": 40,
        "256": 111,
        "257": 149,
        "258": 0,
        "259": 184,
        "260": 167,
        "261": 146,
        "262": 241,
        "263": 156,
        "264": 214,
        "265": 130,
        "266": 4,
        "267": 88,
        "268": 32,
        "269": 238,
        "270": 249,
        "271": 202,
        "272": 148,
        "273": 127,
        "274": 229,
        "275": 204,
        "276": 68,
        "277": 149,
        "278": 99,
        "279": 128,
        "280": 217,
        "281": 136,
        "282": 33,
        "283": 70,
        "284": 133,
        "285": 234,
        "286": 34,
        "287": 54,
        "288": 135,
        "289": 205,
        "290": 30,
        "291": 181,
        "292": 120,
        "293": 155,
        "294": 188,
        "295": 196,
        "296": 23,
        "297": 123,
        "298": 119,
        "299": 221,
        "300": 133,
        "301": 130,
        "302": 4,
        "303": 88,
        "304": 32,
        "305": 22,
        "306": 85,
        "307": 179,
        "308": 252,
        "309": 255,
        "310": 136,
        "311": 236,
        "312": 101,
        "313": 226,
        "314": 23,
        "315": 215,
        "316": 213,
        "317": 51,
        "318": 2,
        "319": 116,
        "320": 60,
        "321": 49,
        "322": 58,
        "323": 195,
        "324": 175,
        "325": 177,
        "326": 222,
        "327": 51,
        "328": 31,
        "329": 72,
        "330": 183,
        "331": 147,
        "332": 2,
        "333": 190,
        "334": 199,
        "335": 57,
        "336": 238,
        "337": 130,
        "338": 4,
        "339": 88,
        "340": 32,
        "341": 48,
        "342": 90,
        "343": 207,
        "344": 226,
        "345": 93,
        "346": 219,
        "347": 247,
        "348": 212,
        "349": 55,
        "350": 102,
        "351": 238,
        "352": 132,
        "353": 58,
        "354": 77,
        "355": 217,
        "356": 149,
        "357": 22,
        "358": 245,
        "359": 115,
        "360": 93,
        "361": 25,
        "362": 46,
        "363": 155,
        "364": 174,
        "365": 9,
        "366": 138,
        "367": 95,
        "368": 63,
        "369": 121,
        "370": 74,
        "371": 224,
        "372": 204,
        "373": 131,
        "374": 1,
        "375": 130,
        "376": 4,
        "377": 88,
        "378": 32,
        "379": 4,
        "380": 138,
        "381": 112,
        "382": 79,
        "383": 102,
        "384": 85,
        "385": 47,
        "386": 42,
        "387": 153,
        "388": 48,
        "389": 147,
        "390": 195,
        "391": 230,
        "392": 237,
        "393": 183,
        "394": 14,
        "395": 73,
        "396": 95,
        "397": 194,
        "398": 89,
        "399": 129,
        "400": 95,
        "401": 93,
        "402": 10,
        "403": 236,
        "404": 55,
        "405": 148,
        "406": 131,
        "407": 239,
        "408": 36,
        "409": 147,
        "410": 111,
        "411": 131,
        "412": 2,
        "413": 68,
        "414": 116,
        "415": 105,
        "416": 109,
        "417": 101,
        "418": 130,
        "419": 3,
        "420": 73,
        "421": 208,
        "422": 200,
        "423": 195,
        "424": 186,
        "425": 144,
        "426": 239,
        "427": 250,
        "428": 150,
        "429": 24,
        "430": 105,
        "431": 115,
        "432": 105,
        "433": 103,
        "434": 110,
        "435": 97,
        "436": 116,
        "437": 117,
        "438": 114,
        "439": 101,
        "440": 88,
        "441": 48,
        "442": 146,
        "443": 34,
        "444": 234,
        "445": 44,
        "446": 20,
        "447": 209,
        "448": 103,
        "449": 219,
        "450": 12,
        "451": 37,
        "452": 34,
        "453": 42,
        "454": 216,
        "455": 151,
        "456": 5,
        "457": 96,
        "458": 207,
        "459": 5,
        "460": 105,
        "461": 238,
        "462": 247,
        "463": 101,
        "464": 67,
        "465": 73,
        "466": 164,
        "467": 72,
        "468": 217,
        "469": 126,
        "470": 125,
        "471": 58,
        "472": 82,
        "473": 7,
        "474": 194,
        "475": 32,
        "476": 112,
        "477": 75,
        "478": 80,
        "479": 199,
        "480": 138,
        "481": 173,
        "482": 162,
        "483": 233,
        "484": 190,
        "485": 176,
        "486": 184,
        "487": 247,
        "488": 52,
        "489": 245,
        "490": 100,
        "491": 116,
        "492": 114,
        "493": 101,
        "494": 101,
        "495": 131,
        "496": 1,
        "497": 130,
        "498": 4,
        "499": 88,
        "500": 32,
        "501": 217,
        "502": 93,
        "503": 218,
        "504": 9,
        "505": 45,
        "506": 87,
        "507": 38,
        "508": 18,
        "509": 0,
        "510": 77,
        "511": 102,
        "512": 124,
        "513": 69,
        "514": 184,
        "515": 175,
        "516": 130,
        "517": 63,
        "518": 49,
        "519": 7,
        "520": 123,
        "521": 161,
        "522": 14,
        "523": 30,
        "524": 101,
        "525": 201,
        "526": 230,
        "527": 49,
        "528": 49,
        "529": 228,
        "530": 195,
        "531": 241,
        "532": 224,
        "533": 131,
        "534": 2,
        "535": 67,
        "536": 115,
        "537": 105,
        "538": 103,
        "539": 131,
        "540": 2,
        "541": 88,
        "542": 32,
        "543": 220,
        "544": 194,
        "545": 2,
        "546": 3,
        "547": 211,
        "548": 188,
        "549": 160,
        "550": 39,
        "551": 117,
        "552": 154,
        "553": 236,
        "554": 157,
        "555": 59,
        "556": 79,
        "557": 253,
        "558": 193,
        "559": 51,
        "560": 29,
        "561": 33,
        "562": 194,
        "563": 0,
        "564": 41,
        "565": 125,
        "566": 59,
        "567": 122,
        "568": 49,
        "569": 220,
        "570": 209,
        "571": 138,
        "572": 90,
        "573": 86,
        "574": 114,
        "575": 131,
        "576": 2,
        "577": 88,
        "578": 32,
        "579": 67,
        "580": 48,
        "581": 44,
        "582": 36,
        "583": 37,
        "584": 196,
        "585": 191,
        "586": 188,
        "587": 56,
        "588": 142,
        "589": 93,
        "590": 18,
        "591": 155,
        "592": 209,
        "593": 192,
        "594": 201,
        "595": 4,
        "596": 119,
        "597": 153,
        "598": 189,
        "599": 230,
        "600": 240,
        "601": 117,
        "602": 17,
        "603": 7,
        "604": 44,
        "605": 5,
        "606": 87,
        "607": 208,
        "608": 126,
        "609": 96,
        "610": 186,
        "611": 130,
        "612": 3,
        "613": 64
    }
    "#;
    let map = serde_json::from_str::<HashMap<String, u8>>(raw_str).unwrap();
    
    let hex_text = "0xd9d9f7a26b63657274696669636174655901d7d9d9f7a2647472656583018301830182045820267d108b825149c889227f220ca201138ce621c31c7c3cf174117e7015110bb783024863616e69737465728301820458202a129c29df3f49316f377ea1a617e7ffc8f4c97cc375efa720c2a73b2b50c20a83018301820458208192f3fba82b033274679d4938f2d89bd3f540bc61b8ba9148ae3ba6e25af8da83024a800000000010000501018301830183024e6365727469666965645f646174618203582006a7a6f725a6b6ae6e9e49d1530574d989b8a0fca7422818071606b633d882b682045820871cb57e8583f9c3257684da1604d0955be31c68270c286f9500b8a792f19cd682045820eef9ca947fe5cc44956380d988214685ea223687cd1eb5789bbcc4177b77dd85820458201655b3fcff88ec65e217d7d53302743c313ac3afb1de331f48b79302bec739ee82045820305acfe25ddbf7d43766ee843a4dd99516f5735d192e9bae098a5f3f794ae0cc830182045820048a704f66552f2a993093c3e6edb70e495fc259815f5d0aec379483ef24936f83024474696d65820349d0c8c3ba90effa9618697369676e617475726558309222ea2c14d167db0c25222ad8970560cf0569eef7654349a448d97e7d3a5207c220704b50c78aada2e9beb0b8f734f56474726565830182045820d95dda092d572612004d667c45b8af823f31077ba10e1e65c9e63131e4c3f1e083024373696783025820dcc20203d3bca027759aec9d3b4ffdc1331d21c200297d3b7a31dcd18a5a56728302582043302c2425c4bfbc388e5d129bd1c0c9047799bde6f07511072c0557d07e60ba820340";
    let vec = hex::decode(&hex_text[2..]).unwrap();
    for i in 0..vec.len() {
        assert!(vec[i] .eq(map.get(&i.to_string()).unwrap()));
    }
    dbg!(&vec);
}

#[test]
pub fn testsetste() {
    let a = "0a8000000000100005010172a283a9dc5fd6e83b4518bc20b889b5460cb2206b38a0f23370dd2a500e40f4";
    // 0a800000000010000501015f4049163256a9956d796ef5946986e1afb266bdd078ea85d591b15c8a567499

    // Principal::from
}