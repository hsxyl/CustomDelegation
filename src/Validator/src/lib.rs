use candid::CandidType;
use libsecp256k1::{verify, Message, RecoveryId, Signature};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

#[derive(Clone, Debug, CandidType, Deserialize, Serialize)]
pub struct VerifyArgs {
    pub message: String,
    pub signature: String,
}

pub fn verify_metamask_personal_sign(args: VerifyArgs) -> Option<String> {
    let msg = Message::parse(&eth_message(args.message));
    if args.signature.len() != 132 {
        return None;
    }
    let signature = hex::decode(&args.signature[2..]).unwrap();
    let sig = match Signature::parse_standard_slice(&signature[0..64]) {
        Ok(res) => res,
        Err(_) => return None,
    };

    if signature[64] != 27 && signature[64] != 28 {
        return None;
    }

    let rec_id = match RecoveryId::parse(signature[64] - 27) {
        Ok(res) => res,
        Err(_) => return None,
    };

    let pubkey = libsecp256k1::recover(&msg, &sig, &rec_id);
    if pubkey.is_err() {
        return None;
    }

    let pubkey = pubkey.unwrap();
    if verify(&msg, &sig, &pubkey) {
        let pubkey = pubkey.serialize().as_slice().to_owned();
        let address = keccak256(&pubkey[1..])[12..].to_vec();
        return Some(format!("0x{}", hex::encode(address).to_lowercase()));
    } else {
        None
    }
}

pub fn eth_message(message: String) -> [u8; 32] {
    keccak256(
        format!(
            "{}{}{}",
            "\x19Ethereum Signed Message:\n",
            message.len(),
            message
        )
        .as_bytes(),
    )
}

pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod test {
    use crate::validator::{verify_metamask_personal_sign, VerifyArgs};
    use crate::{verify_metamask_personal_sign, VerifyArgs};

    #[test]
    fn test() {
        let arg = VerifyArgs{
            message: "hello".to_string(),
            signature: "0x21110cc628aa41005fb3b30b7b7ddf3ee085cfb01b2f01c1a25e24216eb8d69862c51fa976508f1887f994a50697ba9b96c76d41eaab81c9681f197aa76b7d531c".to_string(),
        };
        let res = verify_metamask_personal_sign(arg);
        println!("{:?}", res)
    }
}
