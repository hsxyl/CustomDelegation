use anyhow::bail;
use candid::{Decode, Encode, Principal};
use ic_agent::Agent;
use ic_agent::agent::http_transport::ReqwestTransport;

use VerifyCertification::bls::bls12381::bls;
use VerifyCertification::certification::{
    Certificate, CertificationError, Delegation, extract_der, IC_ROOT_KEY, IC_STATE_ROOT_DOMAIN_SEPARATOR,
    lookup_value,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let contract = Principal::from_text("gibz6-6yaaa-aaaak-qan7a-cai")
        .expect("failed to convert text to principal");
    let transport =
        ReqwestTransport::create("https://ic0.app").expect("failed to create transport");
    let agent = Agent::builder()
        .with_transport(transport)
        .build()
        .expect("failed to build agent");

    let arg = String::from("Bitcoin To The Moon 🚀🚀🚀");

    get_certification_and_verify(&agent, &contract, &arg).await?;

    Ok(())
}

async fn get_certification_and_verify(
    agent: &Agent,
    contract: &Principal,
    arg: &String,
) -> anyhow::Result<()> {
    let serialized_arg = &Encode!(arg).expect("failed to encode arg");

    // set certified data
    let _ = agent
        .update(&contract, "set")
        .with_arg(serialized_arg)
        .call_and_wait()
        .await?;

    // get certified data
    let res = agent
        .query(&contract, "get")
        .with_arg(&Encode!().unwrap())
        .call()
        .await?;

    let res = Decode!(&res, Option<Vec<u8>>).unwrap();

    if let Some(cer) = res {
        let cer = serde_cbor::from_slice::<Certificate>(&cer).unwrap();
        verify(&cer).expect("failed to verify certificate");

        // /canister/${canister_id}/certified_data
        let path = ["canister".into(), contract.into(), "certified_data".into()];

        println!(
            "Certified Value: \n{:?}",
            String::from_utf8(lookup_value(&cer, path).expect("key not exist").to_vec())
        );

        Ok(())
    } else {
        bail!("failed to get certified data");
    }
}

/// recursively verify the certificate
pub fn verify(cert: &Certificate) -> Result<(), CertificationError> {
    let sig = &cert.signature; // subnet signature

    let root_hash = cert.tree.digest();
    let mut msg = vec![];
    msg.extend_from_slice(IC_STATE_ROOT_DOMAIN_SEPARATOR);
    msg.extend_from_slice(&root_hash);

    let der_key = check_delegation(&cert.delegation)?;
    let key = extract_der(der_key);
    let result = bls::core_verify(sig, &*msg, &*key);
    if result != bls::BLS_OK {
        Err(CertificationError::CertificateVerificationFailed)
    } else {
        println!("verify successfully");
        Ok(())
    }
}

/// return Ok(der_encoded_public_key) or Err(CertificationError)
fn check_delegation(delegation: &Option<Delegation>) -> Result<Vec<u8>, CertificationError> {
    match delegation {
        None => Ok(IC_ROOT_KEY.to_vec()),
        Some(delegation) => {
            let cert: Certificate = serde_cbor::from_slice(&delegation.certificate)
                .map_err(|_| CertificationError::InvalidCborData)?;
            verify(&cert)?;
            let public_key_path = [
                "subnet".into(),
                delegation.subnet_id.clone().into(),
                "public_key".into(),
            ];
            lookup_value(&cert, public_key_path).map(|pk| pk.to_vec())
        }
    }
}
