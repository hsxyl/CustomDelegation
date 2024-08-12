use candid::{CandidType, Deserialize};
use ic_types::hash_tree::{Label, LookupResult};
use ic_types::HashTree;

pub const IC_ROOT_KEY: &[u8; 133] = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00\x81\x4c\x0e\x6e\xc7\x1f\xab\x58\x3b\x08\xbd\x81\x37\x3c\x25\x5c\x3c\x37\x1b\x2e\x84\x86\x3c\x98\xa4\xf1\xe0\x8b\x74\x23\x5d\x14\xfb\x5d\x9c\x0c\xd5\x46\xd9\x68\x5f\x91\x3a\x0c\x0b\x2c\xc5\x34\x15\x83\xbf\x4b\x43\x92\xe4\x67\xdb\x96\xd6\x5b\x9b\xb4\xcb\x71\x71\x12\xf8\x47\x2e\x0d\x5a\x4d\x14\x50\x5f\xfd\x74\x84\xb0\x12\x91\x09\x1c\x5f\x87\xb9\x88\x83\x46\x3f\x98\x09\x1a\x0b\xaa\xae";
pub const IC_STATE_ROOT_DOMAIN_SEPARATOR: &[u8; 14] = b"\x0Dic-state-root";
// DER prefix for the certificate
const DER_PREFIX: &[u8; 37] = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00";

#[derive(Debug, Deserialize, PartialEq, Eq, CandidType)]
pub struct Delegation {
    #[serde(with = "serde_bytes")]
    pub subnet_id: Vec<u8>,

    #[serde(with = "serde_bytes")]
    pub certificate: Vec<u8>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct Certificate<'a> {
    /// The hash tree.
    pub tree: HashTree<'a>,

    /// The signature of the root hash in `tree`.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,

    /// A delegation from the root key to the key used to sign `signature`, if one exists.
    pub delegation: Option<Delegation>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub enum CertificationError {
    CertificateVerificationFailed,
    CertificateNotAuthorized,
    InvalidCborData,
    LookupPathAbsent,
    LookupPathUnknown,
    LookupPathError,
}

/// Looks up a value in the certificate's tree at the specified hash.
///
/// Returns the value if it was found; otherwise, errors with `LookupPathAbsent`, `LookupPathUnknown`, or `LookupPathError`.
pub fn lookup_value<'a, P>(
    certificate: &'a Certificate<'a>,
    path: P,
) -> Result<&'a [u8], CertificationError>
where
    for<'p> &'p P: IntoIterator<Item = &'p Label>,
    P: Into<Vec<Label>>,
{
    match certificate.tree.lookup_path(&path) {
        LookupResult::Absent => Err(CertificationError::LookupPathAbsent),
        LookupResult::Unknown => Err(CertificationError::LookupPathUnknown),
        LookupResult::Found(value) => Ok(value),
        LookupResult::Error => Err(CertificationError::LookupPathError),
    }
}

pub fn extract_der(buf: Vec<u8>) -> Vec<u8> {
    buf[DER_PREFIX.len()..].to_vec()
}
