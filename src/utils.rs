use crate::sha3::Digest;
use bincode::serialize;
use bytes::Bytes;
use sha3::Sha3_256;
use sodiumoxide::crypto::sign::{sign_detached, PublicKey, Signature};

/// Determines whether the passed value is within bounds of
/// available tokens in the supply.
///
/// TODO: Currently placeholder, needs to be filled in once requirements known
pub fn is_valid_amount(value: &u64) -> bool {
    true
}

/// Constructs a new address from a public key
///
/// TODO: Build this out to be more comprehensive than just a sha3 hash
///
/// ### Arguments
///
/// * `public_key`  - Public key to generate an address from
pub fn construct_address(public_key: PublicKey) -> String {
    let address_bytes = Bytes::from(serialize(&public_key).unwrap());
    let address_raw_h = Sha3_256::digest(&address_bytes).to_vec();

    hex::encode(address_raw_h)
}
