#![allow(unused)]
use crate::constants::{MAX_BLOCK_SIZE, NETWORK_VERSION};
use crate::primitives::asset::Asset;
use crate::primitives::transaction::{Transaction, TxIn, TxOut};
use crate::sha3::Digest;

use bincode::{deserialize, serialize};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;
use sodiumoxide::crypto::sign::ed25519::PublicKey;
use std::convert::TryInto;

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

use merkle_log::{MemoryStore, MerkleLog, Store};

/// Block header, which contains a smaller footprint view of the block.
/// Hash records are assumed to be 256 bit
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version: u32,
    pub bits: usize,
    pub nonce: Vec<u8>,
    pub b_num: u64,
    pub seed_value: Vec<u8>, // for commercial
    pub previous_hash: Option<String>,
    pub merkle_root_hash: String,
}

impl Default for BlockHeader {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockHeader {
    /// Creates a new BlockHeader
    pub fn new() -> BlockHeader {
        BlockHeader {
            version: NETWORK_VERSION,
            previous_hash: None,
            merkle_root_hash: String::default(),
            seed_value: Vec::new(),
            bits: 0,
            b_num: 0,
            nonce: Vec::new(),
        }
    }

    /// Checks whether a BlockHeader is empty
    pub fn is_null(&self) -> bool {
        self.bits == 0
    }
}

/// A block, a collection of transactions for processing
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<String>,
}

impl Default for Block {
    fn default() -> Self {
        Self::new()
    }
}

impl Block {
    /// Creates a new instance of a block
    pub fn new() -> Block {
        Block {
            header: BlockHeader::new(),
            transactions: Vec::new(),
        }
    }

    /// Sets the internal number of bits based on length
    pub fn set_bits(&mut self) {
        let bytes = Bytes::from(serialize(&self).unwrap());
        self.header.bits = bytes.len();
    }

    /// Checks whether a block has hit its maximum size
    pub fn is_full(&self) -> bool {
        let bytes = Bytes::from(serialize(&self).unwrap());
        bytes.len() >= MAX_BLOCK_SIZE
    }

    /// Get the merkle root for the current set of transactions
    pub async fn set_merkle_root(&mut self) {
        let merkle_result = build_merkle_tree(&self.transactions).await;

        self.header.merkle_root_hash = if let Some((merkle_tree, _)) = merkle_result {
            hex::encode(merkle_tree.root())
        } else {
            "".to_string()
        }
    }
}

/*---- FUNCTIONS ----*/

/// Converts a dynamic array into a static 32 bit
///
/// ### Arguments
///
/// * `bytes`   - Bytes to cast
pub fn from_slice(bytes: &[u8]) -> [u8; 32] {
    let mut array = [0; 32];
    let bytes = &bytes[..array.len()]; // panics if not enough data
    array.copy_from_slice(bytes);
    array
}

/// Generates a random transaction hash for testing
pub fn gen_random_hash() -> String {
    let rand_2: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    hex::encode(Sha3_256::digest(&rand_2.as_bytes()).to_vec())
}

/// Builds a merkle tree of the passed transactions
///
/// ### Arguments
///
/// * `transactions`    - Transactions to construct a merkle tree for
pub async fn build_merkle_tree(
    transactions: &[String],
) -> Option<(MerkleLog<Sha3_256>, MemoryStore)> {
    let mut store = MemoryStore::default();

    if let Some((first_entry, other_entries)) = transactions.split_first() {
        let mut log = MerkleLog::<Sha3_256>::new(&first_entry, &mut store)
            .await
            .unwrap();

        for entry in other_entries {
            log.append(entry, &mut store).await.unwrap();
        }

        return Some((log, store));
    }

    None
}

/*---- TESTS ----*/

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::Sha3_256;

    #[actix_rt::test]
    /// Ensures that the merkle root is set to a valid empty string when no tx's are present
    async fn should_construct_merkle_root_with_no_tx() {
        let mut block = Block::new();
        block.set_merkle_root().await;

        assert_eq!(block.header.merkle_root_hash, "".to_string());
    }

    #[actix_rt::test]
    /// Ensures that a static set of tx produces a valid merkle root hash
    async fn should_construct_a_valid_merkle_root() {
        let mut block = Block::new();
        block.transactions = vec![
            "f479fc771c19c64b14b1b9e446ccccf36b6d705c891eb9a7662c82134e362732".to_string(),
            "ac24e4c5dc8d0a29cac34ddcf7902bc2f2e8a98ec376def02c06db267d0f5477".to_string(),
            "4d04366cb153bdcc11b97a9d1176fc889eafc63edbd2c010a6a62a4f9232d156".to_string(),
            "6486b86af39db28e4f61c7b484e0869ad478e8cb2475b91e92d1b721b70d1746".to_string(),
            "03b45b843d60b1e43241553c9aeb95fed82cc1bbb599c6c066ddaa75709b3186".to_string(),
            "8d0250ea0864ac426fe4f4142dae721c74da732476de83d424e1ba0b638238a7".to_string(),
            "f57e38fb8499b7c2b3d4cf75a24a5dd8a8f7b46f28b9671eb8168ffb93a85424".to_string(),
            "e0acad209b680e61c3ef4624d9a61b32a5e7e3f0691a8f8d41fd50b1c946e338".to_string(),
        ];

        block.set_merkle_root().await;
        assert_eq!(
            block.header.merkle_root_hash,
            "49adba4740eb78c38318bbe2951a3c49e8a5bda6b892870bdcbe0713cf1e0af2"
        );
    }

    #[actix_rt::test]
    /// Ensures that a tx's entry in the merkle tree can be successfully proven
    async fn should_produce_valid_merkle_proof() {
        let mut transactions = vec![
            "f479fc771c19c64b14b1b9e446ccccf36b6d705c891eb9a7662c82134e362732".to_string(),
            "ac24e4c5dc8d0a29cac34ddcf7902bc2f2e8a98ec376def02c06db267d0f5477".to_string(),
            "4d04366cb153bdcc11b97a9d1176fc889eafc63edbd2c010a6a62a4f9232d156".to_string(),
            "6486b86af39db28e4f61c7b484e0869ad478e8cb2475b91e92d1b721b70d1746".to_string(),
            "03b45b843d60b1e43241553c9aeb95fed82cc1bbb599c6c066ddaa75709b3186".to_string(),
            "8d0250ea0864ac426fe4f4142dae721c74da732476de83d424e1bab638238a7".to_string(),
            "f57e38fb8499b7c2b3d4cf75a24a5dd8a8f7b46f28b9671eb8168ffb93a85424".to_string(),
            "e0acad209b680e61c3ef4624d9a61b32a5e7e3f0691a8f8d41fd50b1c946e338".to_string(),
        ];

        let (mtree, store) = build_merkle_tree(&transactions).await.unwrap();
        let check_entry = Sha3_256::digest(&transactions[0].as_bytes());
        let proof = mtree
            .prove(0, &from_slice(&check_entry), &store)
            .await
            .unwrap();

        assert!(mtree.verify(0, &from_slice(&check_entry), &proof));
    }
}
