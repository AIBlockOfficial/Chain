// TODO: Need to create a DB stub for unit tests involving the blockchain

use crate::constants::{DB_PATH, DB_PATH_LIVE, DB_PATH_TEST};
use crate::primitives::block::Block;
use crate::primitives::transaction::{OutPoint, Transaction};
use crate::sha3::Digest;
use bincode::{deserialize, serialize};
use bytes::Bytes;
use rocksdb::DB;
use sha3::Sha3_256;

/// Determines whether a transaction has been spent before
///
/// ### Arguments
///
/// * `prev_out`    - OutPoint of previous transaction
pub fn tx_has_spent(prev_out: Option<OutPoint>) -> bool {
    let current_prev_out_input = Bytes::from(serialize(&prev_out).unwrap());
    let current_prev_out_key = Sha3_256::digest(&current_prev_out_input);

    if let Some(o) = prev_out {
        // TODO: Allow for net type change
        let _prev_out_tx = match get_transaction(o.b_hash.clone(), o.t_hash.clone(), 0) {
            Some(t) => t,
            None => return true,
        };

        // Get outpoint hash
        let load_path = format!("{}/{}", DB_PATH, DB_PATH_TEST);
        let db = DB::open_default(load_path.clone()).unwrap();
        let mut iter = db.raw_iterator();

        // Start from block
        iter.seek(o.b_hash);
        iter.next();

        while iter.valid() {
            let next_block = deserialize::<Block>(&iter.value().unwrap()).unwrap();

            // TODO: Work on a better seeking structure
            for tx in next_block.transactions {
                for input in tx.inputs {
                    let hash_input = Bytes::from(serialize(&input.previous_out).unwrap());
                    let hash_key = Sha3_256::digest(&hash_input);

                    // TODO: This is not the best check, as it is possible to spend a portion of the amount
                    // Need to check amount validity
                    if hash_key == current_prev_out_key {
                        return true;
                    }
                }
            }

            iter.next();
        }
    }

    false
}

/// Finds the relevant transaction based on a block and tx hash. If the transaction is not found
/// the return value will be None
///
/// ### Arguments
///
/// * `b_hash`  - Block hash
/// * `t_hash`  - Transaction hash
/// * `net`     - Which network blockchain to fetch
pub fn get_transaction(b_hash: String, t_hash: String, net: usize) -> Option<Transaction> {
    let load_path = match net {
        0 => format!("{}/{}", DB_PATH, DB_PATH_TEST),
        _ => format!("{}/{}", DB_PATH, DB_PATH_LIVE),
    };

    let db = DB::open_default(load_path.clone()).unwrap();

    let block = match db.get(b_hash) {
        Ok(Some(value)) => deserialize::<Block>(&value).unwrap(),
        Ok(None) => panic!("Block hash not present in this blockchain"),
        Err(e) => panic!("Error retrieving block: {:?}", e),
    };

    for tx in block.transactions {
        let hash_input = Bytes::from(serialize(&tx).unwrap());
        let hash_key_raw = Sha3_256::digest(&hash_input);
        let hash_key = hex::encode(hash_key_raw);

        if hash_key == t_hash {
            return Some(tx);
        }
    }

    None
}
