use bincode::deserialize;
use naom::primitives::block::Block;
use naom::primitives::transaction::Transaction;
use rocksdb::DB;
use std::sync::{Arc, Mutex};
use tracing::warn;

/// Finds all matching transactions for a given DRUID
///
/// ### Arguments
///
/// * `db_path` - Full path to the database
/// * `druid`   - DRUID to find transaction for
/// * `block`   - Block hash containing DRUID
pub fn find_all_matching_druids(db_path: String, druid: String, block: String) -> Vec<Transaction> {
    // TODO: Allow for network type change
    let final_txs = Arc::new(Mutex::new(Vec::new()));
    let db = match DB::open_default(db_path) {
        Ok(db) => db,
        Err(e) => {
            warn!("Failed to open database: {:?}", e);
            return Vec::new();
        }
    };
    let block = match db.get(block) {
        Ok(Some(value)) => match deserialize::<Block>(&value) {
            Ok(block) => block,
            Err(e) => {
                warn!("Failed to deserialize block: {:?}", e);
                return Vec::new();
            }
        },
        Ok(None) => {
            warn!("Block not found in blockchain");
            return Vec::new();
        }
        Err(e) => {
            warn!("Error retrieving block: {:?}", e);
            return Vec::new();
        }
    };

    block.transactions.iter().for_each(|x| {
        let tx = match db.get(x) {
            Ok(Some(value)) => match deserialize::<Transaction>(&value) {
                Ok(tx) => tx,
                Err(e) => {
                    warn!("Failed to deserialize transaction: {:?}", e);
                    return Vec::new();
                }
            }
            Ok(None) => {
                warn!("Transaction not found in blockchain");
                return Vec::new();
            }
            Err(e) => {
                warn!("Error retrieving transaction: {:?}", e);
                return Vec::new();
            }
        };

        if let Some(i) = &tx.druid_info {
            if i.druid == druid {
                final_txs.lock().unwrap().push(tx);
            }
        }
    });

    let guard = Arc::try_unwrap(final_txs).expect("Lock still has multiple owners");
    guard.into_inner().expect("Mutex cannot be locked")
}
