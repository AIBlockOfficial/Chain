use bincode::deserialize;
use naom::primitives::block::Block;
use naom::primitives::transaction::Transaction;
use rocksdb::DB;
use std::sync::{Arc, Mutex};

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
    let db = DB::open_default(db_path).unwrap();
    let block = match db.get(block) {
        Ok(Some(value)) => deserialize::<Block>(&value).unwrap(),
        Ok(None) => panic!("Block not found in blockchain"),
        Err(e) => panic!("Error retrieving block: {:?}", e),
    };

    block.transactions.iter().for_each(|x| {
        let tx = match db.get(x) {
            Ok(Some(value)) => deserialize::<Transaction>(&value).unwrap(),
            Ok(None) => panic!("Transaction not found in blockchain"),
            Err(e) => panic!("Error retrieving transaction: {:?}", e),
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
