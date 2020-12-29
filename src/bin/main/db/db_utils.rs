use bincode::deserialize;
use naom::constants::{DB_PATH, DB_PATH_TEST};
use naom::primitives::block::Block;
use naom::primitives::transaction::Transaction;
use rocksdb::DB;
use std::mem;
use std::sync::{Arc, Mutex};

/// Finds all matching transactions for a given DRUID
///
/// ### Arguments
///
/// * `druid`   - DRUID to find transaction for
/// * `block`   - Block hash containing DRUID
pub fn find_all_matching_druids(druid: String, block: String) -> Vec<Transaction> {
    // TODO: Allow for network type change
    let open_path = format!("{}/{}", DB_PATH, DB_PATH_TEST);
    let final_txs = Arc::new(Mutex::new(Vec::new()));
    let db = DB::open_default(open_path.clone()).unwrap();
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

        if let Some(d) = &tx.druid {
            if d == &druid {
                final_txs.lock().unwrap().push(tx);
            }
        }
    });

    let guard = Arc::try_unwrap(final_txs).expect("Lock still has multiple owners");
    guard.into_inner().expect("Mutex cannot be locked")
}
