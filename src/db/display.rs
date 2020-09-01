use crate::constants::{DB_PATH, DB_PATH_LIVE, DB_PATH_TEST};
use bincode::{deserialize, serialize};
use colored::*;
use rocksdb::{Options, DB};
use sha3::Sha3_256;

use crate::primitives::asset::Asset;
use crate::primitives::block::Block;

/// Lists all assets in the blockchain and outputs them to stdout
pub fn list_assets() {
    let save_path = format!("{}/{}", DB_PATH, DB_PATH_TEST);
    let db = DB::open_default(save_path.clone()).unwrap();

    let mut iter = db.raw_iterator();
    iter.seek_to_first();

    println!("");
    while iter.valid() {
        let key = String::from_utf8_lossy(iter.key().unwrap());
        let block = deserialize::<Block>(iter.value().unwrap()).unwrap();

        println!("//###########################//");
        println!("");
        println!("{}: {}", "BLOCK".magenta(), key);
        println!("{}: {}", "Version".magenta(), block.header.version);
        println!(
            "{}: {:?}",
            "Previous Hash".magenta(),
            block.header.previous_hash
        );
        println!(
            "{}: {}",
            "Merkle Root Hash".magenta(),
            String::from_utf8_lossy(&block.header.merkle_root_hash)
        );
        println!("{}: {}", "Block Number".magenta(), block.header.b_num);
        println!("");

        for i in 0..block.transactions.len() {
            let tx = &block.transactions[i];

            println!("{} {}", "TRANSACTION".cyan(), i.to_string().cyan());
            println!("{}: {}", "Version".cyan(), tx.version);
            println!("{}: {:?}", "DRUID".cyan(), tx.druid);
            println!(
                "{}: {:?}",
                "DRUID Participants".cyan(),
                tx.druid_participants
            );
            println!("{}: {:?}", "Expected Trade Asset".cyan(), tx.expect_value);
            println!(
                "{}: {:?}",
                "Expected Trade Amount".cyan(),
                tx.expect_value_amount
            );
            println!("");
            println!("//------//");
            println!("");
            println!("{}", "INPUTS:".cyan());
            for input in &tx.inputs {
                println!("{}: {:?}", "Previous Out".green(), input.previous_out);
                println!("{}: {:?}", "Script".green(), input.script_signature);
                println!("");
            }
            println!("//------//");
            println!("");
            println!("{}", "OUTPUTS:".cyan());
            for output in &tx.outputs {
                let asset = match &output.value {
                    Some(Asset::Token(v)) => v.to_string(),
                    Some(Asset::Data(v)) => String::from_utf8_lossy(&v).to_string(),
                    None => "None".to_string(),
                };

                let asset_type = match &output.value {
                    Some(Asset::Token(_)) => "Token",
                    Some(Asset::Data(_)) => "Data",
                    None => "None",
                };

                println!("{}: {:?}", "Asset Type".green(), asset_type);
                println!("{}: {:?}", "Asset".green(), asset);
                println!("{}: {:?}", "Amount".green(), output.amount);
                println!("{}: {:?}", "DRS Root Hash".green(), output.drs_block_hash);
                println!(
                    "{}: {:?}",
                    "Script with PubKey".green(),
                    output.script_public_key
                );
                println!("");
            }
            println!("//###########################//");
        }

        iter.next();
    }
    println!("");
    println!("END OF BLOCKCHAIN");
    println!("");

    let _ = DB::destroy(&Options::default(), save_path.clone());
}
