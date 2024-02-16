//! App using Blockchain library.
#![allow(dead_code)]

//use a_block_chain::db::display::list_assets;
use a_block_chain::primitives::asset::TokenAmount;

mod db;

fn main() {
    // list_assets();
    let x = TokenAmount(53040400);
    println!("X: {}", x);
}
