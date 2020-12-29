//! App using NAOM library.
#![allow(dead_code)]

//use naom::db::display::list_assets;
use naom::primitives::asset::TokenAmount;

mod db;

fn main() {
    // list_assets();
    let x = TokenAmount(53040400);
    println!("X: {}", x);
}
