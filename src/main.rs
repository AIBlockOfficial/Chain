#![allow(warnings)]

extern crate bincode;
extern crate bytes;
extern crate crypto;
extern crate hex;
extern crate merkletree;
extern crate rayon;
extern crate serde;
extern crate sha3;
extern crate sodiumoxide;

pub mod constants;
pub mod db;
pub mod primitives;
pub mod script;
pub mod utils;

use crate::db::display::list_assets;
use crate::primitives::asset::TokenAmount;

fn main() {
    // list_assets();
    let x = TokenAmount(53040400);
    println!("X: {}", x);
}
