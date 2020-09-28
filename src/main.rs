extern crate serde;
extern crate merkletree;
extern crate bincode;
extern crate bytes;
extern crate sodiumoxide;
extern crate sha3;
extern crate crypto;
extern crate hex;
extern crate rayon;

pub mod db;
pub mod utils;
pub mod script;
pub mod constants;
pub mod primitives;

use crate::db::display::list_assets;

fn main() {
    list_assets();
}