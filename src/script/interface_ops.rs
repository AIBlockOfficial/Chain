#![allow(unused)]

use crate::constants::TOTAL_TOKENS;
use crate::primitives::asset::{Asset, TokenAmount};
use crate::primitives::transaction::*;
use crate::primitives::transaction_utils::construct_address;
use crate::script::lang::Script;
use crate::script::{OpCodes, StackEntry};
use crate::sha3::Digest;

use bincode::serialize;
use bytes::Bytes;
use hex::encode;
use sha3::Sha3_256;
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::sign::ed25519::{PublicKey, Signature};
use std::collections::BTreeMap;
use tracing::{debug, error, info, trace};

pub fn op_dup(current_stack: &mut Vec<StackEntry>) {
    println!("Duplicating last entry in script stack");
    let dup = current_stack[current_stack.len() - 1].clone();
    current_stack.push(dup);
}
pub fn op_hash256(current_stack: &mut Vec<StackEntry>) -> bool {
    println!("256 bit hashing last stack entry");
    let last_entry = current_stack.pop().unwrap();
    let pub_key = match last_entry {
        StackEntry::PubKey(v) => v,
        _ => return false,
    };
    return true;
}
pub fn op_equalverify(current_stack: &mut Vec<StackEntry>) -> bool {
    println!("Verifying p2pkh hash");
    let input_hash = current_stack.pop();
    let computed_hash = current_stack.pop();

    if input_hash != computed_hash {
        error!("Hash not valid. Transaction input invalid");
        return false;
    }
    return true;
}
pub fn op_checksig(current_stack: &mut Vec<StackEntry>) -> bool {
    println!("Checking p2pkh signature");
    let pub_key: PublicKey = match current_stack.pop().unwrap() {
        StackEntry::PubKey(pub_key) => pub_key,
        _ => panic!("Public key not present to verify transaction"),
    };

    let sig: Signature = match current_stack.pop().unwrap() {
        StackEntry::Signature(sig) => sig,
        _ => panic!("Signature not present to verify transaction"),
    };

    let check_data = match current_stack.pop().unwrap() {
        StackEntry::Bytes(check_data) => check_data,
        _ => panic!("Check data bytes not present to verify transaction"),
    };

    if (!sign::verify_detached(&sig, check_data.as_bytes(), &pub_key)) {
        error!("Signature not valid. Transaction input invalid");
        return false;
    }
    return true;
}
