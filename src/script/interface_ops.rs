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

/// Handles the execution for the duplicate op_code. Returns a bool.
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_dup(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("Duplicating last entry in script stack");
    let dup = current_stack[current_stack.len() - 1].clone();
    current_stack.push(dup);
    true
}

/// Handles the execution for the hash256 op_code. Returns a bool.
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_hash256(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("256 bit hashing last stack entry");
    let last_entry = current_stack.pop().unwrap();
    let pub_key = match last_entry {
        StackEntry::PubKey(v) => v,
        _ => return false,
    };

    let new_entry = construct_address(pub_key);
    current_stack.push(StackEntry::PubKeyHash(new_entry));
    true
}

/// Handles the execution for the equalverify op_code. Returns a bool.
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_equalverify(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("Verifying p2pkh hash");
    let input_hash = current_stack.pop();
    let computed_hash = current_stack.pop();

    if input_hash != computed_hash {
        error!("Hash not valid. Transaction input invalid");
        return false;
    }
    true
}

/// Handles the execution for the checksig op_code. Returns a bool.
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_checksig(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("Checking p2pkh signature");
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
    true
}

/// Handles the execution for the checksig op_code when checking a member of a multisig. Returns a bool.
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_checkmultisigmem(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("Checking signature matches public key for multisig member");
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
        error!("Signature not valid. Member multisig input invalid");
        return false;
    }
    true
}

/// Handles the execution for the multisig op_code. Returns a bool.
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_multisig(current_stack: &mut Vec<StackEntry>) -> bool {
    let mut pub_keys = Vec::new();
    let mut signatures = Vec::new();
    let mut last_val = StackEntry::Op(OpCodes::OP_0);
    let n = match current_stack.pop().unwrap() {
        StackEntry::Num(n) => n,
        _ => panic!("No n value of keys for multisig present"),
    };

    while let StackEntry::PubKey(_pk) = current_stack[current_stack.len() - 1] {
        let next_key = current_stack.pop();

        if let Some(StackEntry::PubKey(pub_key)) = next_key {
            pub_keys.push(pub_key);
        }
    }

    // If there are too few public keys
    if pub_keys.len() < n {
        error!("Too few public keys provided");
        return false;
    }

    let m = match current_stack.pop().unwrap() {
        StackEntry::Num(m) => m,
        _ => panic!("No n value of keys for multisig present"),
    };

    // If there are more keys required than available
    if m > n || m > pub_keys.len() {
        error!("Number of keys required is greater than the number available");
        return false;
    }

    while let StackEntry::Signature(_sig) = current_stack[current_stack.len() - 1] {
        let next_key = current_stack.pop();

        if let Some(StackEntry::Signature(sig)) = next_key {
            signatures.push(sig);
        }
    }

    let check_data = match current_stack.pop().unwrap() {
        StackEntry::Bytes(check_data) => check_data,
        _ => panic!("Check data for validation not present"),
    };

    if !match_on_multisig_to_pubkey(check_data, signatures, pub_keys, m) {
        return false;
    }
    true
}

/// Does pairwise validation of signatures against public keys
///
/// ### Arguments
///
/// * `check_data`  - Data to verify against
/// * `signatures`  - Signatures to check
/// * `pub_keys`    - Public keys to check
/// * `m`           - Number of keys required
fn match_on_multisig_to_pubkey(
    check_data: String,
    signatures: Vec<Signature>,
    pub_keys: Vec<PublicKey>,
    m: usize,
) -> bool {
    let mut counter = 0;

    'outer: for sig in signatures {
        'inner: for pub_key in &pub_keys {
            if sign::verify_detached(&sig, check_data.as_bytes(), pub_key) {
                counter += 1;
                break 'inner;
            }
        }
    }

    counter >= m
}

/// Handles the execution for the default if the op code does not match using a reference. Returns a bool.
///
/// ### Arguments
///
/// * `stack_entry`  - The current entry on the stack
/// * `current_stack`  - mutable reference to the current stack
pub fn op_else(stack_entry: StackEntry, current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("Adding constant to stack: {:?}", stack_entry);
    current_stack.push(stack_entry);
    true
}

/// Handles the execution for the default if the op code does not match. Returns a bool.
///
/// ### Arguments
///
/// * `stack_entry`  - reference to the current entry on the stack
/// * `current_stack`  - mutable reference to the current stack
pub fn op_else_ref(stack_entry: &StackEntry, current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("Adding constant to stack: {:?}", stack_entry);
    current_stack.push(stack_entry.clone());
    true
}
