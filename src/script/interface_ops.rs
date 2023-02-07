#![allow(unused)]

use crate::constants::TOTAL_TOKENS;
use crate::crypto::sha3_256;
use crate::primitives::asset::{Asset, TokenAmount};
use crate::primitives::transaction::*;
use crate::script::lang::Script;
use crate::script::{OpCodes, StackEntry};
use crate::utils::transaction_utils::{construct_address, construct_address_for};

use crate::crypto::sign_ed25519 as sign;
use crate::crypto::sign_ed25519::{PublicKey, Signature};
use bincode::serialize;
use bytes::Bytes;
use hex::encode;
use std::collections::BTreeMap;
use tracing::{debug, error, info, trace};

// --- Stack ops ---

/// Handles the execution of the OP_2DROP opcode. Returns a bool.
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_2drop(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_2DROP: removing the top two items on the stack");
    if current_stack.len() < 2 {
        error!("Not enough elements on the stack");
        return false;
    }
    current_stack.pop();
    current_stack.pop();
    true
}

/// Handles the execution of the OP_2DUP opcode. Returns a bool.
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_2dup(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_2DUP: duplicating the top two items on the stack");
    let len = current_stack.len();
    if len < 2 {
        error!("Not enough elements on the stack");
        return false;
    }
    let item1 = current_stack[len - 2].clone();
    let item2 = current_stack[len - 1].clone();
    current_stack.push(item1);
    current_stack.push(item2);
    true
}

/// Handles the execution of the OP_3DUP opcode. Returns a bool.
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_3dup(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_3DUP: duplicating the top three items on the stack");
    let len = current_stack.len();
    if len < 3 {
        error!("Not enough elements on the stack");
        return false;
    }
    let item1 = current_stack[len - 3].clone();
    let item2 = current_stack[len - 2].clone();
    let item3 = current_stack[len - 1].clone();
    current_stack.push(item1);
    current_stack.push(item2);
    current_stack.push(item3);
    true
}

/// Handles the execution of the OP_2OVER opcode. Returns a bool.
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_2over(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_2OVER: copying the pair of items two spaces back to the top of the stack");
    let len = current_stack.len();
    if len < 4 {
        error!("Not enough elements on the stack");
        return false;
    }
    let item1 = current_stack[len - 4].clone();
    let item2 = current_stack[len - 3].clone();
    current_stack.push(item1);
    current_stack.push(item2);
    true
}

/// Handles the execution of the OP_2ROT opcode. Returns a bool.
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_2rot(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_2ROT: moving the fifth and sixth items back to the top of the stack");
    let len = current_stack.len();
    if len < 6 {
        error!("Not enough elements on the stack");
        return false;
    }
    let item1 = current_stack[len - 6].clone();
    let item2 = current_stack[len - 5].clone();
    current_stack.drain(len - 6..len - 4);
    current_stack.push(item1);
    current_stack.push(item2);
    true
}

/// Handles the execution of the OP_2SWAP opcode. Returns a bool.
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_2swap(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_2SWAP: swapping the top two pairs of items on the stack");
    let len = current_stack.len();
    if len < 4 {
        error!("Not enough elements on the stack");
        return false;
    }
    current_stack.swap(len - 4, len - 2);
    current_stack.swap(len - 3, len - 1);
    true
}

/// Handles the execution of the OP_DEPTH opcode. Returns a bool.
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_depth(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_DEPTH: adding the stack size to the top of the stack");
    current_stack.push(StackEntry::Num(current_stack.len()));
    true
}

/// Handles the execution of the OP_DROP opcode. Returns a bool.
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_drop(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_DROP: removing the top item on the stack");
    if current_stack.len() < 1 {
        error!("Not enough elements on the stack");
        return false;
    }
    current_stack.pop();
    true
}

/// Handles the execution of the OP_DUP opcode. Returns a bool.
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_dup(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_DUP: duplicating the top item on the stack");
    let len = current_stack.len();
    if len < 1 {
        error!("Not enough elements on the stack");
        return false;
    }
    let item = current_stack[len - 1].clone();
    current_stack.push(item);
    true
}

/// Handles the execution of the OP_IFDUP opcode. Returns a bool.
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_ifdup(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_IFDUP: duplicating the top item on the stack if it is not 0");
    let len = current_stack.len();
    if len < 1 {
        error!("Not enough elements on the stack");
        return false;
    }
    let item = current_stack[len - 1].clone();
    if item != StackEntry::Num(0) {
        current_stack.push(item);
    }
    true
}

/// Handles the execution of the OP_NIP opcode. Returns a bool.
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_nip(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_NIP: removing the second-to-top item on the stack");
    let len = current_stack.len();
    if len < 2 {
        error!("Not enough elements on the stack");
        return false;
    }
    current_stack.remove(len - 2);
    true
}

/// Handles the execution of the OP_OVER opcode. Returns a bool.
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_over(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_OVER: copying the second-to-top item to the top of the stack");
    let len = current_stack.len();
    if len < 2 {
        error!("Not enough elements on the stack");
        return false;
    }
    let item = current_stack[len - 2].clone();
    current_stack.push(item);
    true
}

/// Handles the execution of the OP_PICK opcode. Returns a bool.
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_pick(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_PICK: copying the n-th item back to the top of the stack");
    if current_stack.len() < 2 {
        error!("Not enough elements on the stack");
        return false;
    }
    let item = current_stack.pop().unwrap();
    let n = match item {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    let len = current_stack.len();
    if n >= len {
        error!("Not enough elements on the stack");
        return false;
    }
    let item = current_stack[len - 1 - n].clone();
    current_stack.push(item);
    true
}

/// Handles the execution of the OP_ROLL opcode. Returns a bool.
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_roll(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_ROLL: moving the n-th item back to the top of the stack");
    if current_stack.len() < 2 {
        error!("Not enough elements on the stack");
        return false;
    }
    let item = current_stack.pop().unwrap();
    let n = match item {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    let len = current_stack.len();
    if n >= len {
        error!("Not enough elements on the stack");
        return false;
    }
    let index = len - 1 - n;
    let item = current_stack[index].clone();
    current_stack.remove(index);
    current_stack.push(item);
    true
}

/// Handles the execution of the OP_ROT opcode. Returns a bool.
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_rot(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_ROT: moving the third item back to the top of the stack");
    let len = current_stack.len();
    if len < 3 {
        error!("Not enough elements on the stack");
        return false;
    }
    current_stack.swap(len - 3, len - 2);
    current_stack.swap(len - 2, len - 1);
    true
}

/// Handles the execution of the OP_SWAP opcode. Returns a bool.
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_swap(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_SWAP: swapping the top two items on the stack");
    let len = current_stack.len();
    if len < 2 {
        error!("Not enough elements on the stack");
        return false;
    }
    current_stack.swap(len - 2, len - 1);
    true
}

/// Handles the execution of the OP_TUCK opcode. Returns a bool.
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_tuck(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_TUCK: copying the top item before the second-to-top item on the stack");
    let len = current_stack.len();
    if len < 2 {
        error!("Not enough elements on the stack");
        return false;
    }
    let item = current_stack[len - 1].clone();
    current_stack.insert(len - 2, item);
    true
}

// --- Crypto ops ---

/// Handles the execution for the hash256 opcode. Returns a bool.
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_hash256(current_stack: &mut Vec<StackEntry>, address_version: Option<u64>) -> bool {
    trace!("OP_HASH256: creating address from public key and address version");
    let last_entry = current_stack.pop().unwrap();
    let pub_key = match last_entry {
        StackEntry::PubKey(v) => v,
        _ => return false,
    };

    let new_entry = construct_address_for(&pub_key, address_version);
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
        _ => panic!("No m value of keys for multisig present"),
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

/// Pushes a new entry to the current stack. Returns a bool.
///
/// ### Arguments
///
/// * `stack_entry`  - The current entry on the stack
/// * `current_stack`  - mutable reference to the current stack
pub fn push_entry_to_stack(stack_entry: StackEntry, current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("Adding constant to stack: {:?}", stack_entry);
    current_stack.push(stack_entry);
    true
}

/// Pushes a new entry to the current stack. Returns a bool.
///
/// ### Arguments
///
/// * `stack_entry`  - reference to the current entry on the stack
/// * `current_stack`  - mutable reference to the current stack
pub fn push_entry_to_stack_ref(stack_entry: &StackEntry, current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("Adding constant to stack: {:?}", stack_entry);
    current_stack.push(stack_entry.clone());
    true
}
