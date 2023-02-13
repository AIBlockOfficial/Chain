#![allow(unused)]

use crate::constants::*;
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

/*---- STACK OPS ----*/

/// OP_TOALTSTACK: Moves the top item from the main stack to the top of the alt stack. Returns a bool.
///
/// Example: OP_TOALTSTACK([x1, x2], [y1]) -> [x1], [y1, x2]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
/// * `current_alt_stack`  - mutable reference to the current alt stack
pub fn op_toaltstack(
    current_stack: &mut Vec<StackEntry>,
    current_alt_stack: &mut Vec<StackEntry>,
) -> bool {
    trace!("OP_TOALTSTACK: Moves the top item from the main stack to the top of the alt stack");
    if current_stack.is_empty() {
        error!("OP_TOALTSTACK: Not enough elements on the stack");
        return false;
    }
    current_alt_stack.push(current_stack.pop().unwrap());
    true
}

/// OP_FROMALTSTACK: Moves the top item from the alt stack to the top of the main stack. Returns a bool.
///
/// Example: OP_FROMALTSTACK([x1], [y1, y2]) -> [x1, y2], [y1]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
/// * `current_alt_stack`  - mutable reference to the current alt stack
pub fn op_fromaltstack(
    current_stack: &mut Vec<StackEntry>,
    current_alt_stack: &mut Vec<StackEntry>,
) -> bool {
    trace!("OP_FROMALTSTACK: Moves the top item from the alt stack to the top of the main stack");
    if current_alt_stack.is_empty() {
        error!("OP_FROMALTSTACK: Not enough elements on the alt stack");
        return false;
    }
    current_stack.push(current_alt_stack.pop().unwrap());
    true
}

/// OP_2DROP: Removes the top two items from the stack. Returns a bool.
///
/// Example: OP_2DROP([x1, x2, x3]) -> [x1]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_2drop(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_2DROP: Removes the top two items from the stack");
    if current_stack.len() < TWO {
        error!("OP_2DROP: Not enough elements on the stack");
        return false;
    }
    current_stack.pop();
    current_stack.pop();
    true
}

/// OP_2DUP: Duplicates the top two items on the stack. Returns a bool.
///
/// Example: OP_2DUP([x1, x2, x3]) -> [x1, x2, x3, x2, x3]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_2dup(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_2DUP: Duplicates the top two items on the stack");
    let len = current_stack.len();
    if len < TWO {
        error!("OP_2DUP: Not enough elements on the stack");
        return false;
    }
    let item1 = current_stack[len - TWO].clone();
    let item2 = current_stack[len - ONE].clone();
    current_stack.push(item1);
    current_stack.push(item2);
    true
}

/// OP_3DUP: Duplicates the top three items on the stack. Returns a bool.
///
/// Example: OP_3DUP([x1, x2, x3]) -> [x1, x2, x3, x1, x2, x3]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_3dup(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_3DUP: Duplicates the top three items on the stack");
    let len = current_stack.len();
    if len < THREE {
        error!("OP_3DUP: Not enough elements on the stack");
        return false;
    }
    let item1 = current_stack[len - THREE].clone();
    let item2 = current_stack[len - TWO].clone();
    let item3 = current_stack[len - ONE].clone();
    current_stack.push(item1);
    current_stack.push(item2);
    current_stack.push(item3);
    true
}

/// OP_2OVER: Copies the second-to-top pair of items to the top of the stack. Returns a bool.
///
/// Example: OP_2OVER([x1, x2, x3, x4]) -> [x1, x2, x3, x4, x1, x2]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_2over(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_2OVER: Copies the second-to-top pair of items to the top of the stack");
    let len = current_stack.len();
    if len < FOUR {
        error!("OP_2OVER: Not enough elements on the stack");
        return false;
    }
    let item1 = current_stack[len - FOUR].clone();
    let item2 = current_stack[len - THREE].clone();
    current_stack.push(item1);
    current_stack.push(item2);
    true
}

/// OP_2ROT: Moves the third-to-top pair of items to the top of the stack. Returns a bool.
///
/// Example: OP_2ROT([x1, x2, x3, x4, x5, x6]) -> [x3, x4, x5, x6, x1, x2]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_2rot(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_2ROT: Moves the third-to-top pair of items to the top of the stack");
    let len = current_stack.len();
    if len < SIX {
        error!("OP_2ROT: Not enough elements on the stack");
        return false;
    }
    let item1 = current_stack[len - SIX].clone();
    let item2 = current_stack[len - FIVE].clone();
    current_stack.drain(len - SIX..len - FOUR);
    current_stack.push(item1);
    current_stack.push(item2);
    true
}

/// OP_2SWAP: Swaps the top two pairs of items on the stack. Returns a bool.
///
/// Example: OP_2SWAP([x1, x2, x3, x4]) -> [x3, x4, x1, x2]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_2swap(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_2SWAP: Swaps the top two pairs of items on the stack");
    let len = current_stack.len();
    if len < FOUR {
        error!("OP_2SWAP: Not enough elements on the stack");
        return false;
    }
    current_stack.swap(len - FOUR, len - TWO);
    current_stack.swap(len - THREE, len - ONE);
    true
}

/// OP_DEPTH: Adds the stack size to the top of the stack. Returns a bool.
///
/// Example: OP_DEPTH([x1, x2, x3, x4]) -> [x1, x2, x3, x4, 4]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_depth(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_DEPTH: Adds the stack size to the top of the stack");
    current_stack.push(StackEntry::Num(current_stack.len()));
    true
}

/// OP_DROP: Removes the top item from the stack. Returns a bool.
///
/// Example: OP_DROP([x1, x2]) -> [x1]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_drop(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_DROP: Removes the top item from the stack");
    if current_stack.is_empty() {
        error!("OP_DROP: Not enough elements on the stack");
        return false;
    }
    current_stack.pop();
    true
}

/// OP_DUP: Duplicates the top item on the stack. Returns a bool.
///
/// Example: OP_DUP([x1, x2]) -> [x1, x2, x2]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_dup(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_DUP: Duplicates the top item on the stack");
    if current_stack.is_empty() {
        error!("OP_DUP: Not enough elements on the stack");
        return false;
    }
    let item = current_stack[current_stack.len() - ONE].clone();
    current_stack.push(item);
    true
}

/// OP_IFDUP: Duplicates the top item on the stack if it is not ZERO. Returns a bool.
///
/// Example: OP_DUP([x1, x2]) -> [x1, x2, x2] if x2 != 0
///          OP_DUP([x1, x2]) -> [x1, x2]     if x2 == 0
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_ifdup(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_IFDUP: Duplicates the top item on the stack if it is not ZERO");
    if current_stack.is_empty() {
        error!("OP_IFDUP: Not enough elements on the stack");
        return false;
    }
    let item = current_stack[current_stack.len() - ONE].clone();
    if item != StackEntry::Num(ZERO) {
        current_stack.push(item);
    }
    true
}

/// OP_NIP: Removes the second-to-top item from the stack. Returns a bool.
///
/// Example: OP_NIP([x1, x2]) -> [x2]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_nip(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_NIP: Removes the second-to-top item from the stack");
    let len = current_stack.len();
    if len < TWO {
        error!("OP_NIP: Not enough elements on the stack");
        return false;
    }
    current_stack.remove(len - TWO);
    true
}

/// OP_OVER: Copies the second-to-top item to the top of the stack. Returns a bool.
///
/// Example: OP_OVER([x1, x2]) -> [x1, x2, x1]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_over(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_OVER: Copies the second-to-top item to the top of the stack");
    let len = current_stack.len();
    if len < TWO {
        error!("OP_OVER: Not enough elements on the stack");
        return false;
    }
    let item = current_stack[len - TWO].clone();
    current_stack.push(item);
    true
}

/// OP_PICK: Copies the nth-to-top item to the top of the stack,
///          where n is the top item on the stack. Returns a bool.
///
/// Example: OP_PICK([x1, x2, x3, x4, x5, 3]) -> [x1, x2, x3, x4, x5, x2]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_pick(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_PICK: Copies the nth-to-top item to the top of the stack");
    if current_stack.len() < TWO {
        error!("OP_PICK: Not enough elements on the stack");
        return false;
    }
    let item = current_stack.pop().unwrap();
    let n = match item {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    let len = current_stack.len();
    if n >= len {
        error!("OP_PICK: Not enough elements on the stack");
        return false;
    }
    let item = current_stack[len - ONE - n].clone();
    current_stack.push(item);
    true
}

/// OP_ROLL: Moves the nth-to-top item to the top of the stack,
///          where n is the top item on the stack. Returns a bool.
///
/// Example: OP_ROLL([x1, x2, x3, x4, x5, 3]) -> [x1, x3, x4, x5, x2]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_roll(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_ROLL: Moves the nth-to-top item to the top of the stack");
    if current_stack.len() < TWO {
        error!("OP_ROLL: Not enough elements on the stack");
        return false;
    }
    let item = current_stack.pop().unwrap();
    let n = match item {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    let len = current_stack.len();
    if n >= len {
        error!("OP_ROLL: Not enough elements on the stack");
        return false;
    }
    let index = len - ONE - n;
    let item = current_stack[index].clone();
    current_stack.remove(index);
    current_stack.push(item);
    true
}

/// OP_ROT: Moves the third-to-top item to the top of the stack. Returns a bool.
///
/// Example: OP_ROT([x1, x2, x3]) -> [x2, x3, x1]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_rot(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_ROT: Moves the third-to-top item to the top of the stack");
    let len = current_stack.len();
    if len < THREE {
        error!("OP_ROT: Not enough elements on the stack");
        return false;
    }
    current_stack.swap(len - THREE, len - TWO);
    current_stack.swap(len - TWO, len - ONE);
    true
}

/// OP_SWAP: Swaps the top two items on the stack. Returns a bool.
///
/// Example: OP_SWAP([x1, x2]) -> [x2, x1]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_swap(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_SWAP: Swaps the top two items on the stack");
    let len = current_stack.len();
    if len < TWO {
        error!("OP_SWAP: Not enough elements on the stack");
        return false;
    }
    current_stack.swap(len - TWO, len - ONE);
    true
}

/// OP_TUCK: Copies the top item before the second-to-top item on the stack. Returns a bool.
///
/// Example: OP_TUCK([x1, x2]) -> [x2, x1, x2]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_tuck(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_TUCK: Copies the top item before the second-to-top item on the stack");
    let len = current_stack.len();
    if len < TWO {
        error!("OP_TUCK: Not enough elements on the stack");
        return false;
    }
    let item = current_stack[len - ONE].clone();
    current_stack.insert(len - TWO, item);
    true
}

/*---- NUMERIC OPS ----*/

/// OP_1ADD: Adds ONE to the top item on the stack. Returns a bool.
///
/// Example: OP_1ADD([x1, n]) -> [x1, n+1]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_1add(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_1ADD: Adds ONE to the top item on the stack");
    if current_stack.is_empty() {
        error!("OP_1ADD: Not enough elements on the stack");
        return false;
    }
    let n = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    current_stack.push(StackEntry::Num(n + ONE));
    true
}

/// OP_1SUB: Subtracts ONE from the top item on the stack. Returns a bool.
///
/// Example: OP_1SUB([x1, n]) -> [x1, n-1]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_1sub(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_1SUB: Subtracts ONE from the top item on the stack");
    if current_stack.is_empty() {
        error!("OP_1SUB: Not enough elements on the stack");
        return false;
    }
    let n = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    current_stack.push(StackEntry::Num(n - ONE));
    true
}

/*---- CRYPTO OPS ----*/

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
pub fn push_entry_to_stack_ref(
    stack_entry: &StackEntry,
    current_stack: &mut Vec<StackEntry>,
) -> bool {
    trace!("Adding constant to stack: {:?}", stack_entry);
    current_stack.push(stack_entry.clone());
    true
}

/*---- TESTS ----*/

#[cfg(test)]
mod tests {
    use super::*;

    /*---- STACK OPS ----*/

    #[test]
    /// Test OP_TOALTSTACK
    fn test_toaltstack() {
        /// op_toaltstack([1,2,3,4,5,6], [1,2,3,4,5,6]) -> [1,2,3,4,5], [1,2,3,4,5,6,6]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut current_alt_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_alt_stack.push(StackEntry::Num(i));
        }
        let mut v1: Vec<StackEntry> = Vec::new();
        for i in 1..=5 {
            v1.push(StackEntry::Num(i));
        }
        let mut v2: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            v2.push(StackEntry::Num(i));
        }
        v2.push(StackEntry::Num(6));
        op_toaltstack(&mut current_stack, &mut current_alt_stack);
        assert_eq!(current_stack, v1);
        assert_eq!(current_alt_stack, v2)
    }

    #[test]
    /// Test OP_FROMALTSTACK
    fn test_fromaltstack() {
        /// op_fromaltstack([1,2,3,4,5,6], [1,2,3,4,5,6]) -> [1,2,3,4,5,6,6], [1,2,3,4,5]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut current_alt_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_alt_stack.push(StackEntry::Num(i));
        }
        let mut v1: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            v1.push(StackEntry::Num(i));
        }
        v1.push(StackEntry::Num(6));
        let mut v2: Vec<StackEntry> = Vec::new();
        for i in 1..=5 {
            v2.push(StackEntry::Num(i));
        }
        op_fromaltstack(&mut current_stack, &mut current_alt_stack);
        assert_eq!(current_stack, v1);
        assert_eq!(current_alt_stack, v2)
    }

    #[test]
    /// Test OP_2DROP
    fn test_2drop() {
        /// op_2drop([1,2,3,4,5,6]) -> [1,2,3,4]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        op_2drop(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_2DUP
    fn test_2dup() {
        /// op_2dup([1,2,3,4,5,6]) -> [1,2,3,4,5,6,5,6]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(5));
        v.push(StackEntry::Num(6));
        op_2dup(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_3DUP
    fn test_3dup() {
        /// op_3dup([1,2,3,4,5,6]) -> [1,2,3,4,5,6,4,5,6]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(4));
        v.push(StackEntry::Num(5));
        v.push(StackEntry::Num(6));
        op_3dup(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_2OVER
    fn test_2over() {
        /// op_2over([1,2,3,4,5,6]) -> [1,2,3,4,5,6,3,4]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(3));
        v.push(StackEntry::Num(4));
        op_2over(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_2ROT
    fn test_2rot() {
        /// op_2rot([1,2,3,4,5,6]) -> [3,4,5,6,1,2]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 3..=6 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(1));
        v.push(StackEntry::Num(2));
        op_2rot(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_2SWAP
    fn test_2swap() {
        /// op_2swap([1,2,3,4,5,6]) -> [1,2,5,6,3,4]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=2 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(5));
        v.push(StackEntry::Num(6));
        v.push(StackEntry::Num(3));
        v.push(StackEntry::Num(4));
        op_2swap(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_IFDUP
    fn test_ifdup() {
        /// op_ifdup([1,2,3,4,5,6]) -> [1,2,3,4,5,6,6]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(6));
        op_ifdup(&mut current_stack);
        assert_eq!(current_stack, v);
        /// op_ifdup([1,2,3,4,5,6,0]) -> [1,2,3,4,5,6,0]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(0));
        op_ifdup(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_DEPTH
    fn test_depth() {
        /// op_depth([1,1,1,1,1,1]) -> [1,1,1,1,1,1,6]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(1));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            v.push(StackEntry::Num(1));
        }
        v.push(StackEntry::Num(6));
        op_depth(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_DROP
    fn test_drop() {
        /// op_drop([1,2,3,4,5,6]) -> [1,2,3,4,5]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=5 {
            v.push(StackEntry::Num(i));
        }
        op_drop(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_DUP
    fn test_dup() {
        /// op_dup([1,2,3,4,5,6]) -> [1,2,3,4,5,6,6]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(6));
        op_dup(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_NIP
    fn test_nip() {
        /// op_nip([1,2,3,4,5,6]) -> [1,2,3,4,6]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(6));
        op_nip(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_OVER
    fn test_over() {
        /// op_over([1,2,3,4,5,6]) -> [1,2,3,4,5,6,5]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(5));
        op_over(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_PICK
    fn test_pick() {
        /// op_pick([1,2,3,4,5,6,2]) -> [1,2,3,4,5,6,4]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Num(2));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(4));
        op_pick(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_ROLL
    fn test_roll() {
        /// op_roll([1,2,3,4,5,6,2]) -> [1,2,3,5,6,4]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Num(2));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=3 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(5));
        v.push(StackEntry::Num(6));
        v.push(StackEntry::Num(4));
        op_roll(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_ROT
    fn test_rot() {
        /// op_rot([1,2,3,4,5,6]) -> [1,2,3,5,6,4]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=3 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(5));
        v.push(StackEntry::Num(6));
        v.push(StackEntry::Num(4));
        op_rot(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_SWAP
    fn test_swap() {
        /// op_swap([1,2,3,4,5,6]) -> [1,2,3,4,6,5]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(6));
        v.push(StackEntry::Num(5));
        op_swap(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_TUCK
    fn test_tuck() {
        /// op_tuck([1,2,3,4,5,6]) -> [1,2,3,4,6,5,6]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(6));
        v.push(StackEntry::Num(5));
        v.push(StackEntry::Num(6));
        op_tuck(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    /*---- NUMERIC OPS ----*/

    #[test]
    /// Test OP_1ADD
    fn test_1add() {
        /// op_1add([1,2,3,4,5,6]) -> [1,2,3,4,5,7]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=5 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(7));
        op_1add(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_1SUB
    fn test_1sub() {
        /// op_1sub([1,2,3,4,5,6]) -> [1,2,3,4,5,5]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=5 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(5));
        op_1sub(&mut current_stack);
        assert_eq!(current_stack, v)
    }
}
