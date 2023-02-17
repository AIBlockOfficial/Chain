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
use std::ops::{BitAnd, BitOr, BitXor, Not};
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

/// OP_IFDUP: Duplicates the top item on the stack if it is not ZERO. Returns a bool.
///
/// Example: OP_IFDUP([x1, x2]) -> [x1, x2, x2] if x2 != 0
///          OP_IFDUP([x1, x2]) -> [x1, x2]     if x2 == 0
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
        error!("OP_PICK: Index is out of bound");
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
        error!("OP_ROLL: Index is out of bound");
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

/*---- SPLICE OPS ----*/

/// OP_CAT: Concatenates the second-to-top item and the top item on the stack. Returns a bool.
///
/// Example: OP_CAT([x, s1, s2]) -> [x, s1s2]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_cat(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_CAT: Concatenates the second-to-top item and the top item on the stack");
    if current_stack.len() < TWO {
        error!("OP_CAT: Not enough elements on the stack");
        return false;
    }
    let s2 = match current_stack.pop().unwrap() {
        StackEntry::Bytes(s) => s,
        _ => return false,
    };
    let s1 = match current_stack.pop().unwrap() {
        StackEntry::Bytes(s) => s,
        _ => return false,
    };
    if s1.len() + s2.len() > MAX_SCRIPT_ELEMENT_SIZE as usize {
        error!(
            "OP_CAT: Item size is greater than {}-byte limit",
            MAX_SCRIPT_ELEMENT_SIZE
        );
        return false;
    }
    current_stack.push(StackEntry::Bytes([s1, s2].join("")));
    true
}

/// OP_SUBSTR: Extracts a substring from the third-to-top item on the stack. Returns a bool.
///
/// Example: OP_SUBSTR([x, s, n1, n2]) -> [x, s[n1..n1+n2-1]]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_substr(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_SUBSTR: Extracts a substring from the third-to-top item on the stack");
    if current_stack.len() < THREE {
        error!("OP_SUBSTR: Not enough elements on the stack");
        return false;
    }
    let n2 = match current_stack.pop().unwrap() {
        StackEntry::Num(n) => n,
        _ => return false,
    };
    let n1 = match current_stack.pop().unwrap() {
        StackEntry::Num(n) => n,
        _ => return false,
    };
    let s = match current_stack.pop().unwrap() {
        StackEntry::Bytes(s) => s,
        _ => return false,
    };
    if n1 > s.len() {
        error!("OP_SUBSTR: Start index is out of bound");
        return false;
    }
    if n1 + n2 >= s.len() {
        error!("OP_SUBSTR: End index is out of bound");
        return false;
    }
    current_stack.push(StackEntry::Bytes(s.get(n1..n1 + n2).unwrap().to_string()));
    true
}

/// OP_LEFT: Extracts a left substring from the second-to-top item on the stack. Returns a bool.
///
/// Example: OP_LEFT([x, s, n]) -> [x, s[..n-1]]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_left(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_LEFT: Extracts a left substring from the second-to-top item on the stack");
    if current_stack.len() < THREE {
        error!("OP_LEFT: Not enough elements on the stack");
        return false;
    }
    let n = match current_stack.pop().unwrap() {
        StackEntry::Num(n) => n,
        _ => return false,
    };
    let s = match current_stack.pop().unwrap() {
        StackEntry::Bytes(s) => s,
        _ => return false,
    };
    if n >= s.len() {
        current_stack.push(StackEntry::Bytes(s));
    } else {
        current_stack.push(StackEntry::Bytes(s.get(..n).unwrap().to_string()));
    }
    true
}

/// OP_RIGHT: Extracts a right substring from the second-to-top item on the stack. Returns a bool.
///
/// Example: OP_RIGHT([x, s, n]) -> [x, s[n..]]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_right(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_RIGHT: Extracts a right substring from the second-to-top item on the stack");
    if current_stack.len() < THREE {
        error!("OP_RIGHT: Not enough elements on the stack");
        return false;
    }
    let n = match current_stack.pop().unwrap() {
        StackEntry::Num(n) => n,
        _ => return false,
    };
    let s = match current_stack.pop().unwrap() {
        StackEntry::Bytes(s) => s,
        _ => return false,
    };
    if n >= s.len() {
        current_stack.push(StackEntry::Bytes(String::new()));
    } else {
        current_stack.push(StackEntry::Bytes(s.get(n..).unwrap().to_string()));
    }
    true
}

/// OP_SIZE: Computes the size in bytes of the top item on the stack. Returns a bool.
///
/// Example: OP_SIZE([x, s]) -> [x, s, len(s)]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_size(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_SIZE: Computes the size in bytes of the top item on the stack");
    if current_stack.is_empty() {
        error!("OP_SIZE: Not enough elements on the stack");
        return false;
    }
    let s = match current_stack.pop().unwrap() {
        StackEntry::Bytes(s) => s,
        _ => return false,
    };
    current_stack.push(StackEntry::Num(s.len()));
    true
}

/*---- BITWISE LOGIC OPS ----*/

/// OP_INVERT: Computes bitwise complement of the top item on the stack. Returns a bool.
///
/// Example: OP_INVERT([x, n]) -> [x, !n]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_invert(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_INVERT: Computes bitwise complement of the top item on the stack");
    if current_stack.is_empty() {
        error!("OP_INVERT: Not enough elements on the stack");
        return false;
    }
    let n = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    current_stack.push(StackEntry::Num(n.not()));
    true
}

/// OP_AND: Computes bitwise AND between the second-to-top and the top item on the stack. Returns a bool.
///
/// Example: OP_AND([x, n1, n2]) -> [x, n1 & n2]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_and(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_AND: Computes bitwise AND between the second-to-top and the top item on the stack");
    if current_stack.len() < TWO {
        error!("OP_AND: Not enough elements on the stack");
        return false;
    }
    let n2 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    let n1 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    current_stack.push(StackEntry::Num(n1.bitand(n2)));
    true
}

/// OP_OR: Computes bitwise OR between the second-to-top and the top item on the stack. Returns a bool.
///
/// Example: OP_OR([x, n1, n2]) -> [x, n1 | n2]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_or(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_OR: Computes bitwise OR between the second-to-top and the top item on the stack");
    if current_stack.len() < TWO {
        error!("OP_OR: Not enough elements on the stack");
        return false;
    }
    let n2 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    let n1 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    current_stack.push(StackEntry::Num(n1.bitor(n2)));
    true
}

/// OP_XOR: Computes bitwise exclusive OR between the second-to-top and the top item on the stack. Returns a bool.
///
/// Example: OP_XOR([x, n1, n2]) -> [x, n1 ^ n2]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_xor(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_XOR: Computes bitwise exclusive OR between the second-to-top and the top item on the stack");
    if current_stack.len() < TWO {
        error!("OP_XOR: Not enough elements on the stack");
        return false;
    }
    let n2 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    let n1 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    current_stack.push(StackEntry::Num(n1.bitxor(n2)));
    true
}

/// OP_EQUAL: Substitutes the top two items on the stack with ONE if they are equal, with ZERO otherwise. Returns a bool.
///
/// Example: OP_EQUAL([x, x1, x2]) -> [x, 1] if x1 == x2
///          OP_EQUAL([x, x1, x2]) -> [x, 0] if x1 != x2
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_equal(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_EQUAL: Substitutes the top two items on the stack with ONE if they are equal, with ZERO otherwise");
    if current_stack.len() < TWO {
        error!("OP_EQUAL: Not enough elements on the stack");
        return false;
    }
    let x2 = current_stack.pop().unwrap();
    let x1 = current_stack.pop().unwrap();
    let item = match x1 == x2 {
        true => StackEntry::Num(ONE),
        false => StackEntry::Num(ZERO),
    };
    current_stack.push(item);
    true
}

/// OP_EQUALVERIFY: Computes OP_EQUAL and OP_VERIFY in sequence. Returns a bool.
///
/// Example: OP_EQUALVERIFY([x, x1, x2]) -> [x]  if x1 == x2
///          OP_EQUALVERIFY([x, x1, x2]) -> fail if x1 != x2
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_equalverify(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_EQUALVERIFY: Computes OP_EQUAL and OP_VERIFY in sequence");
    if current_stack.len() < TWO {
        error!("OP_EQUALVERIFY: Not enough elements on the stack");
        return false;
    }
    let x2 = current_stack.pop().unwrap();
    let x1 = current_stack.pop().unwrap();
    if x1 != x2 {
        error!("OP_EQUALVERIFY: The two top items are not equal");
        return false;
    }
    true
}

/*---- ARITHMETIC OPS ----*/

/// OP_1ADD: Adds ONE to the top item on the stack. Returns a bool.
///
/// Example: OP_1ADD([x, n]) -> [x, n+1]
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
    current_stack.push(StackEntry::Num(n.wrapping_add(ONE)));
    true
}

/// OP_1SUB: Subtracts ONE from the top item on the stack. Returns a bool.
///
/// Example: OP_1SUB([x, n]) -> [x, n-1]
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
    current_stack.push(StackEntry::Num(n.wrapping_sub(ONE)));
    true
}

/// OP_2MUL: Multiplies by TWO the top item on the stack. Returns a bool.
///
/// Example: OP_2MUL([x, n]) -> [x, n*2]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_2mul(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_2MUL: Multiplies by TWO the top item on the stack");
    if current_stack.is_empty() {
        error!("OP_2MUL: Not enough elements on the stack");
        return false;
    }
    let n = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    current_stack.push(StackEntry::Num(n.wrapping_mul(TWO)));
    true
}

/// OP_2DIV: Divides by TWO the top item on the stack. Returns a bool.
///
/// Example: OP_2DIV([x, n]) -> [x, n/2]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_2div(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_2DIV: Divides by TWO the top item on the stack");
    if current_stack.is_empty() {
        error!("OP_2DIV: Not enough elements on the stack");
        return false;
    }
    let n = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    current_stack.push(StackEntry::Num(n.wrapping_div(TWO)));
    true
}

/// OP_NOT: Substitutes the top item on the stack with ONE if it is equal to ZERO,
///         with ZERO otherwise. Returns a bool.
///
/// Example: OP_NOT([x, n]) -> [x, 1] if n == 0
///          OP_NOT([x, n]) -> [x, 0] if n != 0
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_not(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_NOT: Substitutes the top item on the stack with ONE if it is equal to ZERO, with ZERO otherwise");
    if current_stack.is_empty() {
        error!("OP_NOT: Not enough elements on the stack");
        return false;
    }
    let n = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    if n == ZERO {
        current_stack.push(StackEntry::Num(ONE));
    } else {
        current_stack.push(StackEntry::Num(ZERO));
    }
    true
}

/// OP_0NOTEQUAL: Substitutes the top item on the stack with ONE if it is not equal to ZERO,
///               with ZERO otherwise. Returns a bool.
///
/// Example: OP_0NOTEQUAL([x, n]) -> [x, 1] if n != 0
///          OP_0NOTEQUAL([x, n]) -> [x, 0] if n == 0
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_0notequal(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_0NOTEQUAL: Substitutes the top item on the stack with ONE if it is not equal to ZERO, with ZERO otherwise");
    if current_stack.is_empty() {
        error!("OP_0NOTEQUAL: Not enough elements on the stack");
        return false;
    }
    let n = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    if n != ZERO {
        current_stack.push(StackEntry::Num(ONE));
    } else {
        current_stack.push(StackEntry::Num(ZERO));
    }
    true
}

/// OP_ADD: Adds the top item to the second-to-top item on the stack. Returns a bool.
///
/// Example: OP_ADD([x, n1, n2]) -> [x, n1+n2]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_add(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_ADD: Adds the top item to the second-to-top item on the stack");
    if current_stack.len() < TWO {
        error!("OP_ADD: Not enough elements on the stack");
        return false;
    }
    let n2 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    let n1 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    current_stack.push(StackEntry::Num(n1.wrapping_add(n2)));
    true
}

/// OP_SUB: Subtracts the top item from the second-to-top item on the stack. Returns a bool.
///
/// Example: OP_SUB([x, n1, n2]) -> [x, n1-n2]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_sub(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_SUB: Subtracts the top item from the second-to-top item on the stack");
    if current_stack.len() < TWO {
        error!("OP_SUB: Not enough elements on the stack");
        return false;
    }
    let n2 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    let n1 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    current_stack.push(StackEntry::Num(n1.wrapping_sub(n2)));
    true
}

/// OP_MUL: Multiplies the second-to-top item by the top item on the stack. Returns a bool.
///
/// Example: OP_MUL([x, n1, n2]) -> [x, n1*n2]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_mul(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_MUL: Multiplies the second-to-top item by the top item on the stack");
    if current_stack.len() < TWO {
        error!("OP_MUL: Not enough elements on the stack");
        return false;
    }
    let n2 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    let n1 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    current_stack.push(StackEntry::Num(n1.wrapping_mul(n2)));
    true
}

/// OP_DIV: Divides the second-to-top item by the top item on the stack. Returns a bool.
///
/// Example: OP_DIV([x, n1, n2]) -> [x, n1/n2]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_div(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_DIV: Divides the second-to-top item by the top item on the stack");
    if current_stack.len() < TWO {
        error!("OP_DIV: Not enough elements on the stack");
        return false;
    }
    let n2 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    let n1 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    current_stack.push(StackEntry::Num(n1.wrapping_div(n2)));
    true
}

/// OP_MOD: Computes the remainder of the division of the second-to-top item by the top item on the stack. Returns a bool.
///
/// Example: OP_MOD([x, n1, n2]) -> [x, n1%n2]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_mod(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_MOD: Computes the remainder of the division of the second-to-top item by the top item on the stack");
    if current_stack.len() < TWO {
        error!("OP_MOD: Not enough elements on the stack");
        return false;
    }
    let n2 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    let n1 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    current_stack.push(StackEntry::Num(n1.wrapping_rem(n2)));
    true
}

/// OP_LSHIFT: Computes the left shift of the second-to-top item by the top item on the stack. Returns a bool.
///
/// Example: OP_LSHIFT([x, n1, n2]) -> [x, n1 << n2]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_lshift(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!(
        "OP_LSHIFT: Computes the left shift of the second-to-top item by the top item on the stack"
    );
    if current_stack.len() < TWO {
        error!("OP_LSHIFT: Not enough elements on the stack");
        return false;
    }
    let n2 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num as u32,
        _ => return false,
    };
    let n1 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    current_stack.push(StackEntry::Num(n1.wrapping_shl(n2)));
    true
}

/// OP_RSHIFT: Computes the right shift of the second-to-top item by the top item on the stack. Returns a bool.
///
/// Example: OP_RSHIFT([x, n1, n2]) -> [x, n1 >> n2]
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_rshift(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_RSHIFT: Computes the right shift of the second-to-top item by the top item on the stack");
    if current_stack.len() < TWO {
        error!("OP_RSHIFT: Not enough elements on the stack");
        return false;
    }
    let n2 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num as u32,
        _ => return false,
    };
    let n1 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    current_stack.push(StackEntry::Num(n1.wrapping_shr(n2)));
    true
}

/// OP_BOOLAND: Substitutes the top two items on the stack with ONE if they are both non-ZERO, with ZERO otherwise. Returns a bool.
///
/// Example: OP_BOOLAND([x, n1, n2]) -> [x, 1] if n1 != 0 and n2 != 0
///          OP_BOOLAND([x, n1, n2]) -> [x, 0] if n1 == 0 or n2 == 0
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_booland(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_BOOLAND: Substitutes the top two items on the stack with ONE if they are both non-ZERO, with ZERO otherwise");
    if current_stack.len() < TWO {
        error!("OP_BOOLAND: Not enough elements on the stack");
        return false;
    }
    let n2 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    let n1 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    let item = match n1 != ZERO && n2 != ZERO {
        true => StackEntry::Num(ONE),
        false => StackEntry::Num(ZERO),
    };
    current_stack.push(item);
    true
}

/// OP_BOOLOR: Substitutes the top two items on the stack with ONE if they are not both ZERO, with ZERO otherwise. Returns a bool.
///
/// Example: OP_BOOLOR([x, n1, n2]) -> [x, 1] if n1 != 0 or n2 != 0
///          OP_BOOLOR([x, n1, n2]) -> [x, 0] if n1 == 0 and n2 == 0
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_boolor(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_BOOLOR: Substitutes the top two items on the stack with ONE if they are not both ZERO, with ZERO otherwise");
    if current_stack.len() < TWO {
        error!("OP_BOOLOR: Not enough elements on the stack");
        return false;
    }
    let n2 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    let n1 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    let item = match n1 != ZERO || n2 != ZERO {
        true => StackEntry::Num(ONE),
        false => StackEntry::Num(ZERO),
    };
    current_stack.push(item);
    true
}

/// OP_NUMEQUAL: Substitutes the top two items on the stack with ONE if they are equal as numbers, with ZERO otherwise. Returns a bool.
///
/// Example: OP_NUMEQUAL([x, n1, n2]) -> [x, 1] if n1 == n2
///          OP_NUMEQUAL([x, n1, n2]) -> [x, 0] if n1 != n2
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_numequal(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_NUMEQUAL: Substitutes the top two items on the stack with ONE if they are equal as numbers, with ZERO otherwise");
    if current_stack.len() < TWO {
        error!("OP_NUMEQUAL: Not enough elements on the stack");
        return false;
    }
    let n2 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    let n1 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    let item = match n1 == n2 {
        true => StackEntry::Num(ONE),
        false => StackEntry::Num(ZERO),
    };
    current_stack.push(item);
    true
}

/// OP_NUMEQUALVERIFY: Computes OP_NUMEQUAL and OP_VERIFY in sequence. Returns a bool.
///
/// Example: OP_NUMEQUALVERIFY([x, n1, n2]) -> [x]  if n1 == n2
///          OP_NUMEQUALVERIFY([x, n1, n2]) -> fail if n1 != n2
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_numequalverify(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_NUMEQUALVERIFY: Computes OP_NUMEQUAL and OP_VERIFY in sequence");
    if current_stack.len() < TWO {
        error!("OP_NUMEQUALVERIFY: Not enough elements on the stack");
        return false;
    }
    let n2 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    let n1 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    if n1 != n2 {
        error!("OP_NUMEQUALVERIFY: The two top items are not equal");
        return false;
    }
    true
}

/// OP_NUMNOTEQUAL: Substitutes the top two items on the stack with ONE if they are not equal, with ZERO otherwise. Returns a bool.
///
/// Example: OP_NUMNOTEQUAL([x, n1, n2]) -> [x, 1] if n1 != n2
///          OP_NUMNOTEQUAL([x, n1, n2]) -> [x, 0] if n1 == n2
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_numnotequal(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_NUMNOTEQUAL: Substitutes the top two items on the stack with ONE if they are not equal, with ZERO otherwise");
    if current_stack.len() < TWO {
        error!("OP_NUMNOTEQUAL: Not enough elements on the stack");
        return false;
    }
    let n2 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    let n1 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    let item = match n1 != n2 {
        true => StackEntry::Num(ONE),
        false => StackEntry::Num(ZERO),
    };
    current_stack.push(item);
    true
}

/// OP_LESSTHAN: Substitutes the top two items on the stack with ONE if the second-to-top is less than the top item, with ZERO otherwise. Returns a bool.
///
/// Example: OP_LESSTHAN([x, n1, n2]) -> [x, 1] if n1 < n2
///          OP_LESSTHAN([x, n1, n2]) -> [x, 0] if n1 >= n2
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_lessthan(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_LESSTHAN: Substitutes the top two items on the stack with ONE if the second-to-top is less than the top item, with ZERO otherwise");
    if current_stack.len() < TWO {
        error!("OP_LESSTHAN: Not enough elements on the stack");
        return false;
    }
    let n2 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    let n1 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    let item = match n1 < n2 {
        true => StackEntry::Num(ONE),
        false => StackEntry::Num(ZERO),
    };
    current_stack.push(item);
    true
}

/// OP_GREATERTHAN: Substitutes the top two items on the stack with ONE if the second-to-top is greater than the top item, with ZERO otherwise. Returns a bool.
///
/// Example: OP_GREATERTHAN([x, n1, n2]) -> [x, 1] if n1 > n2
///          OP_GREATERTHAN([x, n1, n2]) -> [x, 0] if n1 <= n2
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_greaterthan(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_GREATERTHAN: Substitutes the top two items on the stack with ONE if the second-to-top is greater than the top item, with ZERO otherwise");
    if current_stack.len() < TWO {
        error!("OP_GREATERTHAN: Not enough elements on the stack");
        return false;
    }
    let n2 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    let n1 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    let item = match n1 > n2 {
        true => StackEntry::Num(ONE),
        false => StackEntry::Num(ZERO),
    };
    current_stack.push(item);
    true
}

/// OP_LESSTHANOREQUAL: Substitutes the top two items on the stack with ONE if the second-to-top is less than or equal to the top item, with ZERO otherwise. Returns a bool.
///
/// Example: OP_LESSTHANOREQUAL([x, n1, n2]) -> [x, 1] if n1 <= n2
///          OP_LESSTHANOREQUAL([x, n1, n2]) -> [x, 0] if n1 > n2
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_lessthanorequal(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_LESSTHANOREQUAL: Substitutes the top two items on the stack with ONE if the second-to-top is less than or equal to the top item, with ZERO otherwise");
    if current_stack.len() < TWO {
        error!("OP_LESSTHANOREQUAL: Not enough elements on the stack");
        return false;
    }
    let n2 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    let n1 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    let item = match n1 <= n2 {
        true => StackEntry::Num(ONE),
        false => StackEntry::Num(ZERO),
    };
    current_stack.push(item);
    true
}

/// OP_GREATERTHANOREQUAL: Substitutes the top two items on the stack with ONE if the second-to-top is greater than or equal to the top item, with ZERO otherwise. Returns a bool.
///
/// Example: OP_GREATERTHANOREQUAL([x, n1, n2]) -> [x, 1] if n1 >= n2
///          OP_GREATERTHANOREQUAL([x, n1, n2]) -> [x, 0] if n1 < n2
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_greaterthanorequal(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_GREATERTHANOREQUAL: Substitutes the top two items on the stack with ONE if the second-to-top is greater than or equal to the top item, with ZERO otherwise");
    if current_stack.len() < TWO {
        error!("OP_GREATERTHANOREQUAL: Not enough elements on the stack");
        return false;
    }
    let n2 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    let n1 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    let item = match n1 >= n2 {
        true => StackEntry::Num(ONE),
        false => StackEntry::Num(ZERO),
    };
    current_stack.push(item);
    true
}

/// OP_MIN: Substitutes the top two items on the stack with the minimum between the two. Returns a bool.
///
/// Example: OP_MIN([x, n1, n2]) -> [x, n1] if n1 <= n2
///          OP_MIN([x, n1, n2]) -> [x, n2] if n1 > n2
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_min(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_MIN: Substitutes the top two items on the stack with the minimum between the two");
    if current_stack.len() < TWO {
        error!("OP_MIN: Not enough elements on the stack");
        return false;
    }
    let n2 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    let n1 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    current_stack.push(StackEntry::Num(n1.min(n2)));
    true
}

/// OP_MAX: Substitutes the top two items on the stack with the maximum between the two. Returns a bool.
///
/// Example: OP_MAX([x, n1, n2]) -> [x, n1] if n1 >= n2
///          OP_MAX([x, n1, n2]) -> [x, n2] if n1 < n2
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_max(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_MAX: Substitutes the top two items on the stack with the maximum between the two");
    if current_stack.len() < TWO {
        error!("OP_MAX: Not enough elements on the stack");
        return false;
    }
    let n2 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    let n1 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    current_stack.push(StackEntry::Num(n1.max(n2)));
    true
}

/// OP_WITHIN: Substitutes the top three items on the stack with ONE if the third-to-top is greater or equal to the second-to-top and less than the top item,
///            with ZERO otherwise. Returns a bool.
///
/// Example: OP_WITHIN([x, n1, n2, n3]) -> [x, 1] if n1 >= n2 and n1 < n3
///          OP_WITHIN([x, n1, n2, n3]) -> [x, 0] if n1 < n2 or n1 >= n3
///
/// ### Arguments
///
/// * `current_stack`  - mutable reference to the current stack
pub fn op_within(current_stack: &mut Vec<StackEntry>) -> bool {
    trace!("OP_WITHIN: Substitutes the top three items on the stack with ONE if the third-to-top is greater or equal to the second-to-top and less than the top item, with ZERO otherwise");
    if current_stack.len() < THREE {
        error!("OP_WITHIN: Not enough elements on the stack");
        return false;
    }
    let n3 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    let n2 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    let n1 = match current_stack.pop().unwrap() {
        StackEntry::Num(num) => num,
        _ => return false,
    };
    let item = match n1 >= n2 && n1 < n3 {
        true => StackEntry::Num(ONE),
        false => StackEntry::Num(ZERO),
    };
    current_stack.push(item);
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
        assert_eq!(current_alt_stack, v2);
        /// op_toaltstack([], [1]) -> fail
        let mut current_stack: Vec<StackEntry> = Vec::new();
        let mut current_alt_stack: Vec<StackEntry> = Vec::new();
        current_alt_stack.push(StackEntry::Num(1));
        let b = op_toaltstack(&mut current_stack, &mut current_alt_stack);
        assert!(!b)
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
        assert_eq!(current_alt_stack, v2);
        /// op_fromaltstack([1], []) -> fail
        let mut current_stack: Vec<StackEntry> = Vec::new();
        let mut current_alt_stack: Vec<StackEntry> = Vec::new();
        current_stack.push(StackEntry::Num(1));
        let b = op_fromaltstack(&mut current_stack, &mut current_alt_stack);
        assert!(!b)
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
        assert_eq!(current_stack, v);
        /// op_2drop([1]) -> fail
        let mut current_stack: Vec<StackEntry> = Vec::new();
        current_stack.push(StackEntry::Num(1));
        let b = op_2drop(&mut current_stack);
        assert!(!b)
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
        assert_eq!(current_stack, v);
        /// op_2dup([1]) -> fail
        let mut current_stack: Vec<StackEntry> = Vec::new();
        current_stack.push(StackEntry::Num(1));
        let b = op_2dup(&mut current_stack);
        assert!(!b)
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
        assert_eq!(current_stack, v);
        /// op_3dup([1,2]) -> fail
        let mut current_stack: Vec<StackEntry> = Vec::new();
        current_stack.push(StackEntry::Num(1));
        current_stack.push(StackEntry::Num(2));
        let b = op_3dup(&mut current_stack);
        assert!(!b)
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
        assert_eq!(current_stack, v);
        /// op_2over([1,2,3]) -> fail
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=3 {
            current_stack.push(StackEntry::Num(i));
        }
        let b = op_2over(&mut current_stack);
        assert!(!b)
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
        assert_eq!(current_stack, v);
        /// op_2rot([1,2,3,4,5]) -> fail
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=5 {
            current_stack.push(StackEntry::Num(i));
        }
        let b = op_2rot(&mut current_stack);
        assert!(!b)
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
        assert_eq!(current_stack, v);
        /// op_2swap([1,2,3]) -> fail
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=3 {
            current_stack.push(StackEntry::Num(i));
        }
        let b = op_2swap(&mut current_stack);
        assert!(!b)
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
        assert_eq!(current_stack, v);
        /// op_ifdup([]) -> fail
        let mut current_stack: Vec<StackEntry> = Vec::new();
        let b = op_2swap(&mut current_stack);
        assert!(!b)
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
        assert_eq!(current_stack, v);
        /// op_depth([]) -> [0]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
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
        assert_eq!(current_stack, v);
        /// op_drop([]) -> fail
        let mut current_stack: Vec<StackEntry> = Vec::new();
        let b = op_drop(&mut current_stack);
        assert!(!b)
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
        assert_eq!(current_stack, v);
        /// op_dup([]) -> fail
        let mut current_stack: Vec<StackEntry> = Vec::new();
        let b = op_dup(&mut current_stack);
        assert!(!b)
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
        assert_eq!(current_stack, v);
        /// op_nip([1]) -> fail
        let mut current_stack: Vec<StackEntry> = Vec::new();
        current_stack.push(StackEntry::Num(1));
        let b = op_nip(&mut current_stack);
        assert!(!b)
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
        assert_eq!(current_stack, v);
        /// op_over([1]) -> fail
        let mut current_stack: Vec<StackEntry> = Vec::new();
        current_stack.push(StackEntry::Num(1));
        let b = op_over(&mut current_stack);
        assert!(!b)
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
        assert_eq!(current_stack, v);
        /// op_pick([1,2,3,4,5,6,0]) -> [1,2,3,4,5,6,6]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(6));
        op_pick(&mut current_stack);
        assert_eq!(current_stack, v);
        /// op_pick([1]) -> fail
        let mut current_stack: Vec<StackEntry> = Vec::new();
        current_stack.push(StackEntry::Num(1));
        let b = op_pick(&mut current_stack);
        assert!(!b);
        /// op_pick([1,1]) -> fail
        let mut current_stack: Vec<StackEntry> = Vec::new();
        current_stack.push(StackEntry::Num(1));
        current_stack.push(StackEntry::Num(1));
        let b = op_pick(&mut current_stack);
        assert!(!b)
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
        assert_eq!(current_stack, v);
        /// op_roll([1,2,3,4,5,6,0]) -> [1,2,3,4,5,6]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            v.push(StackEntry::Num(i));
        }
        op_roll(&mut current_stack);
        assert_eq!(current_stack, v);
        /// op_roll([1]) -> fail
        let mut current_stack: Vec<StackEntry> = Vec::new();
        current_stack.push(StackEntry::Num(1));
        let b = op_roll(&mut current_stack);
        assert!(!b);
        /// op_roll([1,1]) -> fail
        let mut current_stack: Vec<StackEntry> = Vec::new();
        current_stack.push(StackEntry::Num(1));
        current_stack.push(StackEntry::Num(1));
        let b = op_roll(&mut current_stack);
        assert!(!b)
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
        assert_eq!(current_stack, v);
        /// op_rot([1,2]) -> fail
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=2 {
            current_stack.push(StackEntry::Num(i));
        }
        let b = op_rot(&mut current_stack);
        assert!(!b)
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
        assert_eq!(current_stack, v);
        /// op_swap([1]) -> fail
        let mut current_stack: Vec<StackEntry> = Vec::new();
        current_stack.push(StackEntry::Num(1));
        let b = op_swap(&mut current_stack);
        assert!(!b)
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
        assert_eq!(current_stack, v);
        /// op_tuck([1]) -> fail
        let mut current_stack: Vec<StackEntry> = Vec::new();
        current_stack.push(StackEntry::Num(1));
        let b = op_tuck(&mut current_stack);
        assert!(!b)
    }

    /*---- SPLICE OPS ----*/

    #[test]
    /// Test OP_CAT
    fn test_cat() {
        /// op_cat([1,2,3,4,5,6,"hello","world"]) -> [1,2,3,4,5,6,"helloworld"]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Bytes("hello".to_string()));
        current_stack.push(StackEntry::Bytes("world".to_string()));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Bytes("helloworld".to_string()));
        op_cat(&mut current_stack);
        assert_eq!(current_stack, v);
        /// op_cat([1,2,3,4,5,6,"hello",""]) -> [1,2,3,4,5,6,"hello"]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Bytes("hello".to_string()));
        current_stack.push(StackEntry::Bytes("".to_string()));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Bytes("hello".to_string()));
        op_cat(&mut current_stack);
        assert_eq!(current_stack, v);
        /// op_cat([1,2,3,4,5,6,"a","a"*520]) -> fail
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Bytes('a'.to_string()));
        let mut s = String::new();
        for i in 1..=MAX_SCRIPT_ELEMENT_SIZE {
            s.push('a');
        }
        current_stack.push(StackEntry::Bytes(s.to_string()));
        let b = op_cat(&mut current_stack);
        assert!(!b);
        /// op_cat(["hello"]) -> fail
        let mut current_stack: Vec<StackEntry> = Vec::new();
        current_stack.push(StackEntry::Bytes("hello".to_string()));
        let mut s = String::new();
        let b = op_cat(&mut current_stack);
        assert!(!b);
    }

    #[test]
    /// Test OP_SUBSTR
    fn test_substr() {
        /// op_substr([1,2,3,4,5,6,"hello",1,2]) -> [1,2,3,4,5,6,"el"]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Bytes("hello".to_string()));
        current_stack.push(StackEntry::Num(1));
        current_stack.push(StackEntry::Num(2));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Bytes("el".to_string()));
        op_substr(&mut current_stack);
        assert_eq!(current_stack, v);
        /// op_substr([1,2,3,4,5,6,"hello",0,0]) -> [1,2,3,4,5,6,""]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Bytes("hello".to_string()));
        current_stack.push(StackEntry::Num(0));
        current_stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Bytes("".to_string()));
        op_substr(&mut current_stack);
        assert_eq!(current_stack, v);
        /// op_substr([1,2,3,4,5,6,"hello",5,1]) -> fail
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Bytes("hello".to_string()));
        current_stack.push(StackEntry::Num(5));
        current_stack.push(StackEntry::Num(1));
        let b = op_substr(&mut current_stack);
        assert!(!b);
        /// op_substr([1,2,3,4,5,6,"hello",1,5]) -> fail
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Bytes("hello".to_string()));
        current_stack.push(StackEntry::Num(1));
        current_stack.push(StackEntry::Num(5));
        let b = op_substr(&mut current_stack);
        assert!(!b);
        /// op_substr(["hello",1]) -> fail
        let mut current_stack: Vec<StackEntry> = Vec::new();
        current_stack.push(StackEntry::Bytes("hello".to_string()));
        current_stack.push(StackEntry::Num(1));
        let b = op_substr(&mut current_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_LEFT
    fn test_left() {
        /// op_left([1,2,3,4,5,6,"hello",2]) -> [1,2,3,4,5,6,"he"]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Bytes("hello".to_string()));
        current_stack.push(StackEntry::Num(2));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Bytes("he".to_string()));
        op_left(&mut current_stack);
        assert_eq!(current_stack, v);
        /// op_left([1,2,3,4,5,6,"hello",0]) -> [1,2,3,4,5,6,""]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Bytes("hello".to_string()));
        current_stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Bytes("".to_string()));
        op_left(&mut current_stack);
        assert_eq!(current_stack, v);
        /// op_substr([1,2,3,4,5,6,"hello",5]) -> [1,2,3,4,5,6,"hello"]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Bytes("hello".to_string()));
        current_stack.push(StackEntry::Num(5));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Bytes("hello".to_string()));
        op_left(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_RIGHT
    fn test_right() {
        /// op_right([1,2,3,4,5,6,"hello",0]) -> [1,2,3,4,5,6,"hello"]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Bytes("hello".to_string()));
        current_stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Bytes("hello".to_string()));
        op_right(&mut current_stack);
        assert_eq!(current_stack, v);
        /// op_right([1,2,3,4,5,6,"hello",2]) -> [1,2,3,4,5,6,"llo"]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Bytes("hello".to_string()));
        current_stack.push(StackEntry::Num(2));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Bytes("llo".to_string()));
        op_right(&mut current_stack);
        assert_eq!(current_stack, v);
        /// op_right([1,2,3,4,5,6,"hello",5]) -> [1,2,3,4,5,6,""]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Bytes("hello".to_string()));
        current_stack.push(StackEntry::Num(5));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Bytes("".to_string()));
        op_right(&mut current_stack);
        assert_eq!(current_stack, v);
    }

    #[test]
    /// Test OP_SIZE
    fn test_size() {
        /// op_size([1,2,3,4,5,6,"hello"]) -> [1,2,3,4,5,6,5]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Bytes("hello".to_string()));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(5));
        op_size(&mut current_stack);
        assert_eq!(current_stack, v);
        /// op_size([1,2,3,4,5,6,""]) -> [1,2,3,4,5,6,0]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Bytes("".to_string()));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(0));
        op_size(&mut current_stack);
        assert_eq!(current_stack, v);
        /// op_size([]) -> fail
        let mut current_stack: Vec<StackEntry> = Vec::new();
        let b = op_size(&mut current_stack);
        assert!(!b)
    }

    /*---- BITWISE LOGIC OPS ----*/

    #[test]
    /// Test OP_INVERT
    fn test_invert() {
        /// op_invert([1,2,3,4,5,6,0]) -> [1,2,3,4,5,6,usize::MAX]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(usize::MAX));
        op_invert(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_AND
    fn test_and() {
        /// op_and([1,2,3,4,5,6]) -> [1,2,3,4,4]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(4));
        op_and(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_OR
    fn test_or() {
        /// op_or([1,2,3,4,5,6]) -> [1,2,3,4,7]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(7));
        op_or(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_XOR
    fn test_xor() {
        /// op_xor([1,2,3,4,5,6]) -> [1,2,3,4,3]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(3));
        op_xor(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_EQUAL
    fn test_equal() {
        /// op_equal([1,2,3,4,5,6,"hello","hello"]) -> [1,2,3,4,5,6,1]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Bytes("hello".to_string()));
        current_stack.push(StackEntry::Bytes("hello".to_string()));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(1));
        op_equal(&mut current_stack);
        assert_eq!(current_stack, v);
        /// op_equal([1,2,3,4,5,6,"hello"]) -> [1,2,3,4,5,0]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Bytes("hello".to_string()));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=5 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(0));
        op_equal(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_EQUALVERIFY
    fn test_equalverify() {
        /// op_equalverify([1,2,3,4,5,6,"hello","hello"]) -> [1,2,3,4,5,6]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Bytes("hello".to_string()));
        current_stack.push(StackEntry::Bytes("hello".to_string()));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            v.push(StackEntry::Num(i));
        }
        op_equalverify(&mut current_stack);
        assert_eq!(current_stack, v);
        /// op_equalverify([1,2,3,4,5,6,"hello"]) -> fail
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Bytes("hello".to_string()));
        let b = op_equalverify(&mut current_stack);
        assert!(!b)
    }

    /*---- ARITHMETIC OPS ----*/

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

    #[test]
    /// Test OP_2MUL
    fn test_2mul() {
        /// op_2mul([1,2,3,4,5,6]) -> [1,2,3,4,5,12]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=5 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(12));
        op_2mul(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_2DIV
    fn test_2div() {
        /// op_2div([1,2,3,4,5,6]) -> [1,2,3,4,5,3]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=5 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(3));
        op_2div(&mut current_stack);
        assert_eq!(current_stack, v);
        /// op_2div([1,2,3,4,5]) -> [1,2,3,4,2]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=5 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(2));
        op_2div(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_NOT
    fn test_not() {
        /// op_not([1,2,3,4,5,0]) -> [1,2,3,4,5,1]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=5 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=5 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(1));
        op_not(&mut current_stack);
        assert_eq!(current_stack, v);
        /// op_not([1,2,3,4,5,6]) -> [1,2,3,4,5,0]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=5 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(0));
        op_not(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_0NOTEQUAL
    fn test_0notequal() {
        /// op_0notequal([1,2,3,4,5,6]) -> [1,2,3,4,5,1]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=5 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(1));
        op_0notequal(&mut current_stack);
        assert_eq!(current_stack, v);
        /// op_0notequal([1,2,3,4,5,0]) -> [1,2,3,4,5,0]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=5 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=5 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(0));
        op_0notequal(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_ADD
    fn test_add() {
        /// op_add([1,2,3,4,5,6]) -> [1,2,3,4,11]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(11));
        op_add(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_SUB
    fn test_sub() {
        /// op_sub([1,2,3,4,6,5]) -> [1,2,3,4,1]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=4 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Num(6));
        current_stack.push(StackEntry::Num(5));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(1));
        op_sub(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_MUL
    fn test_mul() {
        /// op_mul([1,2,3,4,5,6]) -> [1,2,3,4,30]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(30));
        op_mul(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_DIV
    fn test_div() {
        /// op_div([1,2,3,4,5,6,3]) -> [1,2,3,4,5,2]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Num(3));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=5 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(2));
        op_div(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_MOD
    fn test_mod() {
        /// op_mod([1,2,3,4,6,4]) -> [1,2,3,4,2]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=4 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Num(6));
        current_stack.push(StackEntry::Num(4));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(2));
        op_mod(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_LSHIFT
    fn test_lshift() {
        /// op_lshift([1,2,3,4,5,6,1]) -> [1,2,3,4,5,12]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Num(1));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=5 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(12));
        op_lshift(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_RSHIFT
    fn test_rshift() {
        /// op_rshift([1,2,3,4,5,6,1]) -> [1,2,3,4,5,3]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Num(1));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=5 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(3));
        op_rshift(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_BOOLAND
    fn test_booland() {
        /// op_booland([1,2,3,4,5,6]) -> [1,2,3,4,1]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(1));
        op_booland(&mut current_stack);
        assert_eq!(current_stack, v);
        /// op_booland([1,2,3,4,5,6,0]) -> [1,2,3,4,5,0]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=5 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(0));
        op_booland(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_BOOLOR
    fn test_boolor() {
        /// op_boolor([1,2,3,4,5,6,0]) -> [1,2,3,4,5,1]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=5 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(1));
        op_boolor(&mut current_stack);
        assert_eq!(current_stack, v);
        /// op_boolor([1,2,3,4,5,0,0]) -> [1,2,3,4,5,0]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=5 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Num(0));
        current_stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=5 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(0));
        op_boolor(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_NUMEQUAL
    fn test_numequal() {
        /// op_numequal([1,2,3,4,5,6,6]) -> [1,2,3,4,5,1]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Num(6));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=5 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(1));
        op_numequal(&mut current_stack);
        assert_eq!(current_stack, v);
        /// op_numequal([1,2,3,4,5,6]) -> [1,2,3,4,0]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(0));
        op_numequal(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_NUMEQUALVERIFY
    fn test_numequalverify() {
        /// op_numequalverify([1,2,3,4,5,6,6]) -> [1,2,3,4,5]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Num(6));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=5 {
            v.push(StackEntry::Num(i));
        }
        op_numequalverify(&mut current_stack);
        assert_eq!(current_stack, v);
        /// op_numequalverify([1,2,3,4,5,6]) -> fail
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let b = op_numequalverify(&mut current_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_NUMNOTEQUAL
    fn test_numnotequal() {
        /// op_numnotequal([1,2,3,4,5,6,6]) -> [1,2,3,4,5,0]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Num(6));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=5 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(0));
        op_numnotequal(&mut current_stack);
        assert_eq!(current_stack, v);
        /// op_numnotequal([1,2,3,4,5,6]) -> [1,2,3,4,1]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(1));
        op_numnotequal(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_LESSTHAN
    fn test_lessthan() {
        /// op_lessthan([1,2,3,4,5,6]) -> [1,2,3,4,1]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(1));
        op_lessthan(&mut current_stack);
        assert_eq!(current_stack, v);
        /// op_lessthan([1,2,3,4,6,5]) -> [1,2,3,4,0]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=4 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Num(6));
        current_stack.push(StackEntry::Num(5));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(0));
        op_lessthan(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_GREATERTHAN
    fn test_greaterthan() {
        /// op_greaterthan([1,2,3,4,5,6]) -> [1,2,3,4,0]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(0));
        op_greaterthan(&mut current_stack);
        assert_eq!(current_stack, v);
        /// op_greaterthan([1,2,3,4,6,5]) -> [1,2,3,4,1]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=4 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Num(6));
        current_stack.push(StackEntry::Num(5));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(1));
        op_greaterthan(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_LESSTHANOREQUAL
    fn test_lessthanorequal() {
        /// test_lessthanorequal([1,2,3,4,6,6]) -> [1,2,3,4,1]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=4 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Num(6));
        current_stack.push(StackEntry::Num(6));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(1));
        op_lessthanorequal(&mut current_stack);
        assert_eq!(current_stack, v);
        /// op_lessthanorequal([1,2,3,4,6,5]) -> [1,2,3,4,0]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=4 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Num(6));
        current_stack.push(StackEntry::Num(5));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(0));
        op_lessthanorequal(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_GREATERTHANOREQUAL
    fn test_greaterthanorequal() {
        /// op_greaterthanorequal([1,2,3,4,5,6]) -> [1,2,3,4,0]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(0));
        op_greaterthan(&mut current_stack);
        assert_eq!(current_stack, v);
        /// op_greaterthanorequal([1,2,3,4,6,6]) -> [1,2,3,4,1]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=4 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Num(6));
        current_stack.push(StackEntry::Num(6));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(1));
        op_greaterthanorequal(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_MIN
    fn test_min() {
        /// op_min([1,2,3,4,5,6]) -> [1,2,3,4,5]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=5 {
            v.push(StackEntry::Num(i));
        }
        op_min(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_MAX
    fn test_max() {
        /// op_max([1,2,3,4,5,6]) -> [1,2,3,4,6]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(6));
        op_max(&mut current_stack);
        assert_eq!(current_stack, v)
    }

    #[test]
    /// Test OP_WITHIN
    fn test_within() {
        /// op_within([1,2,3,5,4,6]) -> [1,2,3,1]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=3 {
            current_stack.push(StackEntry::Num(i));
        }
        current_stack.push(StackEntry::Num(5));
        current_stack.push(StackEntry::Num(4));
        current_stack.push(StackEntry::Num(6));
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=3 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(1));
        op_within(&mut current_stack);
        assert_eq!(current_stack, v);
        /// op_within([1,2,3,4,5,6]) -> [1,2,3,0]
        let mut current_stack: Vec<StackEntry> = Vec::new();
        for i in 1..=6 {
            current_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = Vec::new();
        for i in 1..=3 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(0));
        op_within(&mut current_stack);
        assert_eq!(current_stack, v)
    }
}
