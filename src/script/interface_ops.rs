#![allow(unused)]
use crate::constants::*;
use crate::crypto::sha3_256;
use crate::crypto::sign_ed25519 as sign;
use crate::crypto::sign_ed25519::{PublicKey, Signature};
use crate::primitives::asset::{Asset, TokenAmount};
use crate::primitives::transaction::*;
use crate::script::lang::Script;
use crate::script::{OpCodes, StackEntry};
use crate::utils::error_utils::*;
use crate::utils::transaction_utils::{
    construct_address, construct_address_temp, construct_address_v0,
};
use bincode::serialize;
use bytes::Bytes;
use hex::encode;
use std::collections::BTreeMap;
use tracing::{debug, error, info, trace};

/*---- CONSTANTS OPS ----*/

/// OP_0: Pushes the number ZERO onto the stack. Returns a bool.
///
/// Example: OP_0([]) -> [0]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_0(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, burgir) = (OP0, OP0_DESC);
    trace(op, burgir);
    interpreter_stack.push(StackEntry::Num(ZERO));
    true
}

/// OP_1: Pushes the number ONE onto the stack. Returns a bool.
///
/// Example: OP_1([]) -> [1]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_1(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OP1, OP1_DESC);
    trace(op, desc);
    interpreter_stack.push(StackEntry::Num(ONE));
    true
}

/// OP_2: Pushes the number TWO onto the stack. Returns a bool.
///
/// Example: OP_2([]) -> [2]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_2(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OP2, OP2_DESC);
    trace(op, desc);
    interpreter_stack.push(StackEntry::Num(TWO));
    true
}

/// OP_3: Pushes the number THREE onto the stack. Returns a bool.
///
/// Example: OP_3([]) -> [3]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_3(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OP3, OP3_DESC);
    trace(op, desc);
    interpreter_stack.push(StackEntry::Num(THREE));
    true
}

/// OP_4: Pushes the number FOUR onto the stack. Returns a bool.
///
/// Example: OP_4([]) -> [4]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_4(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OP4, OP4_DESC);
    trace(op, desc);
    interpreter_stack.push(StackEntry::Num(FOUR));
    true
}

/// OP_5: Pushes the number FIVE onto the stack. Returns a bool.
///
/// Example: OP_5([]) -> [5]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_5(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OP5, OP5_DESC);
    trace(op, desc);
    interpreter_stack.push(StackEntry::Num(FIVE));
    true
}

/// OP_6: Pushes the number SIX onto the stack. Returns a bool.
///
/// Example: OP_6([]) -> [6]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_6(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OP6, OP6_DESC);
    trace(op, desc);
    interpreter_stack.push(StackEntry::Num(SIX));
    true
}

/// OP_7: Pushes the number SEVEN onto the stack. Returns a bool.
///
/// Example: OP_7([]) -> [7]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_7(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OP7, OP7_DESC);
    trace(op, desc);
    interpreter_stack.push(StackEntry::Num(SEVEN));
    true
}

/// OP_8: Pushes the number EIGHT onto the stack. Returns a bool.
///
/// Example: OP_8([]) -> [8]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_8(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OP8, OP8_DESC);
    trace(op, desc);
    interpreter_stack.push(StackEntry::Num(EIGHT));
    true
}

/// OP_9: Pushes the number NINE onto the stack. Returns a bool.
///
/// Example: OP_9([]) -> [9]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_9(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OP9, OP9_DESC);
    trace(op, desc);
    interpreter_stack.push(StackEntry::Num(NINE));
    true
}

/// OP_10: Pushes the number TEN onto the stack. Returns a bool.
///
/// Example: OP_10([]) -> [10]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_10(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OP10, OP10_DESC);
    trace(op, desc);
    interpreter_stack.push(StackEntry::Num(TEN));
    true
}

/// OP_11: Pushes the number ELEVEN onto the stack. Returns a bool.
///
/// Example: OP_11([]) -> [11]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_11(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OP11, OP11_DESC);
    trace(op, desc);
    interpreter_stack.push(StackEntry::Num(ELEVEN));
    true
}

/// OP_12: Pushes the number TWELVE onto the stack. Returns a bool.
///
/// Example: OP_12([]) -> [12]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_12(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OP12, OP12_DESC);
    trace(op, desc);
    interpreter_stack.push(StackEntry::Num(TWELVE));
    true
}

/// OP_13: Pushes the number THIRTEEN onto the stack. Returns a bool.
///
/// Example: OP_13([]) -> [13]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_13(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OP13, OP13_DESC);
    trace(op, desc);
    interpreter_stack.push(StackEntry::Num(THIRTEEN));
    true
}

/// OP_14: Pushes the number FOURTEEN onto the stack. Returns a bool.
///
/// Example: OP_14([]) -> [14]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_14(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OP14, OP14_DESC);
    trace(op, desc);
    interpreter_stack.push(StackEntry::Num(FOURTEEN));
    true
}

/// OP_15: Pushes the number FIFTEEN onto the stack. Returns a bool.
///
/// Example: OP_15([]) -> [15]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_15(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OP15, OP15_DESC);
    trace(op, desc);
    interpreter_stack.push(StackEntry::Num(FIFTEEN));
    true
}

/// OP_16: Pushes the number SIXTEEN onto the stack. Returns a bool.
///
/// Example: OP_16([]) -> [16]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_16(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OP16, OP16_DESC);
    trace(op, desc);
    interpreter_stack.push(StackEntry::Num(SIXTEEN));
    true
}

/*---- STACK OPS ----*/

/// OP_TOALTSTACK: Moves the top item from the main stack to the top of the alt stack. Returns a bool.
///
/// Example: OP_TOALTSTACK([x], []) -> [], [x]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
/// * `interpreter_alt_stack`  - mutable reference to the interpreter alt stack
pub fn op_toaltstack(
    interpreter_stack: &mut Vec<StackEntry>,
    interpreter_alt_stack: &mut Vec<StackEntry>,
) -> bool {
    let (op, desc) = (OPTOALTSTACK, OPTOALTSTACK_DESC);
    trace(op, desc);
    match interpreter_stack.pop() {
        Some(x) => interpreter_alt_stack.push(x),
        _ => {
            error_num_items(op);
            return false;
        }
    };
    true
}

/// OP_FROMALTSTACK: Moves the top item from the alt stack to the top of the main stack. Returns a bool.
///
/// Example: OP_FROMALTSTACK([], [x]) -> [x], []
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
/// * `interpreter_alt_stack`  - mutable reference to the interpreter alt stack
pub fn op_fromaltstack(
    interpreter_stack: &mut Vec<StackEntry>,
    interpreter_alt_stack: &mut Vec<StackEntry>,
) -> bool {
    let (op, desc) = (OPFROMALTSTACK, OPFROMALTSTACK_DESC);
    trace(op, desc);
    match interpreter_alt_stack.pop() {
        Some(x) => interpreter_stack.push(x),
        _ => {
            error_num_items(op);
            return false;
        }
    };
    true
}

/// OP_2DROP: Removes the top two items from the stack. Returns a bool.
///
/// Example: OP_2DROP([x1, x2]) -> []
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_2drop(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OP2DROP, OP2DROP_DESC);
    trace(op, desc);
    let len = interpreter_stack.len();
    if len < TWO {
        error_num_items(op);
        return false;
    }
    interpreter_stack.drain(len - TWO..);
    true
}

/// OP_2DUP: Duplicates the top two items on the stack. Returns a bool.
///
/// Example: OP_2DUP([x1, x2]) -> [x1, x2, x1, x2]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_2dup(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OP2DUP, OP2DUP_DESC);
    trace(op, desc);
    let len = interpreter_stack.len();
    if len < TWO {
        error_num_items(op);
        return false;
    }
    let last_two = interpreter_stack[len - TWO..].to_vec();
    interpreter_stack.extend_from_slice(&last_two);
    true
}

/// OP_3DUP: Duplicates the top three items on the stack. Returns a bool.
///
/// Example: OP_3DUP([x1, x2, x3]) -> [x1, x2, x3, x1, x2, x3]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_3dup(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OP3DUP, OP3DUP_DESC);
    trace(op, desc);
    let len = interpreter_stack.len();
    if len < THREE {
        error_num_items(op);
        return false;
    }
    let last_three = interpreter_stack[len - THREE..].to_vec();
    interpreter_stack.extend_from_slice(&last_three);
    true
}

/// OP_2OVER: Copies the second-to-top pair of items to the top of the stack. Returns a bool.
///
/// Example: OP_2OVER([x1, x2, x3, x4]) -> [x1, x2, x3, x4, x1, x2]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_2over(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OP2OVER, OP2OVER_DESC);
    trace(op, desc);
    let len = interpreter_stack.len();
    if len < FOUR {
        error_num_items(op);
        return false;
    }
    let items = interpreter_stack[len - FOUR..len - TWO].to_vec();
    interpreter_stack.extend_from_slice(&items);
    true
}

/// OP_2ROT: Moves the third-to-top pair of items to the top of the stack. Returns a bool.
///
/// Example: OP_2ROT([x1, x2, x3, x4, x5, x6]) -> [x3, x4, x5, x6, x1, x2]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_2rot(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OP2ROT, OP2ROT_DESC);
    trace(op, desc);
    let len = interpreter_stack.len();
    if len < SIX {
        error_num_items(op);
        return false;
    }
    let items = interpreter_stack[len - SIX..len - FOUR].to_vec();
    interpreter_stack.drain(len - SIX..len - FOUR);
    interpreter_stack.extend_from_slice(&items);
    true
}

/// OP_2SWAP: Swaps the top two pairs of items on the stack. Returns a bool.
///
/// Example: OP_2SWAP([x1, x2, x3, x4]) -> [x3, x4, x1, x2]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_2swap(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OP2SWAP, OP2SWAP_DESC);
    trace(op, desc);
    let len = interpreter_stack.len();
    if len < FOUR {
        error_num_items(op);
        return false;
    }
    interpreter_stack.swap(len - FOUR, len - TWO);
    interpreter_stack.swap(len - THREE, len - ONE);
    true
}

/// OP_IFDUP: Duplicates the top item on the stack if it is not ZERO. Returns a bool.
///
/// Example: OP_IFDUP([x]) -> [x, x] if x != 0
///          OP_IFDUP([x]) -> [x]    if x == 0
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_ifdup(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPIFDUP, OPIFDUP_DESC);
    trace(op, desc);
    match interpreter_stack.last().cloned() {
        Some(x) => {
            if x != StackEntry::Num(ZERO) {
                interpreter_stack.push(x);
            }
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    true
}

/// OP_DEPTH: Pushes the stack size onto the stack. Returns a bool.
///
/// Example: OP_DEPTH([x1, x2, x3, x4]) -> [x1, x2, x3, x4, 4]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_depth(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPDEPTH, OPDEPTH_DESC);
    trace(op, desc);
    interpreter_stack.push(StackEntry::Num(interpreter_stack.len()));
    true
}

/// OP_DROP: Removes the top item from the stack. Returns a bool.
///
/// Example: OP_DROP([x]) -> []
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_drop(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPDROP, OPDROP_DESC);
    trace(op, desc);
    match interpreter_stack.pop() {
        Some(x) => (),
        _ => {
            error_num_items(op);
            return false;
        }
    };
    true
}

/// OP_DUP: Duplicates the top item on the stack. Returns a bool.
///
/// Example: OP_DUP([x]) -> [x, x]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_dup(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPDUP, OPDUP_DESC);
    trace(op, desc);
    match interpreter_stack.last().cloned() {
        Some(x) => interpreter_stack.push(x),
        _ => {
            error_num_items(op);
            return false;
        }
    };
    true
}

/// OP_NIP: Removes the second-to-top item from the stack. Returns a bool.
///
/// Example: OP_NIP([x1, x2]) -> [x2]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_nip(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPNIP, OPNIP_DESC);
    trace(op, desc);
    let len = interpreter_stack.len();
    if len < TWO {
        error_num_items(op);
        return false;
    }
    interpreter_stack.remove(len - TWO);
    true
}

/// OP_OVER: Copies the second-to-top item to the top of the stack. Returns a bool.
///
/// Example: OP_OVER([x1, x2]) -> [x1, x2, x1]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_over(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPOVER, OPOVER_DESC);
    trace(op, desc);
    let len = interpreter_stack.len();
    if len < TWO {
        error_num_items(op);
        return false;
    }
    let x1 = interpreter_stack[len - TWO].clone();
    interpreter_stack.push(x1);
    true
}

/// OP_PICK: Copies the (n+1)th-to-top item to the top of the stack,
///          where n is the top item on the stack. Returns a bool.
///
/// Example: OP_PICK([x, x2, x1, x0, 3]) -> [x, x2, x1, x0, x]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_pick(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPPICK, OPPICK_DESC);
    trace(op, desc);
    let n = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let len = interpreter_stack.len();
    if n >= len {
        error_item_index(op);
        return false;
    }
    let x = interpreter_stack[len - ONE - n].clone();
    interpreter_stack.push(x);
    true
}

/// OP_ROLL: Moves the (n+1)th-to-top item to the top of the stack,
///          where n is the top item on the stack. Returns a bool.
///
/// Example: OP_ROLL([x, x2, x1, x0, 3]) -> [x2, x1, x0, x]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_roll(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPROLL, OPROLL_DESC);
    trace(op, desc);
    let n = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let len = interpreter_stack.len();
    if n >= len {
        error_item_index(op);
        return false;
    }
    let x = interpreter_stack[len - ONE - n].clone();
    interpreter_stack.remove(len - ONE - n);
    interpreter_stack.push(x);
    true
}

/// OP_ROT: Moves the third-to-top item to the top of the stack. Returns a bool.
///
/// Example: OP_ROT([x1, x2, x3]) -> [x2, x3, x1]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_rot(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPROT, OPROT_DESC);
    trace(op, desc);
    let len = interpreter_stack.len();
    if len < THREE {
        error_num_items(op);
        return false;
    }
    interpreter_stack.swap(len - THREE, len - TWO);
    interpreter_stack.swap(len - TWO, len - ONE);
    true
}

/// OP_SWAP: Swaps the top two items on the stack. Returns a bool.
///
/// Example: OP_SWAP([x1, x2]) -> [x2, x1]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_swap(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPSWAP, OPSWAP_DESC);
    trace(op, desc);
    let len = interpreter_stack.len();
    if len < TWO {
        error_num_items(op);
        return false;
    }
    interpreter_stack.swap(len - TWO, len - ONE);
    true
}

/// OP_TUCK: Copies the top item before the second-to-top item on the stack. Returns a bool.
///
/// Example: OP_TUCK([x1, x2]) -> [x2, x1, x2]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_tuck(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPTUCK, OPTUCK_DESC);
    trace(op, desc);
    let len = interpreter_stack.len();
    if len < TWO {
        error_num_items(op);
        return false;
    }
    let x2 = interpreter_stack[len - ONE].clone();
    interpreter_stack.insert(len - TWO, x2);
    true
}

/*---- SPLICE OPS ----*/

/// OP_CAT: Concatenates the second-to-top item and the top item on the stack. Returns a bool.
///
/// Example: OP_CAT([s1, s2]) -> [s1s2]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_cat(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPCAT, OPCAT_DESC);
    trace(op, desc);
    let s2 = match interpreter_stack.pop() {
        Some(StackEntry::Bytes(s)) => s,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let s1 = match interpreter_stack.pop() {
        Some(StackEntry::Bytes(s)) => s,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if s1.len() + s2.len() > MAX_SCRIPT_ITEM_SIZE as usize {
        error_item_size(op);
        return false;
    }
    let cat = [s1, s2].join("");
    interpreter_stack.push(StackEntry::Bytes(cat));
    true
}

/// OP_SUBSTR: Extracts a substring from the third-to-top item on the stack. Returns a bool.
///
/// Example: OP_SUBSTR([s, n1, n2]) -> [s[n1..n1+n2-1]]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_substr(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPSUBSTR, OPSUBSTR_DESC);
    trace(op, desc);
    let n2 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let s = match interpreter_stack.pop() {
        Some(StackEntry::Bytes(s)) => s,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if n1 >= s.len() {
        error_item_index(op);
        return false;
    }
    if n2 > s.len() {
        error_item_index(op);
        return false;
    }
    if n1 + n2 > s.len() {
        error_item_index(op);
        return false;
    }
    let substr = s[n1..n1 + n2].to_string();
    interpreter_stack.push(StackEntry::Bytes(substr));
    true
}

/// OP_LEFT: Extracts a left substring from the second-to-top item on the stack. Returns a bool.
///
/// Example: OP_LEFT([s, n]) -> [s[..n-1]] if n < len(s)
///          OP_LEFT([s, n]) -> [s]        if n >= len(s)
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_left(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPLEFT, OPLEFT_DESC);
    trace(op, desc);
    let n = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let s = match interpreter_stack.pop() {
        Some(StackEntry::Bytes(s)) => s,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if n >= s.len() {
        interpreter_stack.push(StackEntry::Bytes(s));
    } else {
        let left = s[..n].to_string();
        interpreter_stack.push(StackEntry::Bytes(left));
    }
    true
}

/// OP_RIGHT: Extracts a right substring from the second-to-top item on the stack. Returns a bool.
///
/// Example: OP_RIGHT([s, n]) -> [s[n..]] if n < len(s)
///          OP_RIGHT([s, n]) -> [""]     if n >= len(s)
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_right(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPRIGHT, OPRIGHT_DESC);
    trace(op, desc);
    let n = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let s = match interpreter_stack.pop() {
        Some(StackEntry::Bytes(s)) => s,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if n >= s.len() {
        interpreter_stack.push(StackEntry::Bytes("".to_string()));
    } else {
        let right = s[n..].to_string();
        interpreter_stack.push(StackEntry::Bytes(right));
    }
    true
}

/// OP_SIZE: Computes the size in bytes of the top item on the stack. Returns a bool.
///
/// Example: OP_SIZE([s]) -> [s, len(s)]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_size(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPSIZE, OPSIZE_DESC);
    trace(op, desc);
    let s = match interpreter_stack.last().cloned() {
        Some(StackEntry::Bytes(s)) => s,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    interpreter_stack.push(StackEntry::Num(s.len()));
    true
}

/*---- BITWISE LOGIC OPS ----*/

/// OP_INVERT: Computes bitwise NOT of the top item on the stack. Returns a bool.
///
/// Example: OP_INVERT([n]) -> [!n]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_invert(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPINVERT, OPINVERT_DESC);
    trace(op, desc);
    let n = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    interpreter_stack.push(StackEntry::Num(!n));
    true
}

/// OP_AND: Computes bitwise AND between the second-to-top and the top item on the stack. Returns a bool.
///
/// Example: OP_AND([n1, n2]) -> [n1 & n2]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_and(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPAND, OPAND_DESC);
    trace(op, desc);
    let n2 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    interpreter_stack.push(StackEntry::Num(n1 & n2));
    true
}

/// OP_OR: Computes bitwise OR between the second-to-top and the top item on the stack. Returns a bool.
///
/// Example: OP_OR([n1, n2]) -> [n1 | n2]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_or(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPOR, OPOR_DESC);
    trace(op, desc);
    let n2 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    interpreter_stack.push(StackEntry::Num(n1 | n2));
    true
}

/// OP_XOR: Computes bitwise XOR between the second-to-top and the top item on the stack. Returns a bool.
///
/// Example: OP_XOR([n1, n2]) -> [n1 ^ n2]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_xor(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPXOR, OPXOR_DESC);
    trace(op, desc);
    let n2 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    interpreter_stack.push(StackEntry::Num(n1 ^ n2));
    true
}

/// OP_EQUAL: Substitutes the top two items on the stack with ONE if they are equal, with ZERO otherwise. Returns a bool.
///
/// Example: OP_EQUAL([x1, x2]) -> [1] if x1 == x2
///          OP_EQUAL([x1, x2]) -> [0] if x1 != x2
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_equal(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPEQUAL, OPEQUAL_DESC);
    trace(op, desc);
    let x2 = match interpreter_stack.pop() {
        Some(x) => x,
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let x1 = match interpreter_stack.pop() {
        Some(x) => x,
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if x1 == x2 {
        interpreter_stack.push(StackEntry::Num(ONE));
    } else {
        interpreter_stack.push(StackEntry::Num(ZERO));
    }
    true
}

/// OP_EQUALVERIFY: Computes OP_EQUAL and OP_VERIFY in sequence. Returns a bool.
///
/// Example: OP_EQUALVERIFY([x1, x2]) -> []   if x1 == x2
///          OP_EQUALVERIFY([x1, x2]) -> fail if x1 != x2
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_equalverify(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPEQUALVERIFY, OPEQUALVERIFY_DESC);
    trace(op, desc);
    let x2 = match interpreter_stack.pop() {
        Some(x) => x,
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let x1 = match interpreter_stack.pop() {
        Some(x) => x,
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if x1 != x2 {
        error_not_equal_items(op);
        return false;
    }
    true
}

/*---- ARITHMETIC OPS ----*/

/// OP_1ADD: Adds ONE to the top item on the stack. Returns a bool.
///
/// Example: OP_1ADD([n]) -> [n+1]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_1add(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OP1ADD, OP1ADD_DESC);
    trace(op, desc);
    let n = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    match n.checked_add(ONE) {
        Some(n) => interpreter_stack.push(StackEntry::Num(n)),
        _ => {
            error_overflow(op);
            return false;
        }
    }
    true
}

/// OP_1SUB: Subtracts ONE from the top item on the stack. Returns a bool.
///
/// Example: OP_1SUB([n]) -> [n-1]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_1sub(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OP1SUB, OP1SUB_DESC);
    trace(op, desc);
    let n = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    match n.checked_sub(ONE) {
        Some(n) => interpreter_stack.push(StackEntry::Num(n)),
        _ => {
            error_overflow(op);
            return false;
        }
    }
    true
}

/// OP_2MUL: Multiplies by TWO the top item on the stack. Returns a bool.
///
/// Example: OP_2MUL([n]) -> [n*2]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_2mul(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OP2MUL, OP2MUL_DESC);
    trace(op, desc);
    let n = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    match n.checked_mul(TWO) {
        Some(n) => interpreter_stack.push(StackEntry::Num(n)),
        _ => {
            error_overflow(op);
            return false;
        }
    }
    true
}

/// OP_2DIV: Divides by TWO the top item on the stack. Returns a bool.
///
/// Example: OP_2DIV([n]) -> [n/2]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_2div(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OP2DIV, OP2DIV_DESC);
    trace(op, desc);
    let n = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    interpreter_stack.push(StackEntry::Num(n / TWO));
    true
}

/// OP_NOT: Substitutes the top item on the stack with ONE if it is equal to ZERO,
///         with ZERO otherwise. Returns a bool.
///
/// Example: OP_NOT([n]) -> [1] if n == 0
///          OP_NOT([n]) -> [0] if n != 0
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_not(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPNOT, OPNOT_DESC);
    trace(op, desc);
    let n = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if n == ZERO {
        interpreter_stack.push(StackEntry::Num(ONE));
    } else {
        interpreter_stack.push(StackEntry::Num(ZERO));
    }
    true
}

/// OP_0NOTEQUAL: Substitutes the top item on the stack with ONE if it is not equal to ZERO,
///               with ZERO otherwise. Returns a bool.
///
/// Example: OP_0NOTEQUAL([n]) -> [1] if n != 0
///          OP_0NOTEQUAL([n]) -> [0] if n == 0
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_0notequal(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OP0NOTEQUAL, OP0NOTEQUAL_DESC);
    trace(op, desc);
    let n = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if n != ZERO {
        interpreter_stack.push(StackEntry::Num(ONE));
    } else {
        interpreter_stack.push(StackEntry::Num(ZERO));
    }
    true
}

/// OP_ADD: Adds the top item to the second-to-top item on the stack. Returns a bool.
///
/// Example: OP_ADD([n1, n2]) -> [n1+n2]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_add(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPADD, OPADD_DESC);
    trace(op, desc);
    let n2 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    match n1.checked_add(n2) {
        Some(n) => interpreter_stack.push(StackEntry::Num(n)),
        _ => {
            error_overflow(op);
            return false;
        }
    }
    true
}

/// OP_SUB: Subtracts the top item from the second-to-top item on the stack. Returns a bool.
///
/// Example: OP_SUB([n1, n2]) -> [n1-n2]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_sub(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPSUB, OPSUB_DESC);
    trace(op, desc);
    let n2 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    match n1.checked_sub(n2) {
        Some(n) => interpreter_stack.push(StackEntry::Num(n)),
        _ => {
            error_overflow(op);
            return false;
        }
    }
    true
}

/// OP_MUL: Multiplies the second-to-top item by the top item on the stack. Returns a bool.
///
/// Example: OP_MUL([n1, n2]) -> [n1*n2]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_mul(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPMUL, OPMUL_DESC);
    trace(op, desc);
    let n2 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    match n1.checked_mul(n2) {
        Some(n) => interpreter_stack.push(StackEntry::Num(n)),
        _ => {
            error_overflow(op);
            return false;
        }
    }
    true
}

/// OP_DIV: Divides the second-to-top item by the top item on the stack. Returns a bool.
///
/// Example: OP_DIV([n1, n2]) -> [n1/n2]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_div(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPDIV, OPDIV_DESC);
    trace(op, desc);
    let n2 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    match n1.checked_div(n2) {
        Some(n) => interpreter_stack.push(StackEntry::Num(n)),
        _ => {
            error_div_zero(op);
            return false;
        }
    }
    true
}

/// OP_MOD: Computes the remainder of the division of the second-to-top item by the top item on the stack. Returns a bool.
///
/// Example: OP_MOD([n1, n2]) -> [n1%n2]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_mod(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPMOD, OPMOD_DESC);
    trace(op, desc);
    let n2 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    match n1.checked_rem(n2) {
        Some(n) => interpreter_stack.push(StackEntry::Num(n)),
        _ => {
            error_div_zero(op);
            return false;
        }
    }
    true
}

/// OP_LSHIFT: Computes the left shift of the second-to-top item by the top item on the stack. Returns a bool.
///
/// Example: OP_LSHIFT([n1, n2]) -> [n1 << n2]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_lshift(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPLSHIFT, OPLSHIFT_DESC);
    trace(op, desc);
    let n2 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    match n1.checked_shl(n2 as u32) {
        Some(n) => interpreter_stack.push(StackEntry::Num(n)),
        _ => {
            error_overflow(op);
            return false;
        }
    }
    true
}

/// OP_RSHIFT: Computes the right shift of the second-to-top item by the top item on the stack. Returns a bool.
///
/// Example: OP_RSHIFT([n1, n2]) -> [n1 >> n2]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_rshift(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPRIGHT, OPRIGHT_DESC);
    trace(op, desc);
    let n2 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    match n1.checked_shr(n2 as u32) {
        Some(n) => interpreter_stack.push(StackEntry::Num(n)),
        _ => {
            error_overflow(op);
            return false;
        }
    }
    true
}

/// OP_BOOLAND: Substitutes the top two items on the stack with ONE if they are both non-ZERO, with ZERO otherwise. Returns a bool.
///
/// Example: OP_BOOLAND([n1, n2]) -> [1] if n1 != 0 and n2 != 0
///          OP_BOOLAND([n1, n2]) -> [0] if n1 == 0 or n2 == 0
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_booland(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPBOOLAND, OPBOOLAND_DESC);
    trace(op, desc);
    let n2 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if n1 != ZERO && n2 != ZERO {
        interpreter_stack.push(StackEntry::Num(ONE));
    } else {
        interpreter_stack.push(StackEntry::Num(ZERO));
    }
    true
}

/// OP_BOOLOR: Substitutes the top two items on the stack with ONE if they are not both ZERO, with ZERO otherwise. Returns a bool.
///
/// Example: OP_BOOLOR([n1, n2]) -> [1] if n1 != 0 or n2 != 0
///          OP_BOOLOR([n1, n2]) -> [0] if n1 == 0 and n2 == 0
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_boolor(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPBOOLOR, OPBOOLOR_DESC);
    trace(op, desc);
    let n2 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if n1 != ZERO || n2 != ZERO {
        interpreter_stack.push(StackEntry::Num(ONE));
    } else {
        interpreter_stack.push(StackEntry::Num(ZERO));
    }
    true
}

/// OP_NUMEQUAL: Substitutes the top two items on the stack with ONE if they are equal as numbers, with ZERO otherwise. Returns a bool.
///
/// Example: OP_NUMEQUAL([n1, n2]) -> [1] if n1 == n2
///          OP_NUMEQUAL([n1, n2]) -> [0] if n1 != n2
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_numequal(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPNUMEQUAL, OPNUMEQUAL_DESC);
    trace(op, desc);
    let n2 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if n1 == n2 {
        interpreter_stack.push(StackEntry::Num(ONE));
    } else {
        interpreter_stack.push(StackEntry::Num(ZERO));
    }
    true
}

/// OP_NUMEQUALVERIFY: Computes OP_NUMEQUAL and OP_VERIFY in sequence. Returns a bool.
///
/// Example: OP_NUMEQUALVERIFY([n1, n2]) -> []   if n1 == n2
///          OP_NUMEQUALVERIFY([n1, n2]) -> fail if n1 != n2
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_numequalverify(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPNUMEQUALVERIFY, OPNUMEQUALVERIFY_DESC);
    trace(op, desc);
    let n2 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if n1 != n2 {
        error_not_equal_items(op);
        return false;
    }
    true
}

/// OP_NUMNOTEQUAL: Substitutes the top two items on the stack with ONE if they are not equal, with ZERO otherwise. Returns a bool.
///
/// Example: OP_NUMNOTEQUAL([n1, n2]) -> [1] if n1 != n2
///          OP_NUMNOTEQUAL([n1, n2]) -> [0] if n1 == n2
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_numnotequal(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPNUMNOTEQUAL, OPNUMNOTEQUAL_DESC);
    trace(op, desc);
    let n2 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if n1 != n2 {
        interpreter_stack.push(StackEntry::Num(ONE));
    } else {
        interpreter_stack.push(StackEntry::Num(ZERO));
    }
    true
}

/// OP_LESSTHAN: Substitutes the top two items on the stack with ONE if the second-to-top is less than the top item, with ZERO otherwise. Returns a bool.
///
/// Example: OP_LESSTHAN([n1, n2]) -> [1] if n1 < n2
///          OP_LESSTHAN([n1, n2]) -> [0] if n1 >= n2
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_lessthan(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPLESSTHAN, OPLESSTHAN_DESC);
    trace(op, desc);
    let n2 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if n1 < n2 {
        interpreter_stack.push(StackEntry::Num(ONE));
    } else {
        interpreter_stack.push(StackEntry::Num(ZERO));
    }
    true
}

/// OP_GREATERTHAN: Substitutes the top two items on the stack with ONE if the second-to-top is greater than the top item, with ZERO otherwise. Returns a bool.
///
/// Example: OP_GREATERTHAN([n1, n2]) -> [1] if n1 > n2
///          OP_GREATERTHAN([n1, n2]) -> [0] if n1 <= n2
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_greaterthan(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OP0NOTEQUAL, OP0NOTEQUAL_DESC);
    trace(op, desc);
    let n2 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if n1 > n2 {
        interpreter_stack.push(StackEntry::Num(ONE));
    } else {
        interpreter_stack.push(StackEntry::Num(ZERO));
    }
    true
}

/// OP_LESSTHANOREQUAL: Substitutes the top two items on the stack with ONE if the second-to-top is less than or equal to the top item, with ZERO otherwise. Returns a bool.
///
/// Example: OP_LESSTHANOREQUAL([n1, n2]) -> [1] if n1 <= n2
///          OP_LESSTHANOREQUAL([n1, n2]) -> [0] if n1 > n2
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_lessthanorequal(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPLESSTHANOREQUAL, OPLESSTHANOREQUAL_DESC);
    trace(op, desc);
    let n2 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if n1 <= n2 {
        interpreter_stack.push(StackEntry::Num(ONE));
    } else {
        interpreter_stack.push(StackEntry::Num(ZERO));
    }
    true
}

/// OP_GREATERTHANOREQUAL: Substitutes the top two items on the stack with ONE if the second-to-top is greater than or equal to the top item, with ZERO otherwise. Returns a bool.
///
/// Example: OP_GREATERTHANOREQUAL([n1, n2]) -> [1] if n1 >= n2
///          OP_GREATERTHANOREQUAL([n1, n2]) -> [0] if n1 < n2
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_greaterthanorequal(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPGREATERTHANOREQUAL, OPGREATERTHANOREQUAL_DESC);
    trace(op, desc);
    let n2 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if n1 >= n2 {
        interpreter_stack.push(StackEntry::Num(ONE));
    } else {
        interpreter_stack.push(StackEntry::Num(ZERO));
    }
    true
}

/// OP_MIN: Substitutes the top two items on the stack with the minimum between the two. Returns a bool.
///
/// Example: OP_MIN([n1, n2]) -> [n1] if n1 <= n2
///          OP_MIN([n1, n2]) -> [n2] if n1 > n2
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_min(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPMIN, OPMIN_DESC);
    trace(op, desc);
    let n2 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    interpreter_stack.push(StackEntry::Num(n1.min(n2)));
    true
}

/// OP_MAX: Substitutes the top two items on the stack with the maximum between the two. Returns a bool.
///
/// Example: OP_MAX([n1, n2]) -> [n1] if n1 >= n2
///          OP_MAX([n1, n2]) -> [n2] if n1 < n2
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_max(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPMAX, OPMAX_DESC);
    trace(op, desc);
    let n2 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    interpreter_stack.push(StackEntry::Num(n1.max(n2)));
    true
}

/// OP_WITHIN: Substitutes the top three items on the stack with ONE if the third-to-top is greater or equal to the second-to-top and less than the top item,
///            with ZERO otherwise. Returns a bool.
///
/// Example: OP_WITHIN([n1, n2, n3]) -> [1] if n1 >= n2 and n1 < n3
///          OP_WITHIN([n1, n2, n3]) -> [0] if n1 < n2 or n1 >= n3
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_within(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPWITHIN, OPWITHIN_DESC);
    trace(op, desc);
    let n3 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n2 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let n1 = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if n1 >= n2 && n1 < n3 {
        interpreter_stack.push(StackEntry::Num(ONE));
    } else {
        interpreter_stack.push(StackEntry::Num(ZERO));
    }
    true
}

/*---- CRYPTO OPS ----*/

/// OP_SHA3: Hashes the top item on the stack using SHA3-256. Returns a bool.
///
/// Example: OP_SHA3([m]) -> [SHA3-256(m)]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_sha3(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPSHA3, OPSHA3_DESC);
    trace(op, desc);
    let data = match interpreter_stack.pop() {
        Some(StackEntry::Signature(sig)) => sig.as_ref().to_owned(),
        Some(StackEntry::PubKey(pk)) => pk.as_ref().to_owned(),
        Some(StackEntry::PubKeyHash(s)) | Some(StackEntry::Bytes(s)) => s.as_bytes().to_owned(),
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let hash = hex::encode(sha3_256::digest(&data));
    interpreter_stack.push(StackEntry::Bytes(hash));
    true
}

/// OP_HASH256: Creates standard address from public key and pushes it onto the stack. Returns a bool.
///
/// Example: OP_HASH256([pk]) -> [addr]
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_hash256(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPHASH256, OPHASH256_DESC);
    trace(op, desc);
    let pk = match interpreter_stack.pop() {
        Some(StackEntry::PubKey(pk)) => pk,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let addr = construct_address(&pk);
    interpreter_stack.push(StackEntry::PubKeyHash(addr));
    true
}

/// OP_HASH256V0: Creates v0 address from public key and pushes it onto the stack. Returns a bool.
///
/// Example: OP_HASH256V0([pk]) -> [addr_v0]
///
/// Info: Support for old 32-byte addresses.
///
/// TODO: Deprecate after addresses retire.
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_hash256v0(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPHASH256V0, OPHASH256V0_DESC);
    trace(op, desc);
    let pk = match interpreter_stack.pop() {
        Some(StackEntry::PubKey(pk)) => pk,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let addr_v0 = construct_address_v0(&pk);
    interpreter_stack.push(StackEntry::PubKeyHash(addr_v0));
    true
}

/// OP_HASH256TEMP: Creates temporary address from public key and pushes it onto the stack. Returns a bool.
///
/// Example: OP_HASH256TEMP([pk]) -> [addr_temp]
///
/// Info: Support for temporary address scheme used in wallet.
///
/// TODO: Deprecate after addresses retire.
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_hash256temp(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPHASH256TEMP, OPHASH256TEMP_DESC);
    trace(op, desc);
    let pk = match interpreter_stack.pop() {
        Some(StackEntry::PubKey(pk)) => pk,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let addr_temp = construct_address_temp(&pk);
    interpreter_stack.push(StackEntry::PubKeyHash(addr_temp));
    true
}

/// OP_CHECKSIG: Pushes ONE onto the stack if the signature is valid, ZERO otherwise. Returns a bool.
///
/// Example: OP_CHECKSIG([msg, sig, pk]) -> [1] if Verify(sig, msg, pk) == 1
///          OP_CHECKSIG([msg, sig, pk]) -> [0] if Verify(sig, msg, pk) == 0
///
/// Info: It allows signature verification on arbitrary messsages, not only transactions.
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_checksig(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPCHECKSIG, OPCHECKSIG_DESC);
    trace(op, desc);
    let pk = match interpreter_stack.pop() {
        Some(StackEntry::PubKey(pk)) => pk,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let sig = match interpreter_stack.pop() {
        Some(StackEntry::Signature(sig)) => sig,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let msg = match interpreter_stack.pop() {
        Some(StackEntry::Bytes(s)) => s,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if (!sign::verify_detached(&sig, msg.as_bytes(), &pk)) {
        interpreter_stack.push(StackEntry::Num(ZERO));
    } else {
        interpreter_stack.push(StackEntry::Num(ONE));
    }
    true
}

/// OP_CHECKSIGVERIFY: Runs OP_CHECKSIG and OP_VERIFY in sequence. Returns a bool.
///
/// Example: OP_CHECKSIGVERIFY([msg, sig, pk]) -> []   if Verify(sig, msg, pk) == 1
///          OP_CHECKSIGVERIFY([msg, sig, pk]) -> fail if Verify(sig, msg, pk) == 0
///
/// Info: It allows signature verification on arbitrary messsages, not only transactions.
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_checksigverify(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPCHECKSIGVERIFY, OPCHECKSIGVERIFY_DESC);
    trace(op, desc);
    let pk = match interpreter_stack.pop() {
        Some(StackEntry::PubKey(pk)) => pk,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let sig = match interpreter_stack.pop() {
        Some(StackEntry::Signature(sig)) => sig,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    let msg = match interpreter_stack.pop() {
        Some(StackEntry::Bytes(s)) => s,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if (!sign::verify_detached(&sig, msg.as_bytes(), &pk)) {
        error_invalid_signature(op);
        return false;
    }
    true
}

/// OP_CHECKMULTISIG: Pushes ONE onto the stack if the m-of-n multi-signature is valid, ZERO otherwise. Returns a bool.
///
/// Example: OP_CHECKMULTISIG([msg, sig1, sig2, m, pk1, pk2, pk3, n]) -> [1] if Verify(msg, sig1, sig2, pk1, pk2, pk3, m) == 1
///          OP_CHECKMULTISIG([msg, sig1, sig2, m, pk1, pk2, pk3, n]) -> [0] if Verify(msg, sig1, sig2, pk1, pk2, pk3, m) == 0
///
/// Info: It allows multi-signature verification on arbitrary messsages, not only transactions.
///       Ordering of signatures and public keys is not relevant.
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_checkmultisig(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPCHECKMULTISIG, OPCHECKMULTISIG_DESC);
    trace(op, desc);
    let n = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if n > MAX_PUB_KEYS_PER_MULTISIG as usize{
        error_num_pubkeys(op);
        return false;
    }
    let mut pks = Vec::new();
    while let Some(StackEntry::PubKey(_)) = interpreter_stack.last().cloned() {
        if let Some(StackEntry::PubKey(pk)) = interpreter_stack.pop() {
            pks.push(pk);
        }
    }
    if pks.len() != n {
        error_num_pubkeys(op);
        return false;
    }
    let m = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if m > n {
        error_num_signatures(op);
        return false;
    }
    let mut sigs = Vec::new();
    while let Some(StackEntry::Signature(_)) = interpreter_stack.last().cloned() {
        if let Some(StackEntry::Signature(sig)) = interpreter_stack.pop() {
            sigs.push(sig);
        }
    }
    if sigs.len() != m {
        error_num_signatures(op);
        return false;
    }
    let msg = match interpreter_stack.pop() {
        Some(StackEntry::Bytes(s)) => s,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if !verify_multisig(msg, sigs, pks) {
        interpreter_stack.push(StackEntry::Num(ZERO));
    } else {
        interpreter_stack.push(StackEntry::Num(ONE));
    }
    true
}

/// OP_CHECKMULTISIGVERIFY: Runs OP_CHECKMULTISIG and OP_VERIFY in sequence. Returns a bool.
///
/// Example: OP_CHECKMULTISIGVERIFY([msg, sig1, sig2, m, pk1, pk2, pk3, n]) -> []   if Verify(msg, sig1, sig2, pk1, pk2, pk3, m) == 1
///          OP_CHECKMULTISIGVERIFY([msg, sig1, sig2, m, pk1, pk2, pk3, n]) -> fail if Verify(msg, sig1, sig2, pk1, pk2, pk3, m) == 0
///
/// Info: It allows multi-signature verification on arbitrary messsages, not only transactions.
///       Ordering of signatures and public keys is not relevant.
///
/// ### Arguments
///
/// * `interpreter_stack`  - mutable reference to the interpreter stack
pub fn op_checkmultisigverify(interpreter_stack: &mut Vec<StackEntry>) -> bool {
    let (op, desc) = (OPCHECKMULTISIG, OPCHECKMULTISIG_DESC);
    trace(op, desc);
    let n = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if n > MAX_PUB_KEYS_PER_MULTISIG as usize{
        error_num_pubkeys(op);
        return false;
    }
    let mut pks = Vec::new();
    while let Some(StackEntry::PubKey(_)) = interpreter_stack.last().cloned() {
        if let Some(StackEntry::PubKey(pk)) = interpreter_stack.pop() {
            pks.push(pk);
        }
    }
    if pks.len() != n {
        error_num_pubkeys(op);
        return false;
    }
    let m = match interpreter_stack.pop() {
        Some(StackEntry::Num(n)) => n,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if m > n {
        error_num_signatures(op);
        return false;
    }
    let mut sigs = Vec::new();
    while let Some(StackEntry::Signature(_)) = interpreter_stack.last().cloned() {
        if let Some(StackEntry::Signature(sig)) = interpreter_stack.pop() {
            sigs.push(sig);
        }
    }
    let msg = match interpreter_stack.pop() {
        Some(StackEntry::Bytes(s)) => s,
        Some(_) => {
            error_item_type(op);
            return false;
        }
        _ => {
            error_num_items(op);
            return false;
        }
    };
    if !verify_multisig(msg, sigs, pks) {
        error_invalid_multisignature(op);
        return false;
    }
    true
}

/// Does pairwise validation of signatures against public keys
///
/// ### Arguments
///
/// * `msg`  - Data to verify against
/// * `sigs` - Signatures to check
/// * `pks`  - Public keys to check
fn verify_multisig(
    msg: String,
    sigs: Vec<Signature>,
    pks: Vec<PublicKey>
) -> bool {
    let mut pks = pks;
    let mut num_valid_sigs = ZERO; 
    for index_sig in ZERO..sigs.len() {
        for index_pk in ZERO..pks.len() {
            if sign::verify_detached(&sigs[index_sig], msg.as_bytes(), &pks[index_pk]) {
                num_valid_sigs += ONE;
                pks.remove(index_pk);
                break;
            }
        }
        if num_valid_sigs != index_sig + ONE { // sigs[index_sig] did not match any pk
            return false;
        }
    }
    num_valid_sigs == sigs.len()
}

/*---- TESTS ----*/

#[cfg(test)]
mod tests {
    use super::*;

    /*---- CONSTANTS OPS ----*/

    #[test]
    /// Test OP_0
    fn test_0() {
        /// op_0([]) -> [0]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_0(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v)
    }

    #[test]
    /// Test OP_1
    fn test_1() {
        /// op_1([]) -> [1]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_1(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v)
    }

    #[test]
    /// Test OP_2
    fn test_2() {
        /// op_2([]) -> [2]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(2)];
        op_2(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v)
    }

    #[test]
    /// Test OP_3
    fn test_3() {
        /// op_3([]) -> [3]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(3)];
        op_3(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v)
    }

    #[test]
    /// Test OP_4
    fn test_4() {
        /// op_4([]) -> [4]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(4)];
        op_4(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v)
    }

    #[test]
    /// Test OP_5
    fn test_5() {
        /// op_5([]) -> [5]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(5)];
        op_5(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v)
    }

    #[test]
    /// Test OP_6
    fn test_6() {
        /// op_6([]) -> [6]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(6)];
        op_6(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v)
    }

    #[test]
    /// Test OP_7
    fn test_7() {
        /// op_7([]) -> [7]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(7)];
        op_7(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v)
    }

    #[test]
    /// Test OP_8
    fn test_8() {
        /// op_8([]) -> [8]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(8)];
        op_8(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v)
    }

    #[test]
    /// Test OP_9
    fn test_9() {
        /// op_9([]) -> [9]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(9)];
        op_9(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v)
    }

    #[test]
    /// Test OP_10
    fn test_10() {
        /// op_10([]) -> [10]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(10)];
        op_10(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v)
    }

    #[test]
    /// Test OP_11
    fn test_11() {
        /// op_11([]) -> [11]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(11)];
        op_11(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v)
    }

    #[test]
    /// Test OP_12
    fn test_12() {
        /// op_12([]) -> [12]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(12)];
        op_12(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v)
    }

    #[test]
    /// Test OP_13
    fn test_13() {
        /// op_13([]) -> [13]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(13)];
        op_13(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v)
    }

    #[test]
    /// Test OP_14
    fn test_14() {
        /// op_14([]) -> [14]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(14)];
        op_14(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v)
    }

    #[test]
    /// Test OP_15
    fn test_15() {
        /// op_15([]) -> [15]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(15)];
        op_15(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v)
    }

    #[test]
    /// Test OP_16
    fn test_16() {
        /// op_16([]) -> [16]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(16)];
        op_16(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v)
    }

    /*---- STACK OPS ----*/

    #[test]
    /// Test OP_TOALTSTACK
    fn test_toaltstack() {
        /// op_toaltstack([1], []) -> [], [1]
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let mut interpreter_alt_stack: Vec<StackEntry> = vec![];
        let mut v1: Vec<StackEntry> = vec![];
        let mut v2: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_toaltstack(&mut interpreter_stack, &mut interpreter_alt_stack);
        assert_eq!(interpreter_stack, v1);
        assert_eq!(interpreter_alt_stack, v2);
        /// op_toaltstack([], []) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let mut interpreter_alt_stack: Vec<StackEntry> = vec![];
        let b = op_toaltstack(&mut interpreter_stack, &mut interpreter_alt_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_FROMALTSTACK
    fn test_fromaltstack() {
        /// op_fromaltstack([], [1]) -> [1], []
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let mut interpreter_alt_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let mut v1: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let mut v2: Vec<StackEntry> = vec![];
        op_fromaltstack(&mut interpreter_stack, &mut interpreter_alt_stack);
        assert_eq!(interpreter_stack, v1);
        assert_eq!(interpreter_alt_stack, v2);
        /// op_fromaltstack([], []) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let mut interpreter_alt_stack: Vec<StackEntry> = vec![];
        let b = op_fromaltstack(&mut interpreter_stack, &mut interpreter_alt_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_2DROP
    fn test_2drop() {
        /// op_2drop([1,2]) -> []
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![];
        op_2drop(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_2drop([1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_2drop(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_2DUP
    fn test_2dup() {
        /// op_2dup([1,2]) -> [1,2,1,2]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            v.push(StackEntry::Num(i));
        }
        for i in 1..=2 {
            v.push(StackEntry::Num(i));
        }
        op_2dup(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_2dup([1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_2dup(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_3DUP
    fn test_3dup() {
        /// op_3dup([1,2,3]) -> [1,2,3,1,2,3]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=3 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![];
        for i in 1..=3 {
            v.push(StackEntry::Num(i));
        }
        for i in 1..=3 {
            v.push(StackEntry::Num(i));
        }
        op_3dup(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_3dup([1,2]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let b = op_3dup(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_2OVER
    fn test_2over() {
        /// op_2over([1,2,3,4]) -> [1,2,3,4,1,2]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=4 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![];
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        for i in 1..=2 {
            v.push(StackEntry::Num(i));
        }
        op_2over(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_2over([1,2,3]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=3 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let b = op_2over(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_2ROT
    fn test_2rot() {
        /// op_2rot([1,2,3,4,5,6]) -> [3,4,5,6,1,2]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=6 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![];
        for i in 3..=6 {
            v.push(StackEntry::Num(i));
        }
        for i in 1..=2 {
            v.push(StackEntry::Num(i));
        }
        op_2rot(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_2rot([1,2,3,4,5]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=5 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let b = op_2rot(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_2SWAP
    fn test_2swap() {
        /// op_2swap([1,2,3,4]) -> [3,4,1,2]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=4 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![];
        for i in 3..=4 {
            v.push(StackEntry::Num(i));
        }
        for i in 1..=2 {
            v.push(StackEntry::Num(i));
        }
        op_2swap(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_2swap([1,2,3]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=3 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let b = op_2swap(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_IFDUP
    fn test_ifdup() {
        /// op_ifdup([1]) -> [1,1]
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let mut v: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            v.push(StackEntry::Num(1));
        }
        op_ifdup(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_ifdup([0]) -> [0]
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(0)];
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_ifdup(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_ifdup([]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let b = op_ifdup(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_DEPTH
    fn test_depth() {
        /// op_depth([1,1,1,1]) -> [1,1,1,1,4]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=4 {
            interpreter_stack.push(StackEntry::Num(1));
        }
        let mut v: Vec<StackEntry> = vec![];
        for i in 1..=4 {
            v.push(StackEntry::Num(1));
        }
        v.push(StackEntry::Num(4));
        op_depth(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_depth([]) -> [0]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_depth(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v)
    }

    #[test]
    /// Test OP_DROP
    fn test_drop() {
        /// op_drop([1]) -> []
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let mut v: Vec<StackEntry> = vec![];
        op_drop(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_drop([]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let b = op_drop(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_DUP
    fn test_dup() {
        /// op_dup([1]) -> [1,1]
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let mut v: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            v.push(StackEntry::Num(1));
        }
        op_dup(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_dup([]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let b = op_dup(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_NIP
    fn test_nip() {
        /// op_nip([1,2]) -> [2]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(2)];
        op_nip(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_nip([1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_nip(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_OVER
    fn test_over() {
        /// op_over([1,2]) -> [1,2,1]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(1));
        op_over(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_over([1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_over(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_PICK
    fn test_pick() {
        /// op_pick([1,2,3,4,3]) -> [1,2,3,4,1]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=4 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        interpreter_stack.push(StackEntry::Num(3));
        let mut v: Vec<StackEntry> = vec![];
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(1));
        op_pick(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_pick([1,2,3,4,0]) -> [1,2,3,4,4]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=4 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        interpreter_stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = vec![];
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(4));
        op_pick(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_pick([1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_pick(&mut interpreter_stack);
        assert!(!b);
        /// op_pick([1,"hello"]) -> fail
        let mut interpreter_stack: Vec<StackEntry> =
            vec![StackEntry::Num(1), StackEntry::Bytes("hello".to_string())];
        let b = op_pick(&mut interpreter_stack);
        assert!(!b);
        /// op_pick([1,1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let b = op_pick(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_ROLL
    fn test_roll() {
        /// op_roll([1,2,3,4,3]) -> [2,3,4,1]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=4 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        interpreter_stack.push(StackEntry::Num(3));
        let mut v: Vec<StackEntry> = vec![];
        for i in 2..=4 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(1));
        op_roll(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_roll([1,2,3,4,0]) -> [1,2,3,4]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=4 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        interpreter_stack.push(StackEntry::Num(0));
        let mut v: Vec<StackEntry> = vec![];
        for i in 1..=4 {
            v.push(StackEntry::Num(i));
        }
        op_roll(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_roll([1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_roll(&mut interpreter_stack);
        assert!(!b);
        /// op_roll([1,"hello"]) -> fail
        let mut interpreter_stack: Vec<StackEntry> =
            vec![StackEntry::Num(1), StackEntry::Bytes("hello".to_string())];
        let b = op_roll(&mut interpreter_stack);
        assert!(!b);
        /// op_roll([1,1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let b = op_roll(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_ROT
    fn test_rot() {
        /// op_rot([1,2,3]) -> [2,3,1]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=3 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![];
        for i in 2..=3 {
            v.push(StackEntry::Num(i));
        }
        v.push(StackEntry::Num(1));
        op_rot(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_rot([1,2]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let b = op_rot(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_SWAP
    fn test_swap() {
        /// op_swap([1,2]) -> [2,1]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(2), StackEntry::Num(1)];
        op_swap(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_swap([1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_swap(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_TUCK
    fn test_tuck() {
        /// op_tuck([1,2]) -> [2,1,2]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(2)];
        for i in 1..=2 {
            v.push(StackEntry::Num(i));
        }
        op_tuck(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_tuck([1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_tuck(&mut interpreter_stack);
        assert!(!b)
    }

    /*---- SPLICE OPS ----*/

    #[test]
    /// Test OP_CAT
    fn test_cat() {
        /// op_cat(["hello","world"]) -> ["helloworld"]
        let mut interpreter_stack: Vec<StackEntry> = vec![
            StackEntry::Bytes("hello".to_string()),
            StackEntry::Bytes("world".to_string()),
        ];
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("helloworld".to_string())];
        op_cat(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_cat(["hello",""]) -> ["hello"]
        let mut interpreter_stack: Vec<StackEntry> = vec![
            StackEntry::Bytes("hello".to_string()),
            StackEntry::Bytes("".to_string()),
        ];
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("hello".to_string())];
        op_cat(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_cat(["a","a"*MAX_SCRIPT_ITEM_SIZE]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Bytes('a'.to_string())];
        let mut s = String::new();
        for i in 1..=MAX_SCRIPT_ITEM_SIZE {
            s.push('a');
        }
        interpreter_stack.push(StackEntry::Bytes(s.to_string()));
        let b = op_cat(&mut interpreter_stack);
        assert!(!b);
        /// op_cat(["hello"]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Bytes("hello".to_string())];
        let b = op_cat(&mut interpreter_stack);
        assert!(!b);
        /// op_cat(["hello", 1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> =
            vec![StackEntry::Bytes("hello".to_string()), StackEntry::Num(1)];
        let b = op_cat(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_SUBSTR
    fn test_substr() {
        /// op_substr(["hello",1,2]) -> ["el"]
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Bytes("hello".to_string())];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("el".to_string())];
        op_substr(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_substr(["hello",0,0]) -> [""]
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Bytes("hello".to_string())];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(0));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("".to_string())];
        op_substr(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_substr(["hello",0,5]) -> ["hello"]
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Bytes("hello".to_string())];
        interpreter_stack.push(StackEntry::Num(0));
        interpreter_stack.push(StackEntry::Num(5));
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("hello".to_string())];
        op_substr(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_substr(["hello",5,0]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Bytes("hello".to_string())];
        interpreter_stack.push(StackEntry::Num(5));
        interpreter_stack.push(StackEntry::Num(0));
        let b = op_substr(&mut interpreter_stack);
        assert!(!b);
        /// op_substr(["hello",1,5]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Bytes("hello".to_string())];
        interpreter_stack.push(StackEntry::Num(1));
        interpreter_stack.push(StackEntry::Num(5));
        let b = op_substr(&mut interpreter_stack);
        assert!(!b);
        /// op_substr(["hello",1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Bytes("hello".to_string())];
        interpreter_stack.push(StackEntry::Num(1));
        let b = op_substr(&mut interpreter_stack);
        assert!(!b);
        /// op_substr(["hello",1,usize::MAX]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Bytes("hello".to_string())];
        interpreter_stack.push(StackEntry::Num(1));
        interpreter_stack.push(StackEntry::Num(usize::MAX));
        let b = op_substr(&mut interpreter_stack);
        assert!(!b);
        /// op_substr(["hello",1,""]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Bytes("hello".to_string())];
        interpreter_stack.push(StackEntry::Num(1));
        interpreter_stack.push(StackEntry::Bytes("".to_string()));
        let b = op_substr(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_LEFT
    fn test_left() {
        /// op_left(["hello",2]) -> ["he"]
        let mut interpreter_stack: Vec<StackEntry> =
            vec![StackEntry::Bytes("hello".to_string()), StackEntry::Num(2)];
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("he".to_string())];
        op_left(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_left(["hello",0]) -> [""]
        let mut interpreter_stack: Vec<StackEntry> =
            vec![StackEntry::Bytes("hello".to_string()), StackEntry::Num(0)];
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("".to_string())];
        op_left(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_left(["hello",5]) -> ["hello"]
        let mut interpreter_stack: Vec<StackEntry> =
            vec![StackEntry::Bytes("hello".to_string()), StackEntry::Num(5)];
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("hello".to_string())];
        op_left(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_left(["hello",""]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![
            StackEntry::Bytes("hello".to_string()),
            StackEntry::Bytes("".to_string()),
        ];
        let b = op_left(&mut interpreter_stack);
        assert!(!b);
        /// op_left(["hello"]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Bytes("hello".to_string())];
        let b = op_left(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_RIGHT
    fn test_right() {
        /// op_right(["hello",0]) -> ["hello"]
        let mut interpreter_stack: Vec<StackEntry> =
            vec![StackEntry::Bytes("hello".to_string()), StackEntry::Num(0)];
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("hello".to_string())];
        op_right(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_right(["hello",2]) -> ["llo"]
        let mut interpreter_stack: Vec<StackEntry> =
            vec![StackEntry::Bytes("hello".to_string()), StackEntry::Num(2)];
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("llo".to_string())];
        op_right(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_right(["hello",5]) -> [""]
        let mut interpreter_stack: Vec<StackEntry> =
            vec![StackEntry::Bytes("hello".to_string()), StackEntry::Num(5)];
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("".to_string())];
        op_right(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_right(["hello",""]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![
            StackEntry::Bytes("hello".to_string()),
            StackEntry::Bytes("".to_string()),
        ];
        let b = op_right(&mut interpreter_stack);
        assert!(!b);
        /// op_right(["hello"]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Bytes("hello".to_string())];
        let b = op_right(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_SIZE
    fn test_size() {
        /// op_size(["hello"]) -> ["hello",5]
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Bytes("hello".to_string())];
        let mut v: Vec<StackEntry> =
            vec![StackEntry::Bytes("hello".to_string()), StackEntry::Num(5)];
        op_size(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_size([""]) -> ["",0]
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Bytes("".to_string())];
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes("".to_string()), StackEntry::Num(0)];
        op_size(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_size([1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_size(&mut interpreter_stack);
        assert!(!b);
        /// op_size([]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let b = op_size(&mut interpreter_stack);
        assert!(!b)
    }

    /*---- BITWISE LOGIC OPS ----*/

    #[test]
    /// Test OP_INVERT
    fn test_invert() {
        /// op_invert([0]) -> [usize::MAX]
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(0)];
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(usize::MAX)];
        op_invert(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_invert([]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let b = op_invert(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_AND
    fn test_and() {
        /// op_and([1,2]) -> [0]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_and(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_and([1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_and(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_OR
    fn test_or() {
        /// op_or([1,2]) -> [3]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(3)];
        op_or(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_or([1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_or(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_XOR
    fn test_xor() {
        /// op_xor([1,2]) -> [3]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(3)];
        op_xor(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_xor([1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_xor(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_EQUAL
    fn test_equal() {
        /// op_equal(["hello","hello"]) -> [1]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Bytes("hello".to_string()));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_equal(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_equal([1,2]) -> [0]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_equal(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_equal([1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_equal(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_EQUALVERIFY
    fn test_equalverify() {
        /// op_equalverify(["hello","hello"]) -> []
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Bytes("hello".to_string()));
        }
        let mut v: Vec<StackEntry> = vec![];
        op_equalverify(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_equalverify([1,2]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let b = op_equalverify(&mut interpreter_stack);
        assert!(!b);
        /// op_equalverify([1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_equalverify(&mut interpreter_stack);
        assert!(!b)
    }

    /*---- ARITHMETIC OPS ----*/

    #[test]
    /// Test OP_1ADD
    fn test_1add() {
        /// op_1add([1]) -> [2]
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(2)];
        op_1add(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_1add([usize::MAX]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(usize::MAX)];
        let b = op_1add(&mut interpreter_stack);
        assert!(!b);
        /// op_1add([]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let b = op_1add(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_1SUB
    fn test_1sub() {
        /// op_1sub([1]) -> [0]
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_1sub(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_1sub([0]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(0)];
        let b = op_1sub(&mut interpreter_stack);
        assert!(!b);
        /// op_1sub([]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let b = op_1sub(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_2MUL
    fn test_2mul() {
        /// op_2mul([1]) -> [2]
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(2)];
        op_2mul(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_2mul([usize::MAX]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(usize::MAX)];
        let b = op_2mul(&mut interpreter_stack);
        assert!(!b);
        /// op_2mul([]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let b = op_2mul(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_2DIV
    fn test_2div() {
        /// op_2div([1]) -> [0]
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_2div(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_2div([]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let b = op_2div(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_NOT
    fn test_not() {
        /// op_not([0]) -> [1]
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(0)];
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_not(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_not([1]) -> [0]
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_not(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_not([]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let b = op_not(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_0NOTEQUAL
    fn test_0notequal() {
        /// op_0notequal([1]) -> [1]
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_0notequal(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_0notequal([0]) -> [0]
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(0)];
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_0notequal(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_0notequal([]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let b = op_0notequal(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_ADD
    fn test_add() {
        /// op_add([1,2]) -> [3]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(3)];
        op_add(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_add([1,usize::MAX]) -> fail
        let mut interpreter_stack: Vec<StackEntry> =
            vec![StackEntry::Num(1), StackEntry::Num(usize::MAX)];
        let b = op_add(&mut interpreter_stack);
        assert!(!b);
        /// op_add([1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_add(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_SUB
    fn test_sub() {
        /// op_sub([1,0]) -> [1]
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1), StackEntry::Num(0)];
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_sub(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_sub([0,1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(0), StackEntry::Num(1)];
        let b = op_sub(&mut interpreter_stack);
        assert!(!b);
        /// op_sub([1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_sub(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_MUL
    fn test_mul() {
        /// op_mul([1,2]) -> [2]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(2)];
        op_mul(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_mul([2,usize::MAX]) -> fail
        let mut interpreter_stack: Vec<StackEntry> =
            vec![StackEntry::Num(2), StackEntry::Num(usize::MAX)];
        let b = op_mul(&mut interpreter_stack);
        assert!(!b);
        /// op_mul([1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_mul(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_DIV
    fn test_div() {
        /// op_div([1,2]) -> [0]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_div(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_div([1,0]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1), StackEntry::Num(0)];
        let b = op_div(&mut interpreter_stack);
        assert!(!b);
        /// op_div([1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_div(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_MOD
    fn test_mod() {
        /// op_mod([1,2]) -> [1]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_mod(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_mod([1,0]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1), StackEntry::Num(0)];
        let b = op_mod(&mut interpreter_stack);
        assert!(!b);
        /// op_mod([1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_mod(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_LSHIFT
    fn test_lshift() {
        /// op_lshift([1,2]) -> [4]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(4)];
        op_lshift(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_lshift([1,64]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1), StackEntry::Num(64)];
        let b = op_lshift(&mut interpreter_stack);
        assert!(!b);
        /// op_lshift([1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_lshift(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_RSHIFT
    fn test_rshift() {
        /// op_rshift([1,2]) -> [0]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_rshift(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_rshift([1,64]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1), StackEntry::Num(64)];
        let b = op_rshift(&mut interpreter_stack);
        assert!(!b);
        /// op_rshift([1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_rshift(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_BOOLAND
    fn test_booland() {
        /// op_booland([1,2]) -> [1]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_booland(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_booland([0,1]) -> [0]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 0..=1 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_booland(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_booland([1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_booland(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_BOOLOR
    fn test_boolor() {
        /// op_boolor([0,1]) -> [1]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 0..=1 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_boolor(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_boolor([0,0]) -> [0]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(0));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_boolor(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_boolor([1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_boolor(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_NUMEQUAL
    fn test_numequal() {
        /// op_numequal([1,1]) -> [1]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(1));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_numequal(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_numequal([1,2]) -> [0]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_numequal(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_numequal([1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_numequal(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_NUMEQUALVERIFY
    fn test_numequalverify() {
        /// op_numequalverify([1,1]) -> []
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(1));
        }
        let mut v: Vec<StackEntry> = vec![];
        op_numequalverify(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_numequalverify([1,2]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let b = op_numequalverify(&mut interpreter_stack);
        assert!(!b);
        /// op_numequalverify([1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_numequalverify(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_NUMNOTEQUAL
    fn test_numnotequal() {
        /// op_numnotequal([1,2]) -> [1]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_numnotequal(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_numnotequal([1,1]) -> [0]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(1));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_numnotequal(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_numnotequal([1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_numnotequal(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_LESSTHAN
    fn test_lessthan() {
        /// op_lessthan([1,2]) -> [1]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_lessthan(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_lessthan([1,1]) -> [0]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(1));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_lessthan(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_lessthan([1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_lessthan(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_GREATERTHAN
    fn test_greaterthan() {
        /// op_greaterthan([2,1]) -> [1]
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(2), StackEntry::Num(1)];
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_greaterthan(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_greaterthan([1,1]) -> [0]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(1));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_greaterthan(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_greaterthan([1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_greaterthan(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_LESSTHANOREQUAL
    fn test_lessthanorequal() {
        /// test_lessthanorequal([1,1]) -> [1]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(1));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_lessthanorequal(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_lessthanorequal([2,1]) -> [0]
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(2), StackEntry::Num(1)];
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_lessthanorequal(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_lessthanorequal([1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_lessthanorequal(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_GREATERTHANOREQUAL
    fn test_greaterthanorequal() {
        /// op_greaterthanorequal([1,1]) -> [1]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(1));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_greaterthanorequal(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_greaterthanorequal([1,2]) -> [0]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_greaterthanorequal(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_greaterthanorequal([1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_greaterthanorequal(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_MIN
    fn test_min() {
        /// op_min([1,2]) -> [1]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_min(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_min([1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_min(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_MAX
    fn test_max() {
        /// op_max([1,2]) -> [2]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(2)];
        op_max(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_max([1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_max(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_WITHIN
    fn test_within() {
        /// op_within([2,1,3]) -> [1]
        let mut interpreter_stack: Vec<StackEntry> =
            vec![StackEntry::Num(2), StackEntry::Num(1), StackEntry::Num(3)];
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_within(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_within([1,2,3]) -> [0]
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=3 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_within(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_within([1,2]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        for i in 1..=2 {
            interpreter_stack.push(StackEntry::Num(i));
        }
        let b = op_within(&mut interpreter_stack);
        assert!(!b)
    }

    /*---- CRYPTO OPS ----*/

    #[test]
    /// Test OP_SHA3
    fn test_sha3() {
        /// op_sha3(["hello"]) -> [sha3_256("hello")]
        let s = "hello".to_string();
        let h = hex::encode(sha3_256::digest(s.as_bytes()));
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Bytes(s)];
        let mut v: Vec<StackEntry> = vec![StackEntry::Bytes(h)];
        op_sha3(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_sha3([1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(1)];
        let b = op_sha3(&mut interpreter_stack);
        assert!(!b);
        /// op_sha3([]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let b = op_sha3(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_HASH256
    fn test_hash256() {
        /// op_hash256([pk]) -> [addr]
        let (pk, sk) = sign::gen_keypair();
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::PubKey(pk)];
        let mut v: Vec<StackEntry> = vec![StackEntry::PubKeyHash(construct_address(&pk))];
        op_hash256(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_hash256([]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let b = op_hash256(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_HASH256_V0
    fn test_hash256_v0() {
        /// op_hash256_v0([pk]) -> [addr_v0]
        let (pk, sk) = sign::gen_keypair();
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::PubKey(pk)];
        let mut v: Vec<StackEntry> = vec![StackEntry::PubKeyHash(construct_address_v0(&pk))];
        op_hash256v0(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_hash256([]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let b = op_hash256v0(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_HASH256_TEMP
    fn test_hash256_temp() {
        /// op_hash256_temp([pk]) -> [addr_temp]
        let (pk, sk) = sign::gen_keypair();
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::PubKey(pk)];
        let mut v: Vec<StackEntry> = vec![StackEntry::PubKeyHash(construct_address_temp(&pk))];
        op_hash256temp(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_hash256([]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        let b = op_hash256temp(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_CHECKSIG
    fn test_checksig() {
        /// op_checksig([msg,sig,pk]) -> [1]
        let (pk, sk) = sign::gen_keypair();
        let msg = hex::encode(vec![0, 0, 0]);
        let sig = sign::sign_detached(msg.as_bytes(), &sk);
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        interpreter_stack.push(StackEntry::Bytes(msg));
        interpreter_stack.push(StackEntry::Signature(sig));
        interpreter_stack.push(StackEntry::PubKey(pk));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_checksig(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_checksig([msg',sig,pk]) -> [0]
        let msg = hex::encode(vec![0, 0, 1]);
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        interpreter_stack.push(StackEntry::Bytes(msg));
        interpreter_stack.push(StackEntry::Signature(sig));
        interpreter_stack.push(StackEntry::PubKey(pk));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_checksig(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_checksig([sig,pk]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        interpreter_stack.push(StackEntry::Signature(sig));
        interpreter_stack.push(StackEntry::PubKey(pk));
        let b = op_checksig(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_CHECKSIGVERIFY
    fn test_checksigverify() {
        /// op_checksigverify([msg,sig,pk]) -> []
        let (pk, sk) = sign::gen_keypair();
        let msg = hex::encode(vec![0, 0, 0]);
        let sig = sign::sign_detached(msg.as_bytes(), &sk);
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        interpreter_stack.push(StackEntry::Bytes(msg));
        interpreter_stack.push(StackEntry::Signature(sig));
        interpreter_stack.push(StackEntry::PubKey(pk));
        let mut v: Vec<StackEntry> = vec![];
        op_checksigverify(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_checksigverify([msg',sig,pk]) -> fail
        let msg = hex::encode(vec![0, 0, 1]);
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        interpreter_stack.push(StackEntry::Bytes(msg));
        interpreter_stack.push(StackEntry::Signature(sig));
        interpreter_stack.push(StackEntry::PubKey(pk));
        let b = op_checksigverify(&mut interpreter_stack);
        assert!(!b);
        /// op_checksigverify([sig,pk]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        interpreter_stack.push(StackEntry::Signature(sig));
        interpreter_stack.push(StackEntry::PubKey(pk));
        let b = op_checksigverify(&mut interpreter_stack);
        assert!(!b)
    }

    #[test]
    /// Test OP_CHECKMULTISIG
    fn test_checkmultisig() {
        /// op_checkmultisig([msg,sig1,sig2,2,pk1,pk2,pk3,3]) -> [1]
        let (pk1, sk1) = sign::gen_keypair();
        let (pk2, sk2) = sign::gen_keypair();
        let (pk3, sk3) = sign::gen_keypair();
        let msg = hex::encode(vec![0, 0, 0]);
        let sig1 = sign::sign_detached(msg.as_bytes(), &sk1);
        let sig2 = sign::sign_detached(msg.as_bytes(), &sk2);
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Bytes(msg)];
        interpreter_stack.push(StackEntry::Signature(sig1));
        interpreter_stack.push(StackEntry::Signature(sig2));
        interpreter_stack.push(StackEntry::Num(2));
        interpreter_stack.push(StackEntry::PubKey(pk1));
        interpreter_stack.push(StackEntry::PubKey(pk2));
        interpreter_stack.push(StackEntry::PubKey(pk3));
        interpreter_stack.push(StackEntry::Num(3));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(1)];
        op_checkmultisig(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_checkmultisig([msg',sig1,sig2,2,pk1,pk2,pk3,3]) -> [0]
        let msg = hex::encode(vec![0, 0, 1]);
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Bytes(msg)];
        interpreter_stack.push(StackEntry::Signature(sig1));
        interpreter_stack.push(StackEntry::Signature(sig2));
        interpreter_stack.push(StackEntry::Num(2));
        interpreter_stack.push(StackEntry::PubKey(pk1));
        interpreter_stack.push(StackEntry::PubKey(pk2));
        interpreter_stack.push(StackEntry::PubKey(pk3));
        interpreter_stack.push(StackEntry::Num(3));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_checkmultisig(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_checkmultisig([msg,sig1,sig1,2,pk1,pk2,pk3,3]) -> [0]
        let msg = hex::encode(vec![0, 0, 0]);
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Bytes(msg)];
        interpreter_stack.push(StackEntry::Signature(sig1));
        interpreter_stack.push(StackEntry::Signature(sig1));
        interpreter_stack.push(StackEntry::Num(2));
        interpreter_stack.push(StackEntry::PubKey(pk1));
        interpreter_stack.push(StackEntry::PubKey(pk2));
        interpreter_stack.push(StackEntry::PubKey(pk3));
        interpreter_stack.push(StackEntry::Num(3));
        let mut v: Vec<StackEntry> = vec![StackEntry::Num(0)];
        op_checkmultisig(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_checkmultisig([MAX_PUB_KEYS_PER_MULTISIG+1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        interpreter_stack.push(StackEntry::Num(MAX_PUB_KEYS_PER_MULTISIG as usize + ONE));
        let b = op_checkmultisig(&mut interpreter_stack);
        assert!(!b);
        /// op_checkmultisig([pk1,pk2,3]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::PubKey(pk1)];
        interpreter_stack.push(StackEntry::PubKey(pk2));
        interpreter_stack.push(StackEntry::Num(3));
        let b = op_checkmultisig(&mut interpreter_stack);
        assert!(!b);
        /// op_checkmultisig([4,pk1,pk2,pk3,3]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(4)];
        interpreter_stack.push(StackEntry::PubKey(pk1));
        interpreter_stack.push(StackEntry::PubKey(pk2));
        interpreter_stack.push(StackEntry::PubKey(pk3));
        interpreter_stack.push(StackEntry::Num(3));
        let b = op_checkmultisig(&mut interpreter_stack);
        assert!(!b);
        /// op_checkmultisig([sig1,2,pk1,pk2,pk3,3]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Signature(sig1)];
        interpreter_stack.push(StackEntry::Num(2));
        interpreter_stack.push(StackEntry::PubKey(pk1));
        interpreter_stack.push(StackEntry::PubKey(pk2));
        interpreter_stack.push(StackEntry::PubKey(pk3));
        interpreter_stack.push(StackEntry::Num(3));
        let b = op_checkmultisig(&mut interpreter_stack);
        assert!(!b);
    }

    #[test]
    /// Test OP_CHECKMULTISIGVERIFY
    fn test_checkmultisigverify() {
        /// op_checkmultisigverify([msg,sig1,sig2,2,pk1,pk2,pk3,3]) -> []
        let (pk1, sk1) = sign::gen_keypair();
        let (pk2, sk2) = sign::gen_keypair();
        let (pk3, sk3) = sign::gen_keypair();
        let msg = hex::encode(vec![0, 0, 0]);
        let sig1 = sign::sign_detached(msg.as_bytes(), &sk1);
        let sig2 = sign::sign_detached(msg.as_bytes(), &sk2);
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Bytes(msg)];
        interpreter_stack.push(StackEntry::Signature(sig1));
        interpreter_stack.push(StackEntry::Signature(sig2));
        interpreter_stack.push(StackEntry::Num(2));
        interpreter_stack.push(StackEntry::PubKey(pk1));
        interpreter_stack.push(StackEntry::PubKey(pk2));
        interpreter_stack.push(StackEntry::PubKey(pk3));
        interpreter_stack.push(StackEntry::Num(3));
        let mut v: Vec<StackEntry> = vec![];
        op_checkmultisigverify(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_checkmultisigverify([msg',sig1,sig2,2,pk1,pk2,pk3,3]) -> fail
        let msg = hex::encode(vec![0, 0, 1]);
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Bytes(msg)];
        interpreter_stack.push(StackEntry::Signature(sig1));
        interpreter_stack.push(StackEntry::Signature(sig2));
        interpreter_stack.push(StackEntry::Num(2));
        interpreter_stack.push(StackEntry::PubKey(pk1));
        interpreter_stack.push(StackEntry::PubKey(pk2));
        interpreter_stack.push(StackEntry::PubKey(pk3));
        interpreter_stack.push(StackEntry::Num(3));
        let b = op_checkmultisigverify(&mut interpreter_stack);
        assert!(!b);
        /// op_checkmultisigverify([msg,sig1,sig1,2,pk1,pk2,pk3,3]) -> fail
        let msg = hex::encode(vec![0, 0, 0]);
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Bytes(msg)];
        interpreter_stack.push(StackEntry::Signature(sig1));
        interpreter_stack.push(StackEntry::Signature(sig1));
        interpreter_stack.push(StackEntry::Num(2));
        interpreter_stack.push(StackEntry::PubKey(pk1));
        interpreter_stack.push(StackEntry::PubKey(pk2));
        interpreter_stack.push(StackEntry::PubKey(pk3));
        interpreter_stack.push(StackEntry::Num(3));
        op_checkmultisigverify(&mut interpreter_stack);
        assert_eq!(interpreter_stack, v);
        /// op_checkmultisigverify([MAX_PUB_KEYS_PER_MULTISIG+1]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![];
        interpreter_stack.push(StackEntry::Num(MAX_PUB_KEYS_PER_MULTISIG as usize + ONE));
        let b = op_checkmultisigverify(&mut interpreter_stack);
        assert!(!b);
        /// op_checkmultisigverify([pk1,pk2,3]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::PubKey(pk1)];
        interpreter_stack.push(StackEntry::PubKey(pk2));
        interpreter_stack.push(StackEntry::Num(3));
        let b = op_checkmultisigverify(&mut interpreter_stack);
        assert!(!b);
        /// op_checkmultisigverify([4,pk1,pk2,pk3,3]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Num(4)];
        interpreter_stack.push(StackEntry::PubKey(pk1));
        interpreter_stack.push(StackEntry::PubKey(pk2));
        interpreter_stack.push(StackEntry::PubKey(pk3));
        interpreter_stack.push(StackEntry::Num(3));
        let b = op_checkmultisigverify(&mut interpreter_stack);
        assert!(!b);
        /// op_checkmultisigverify([sig1,2,pk1,pk2,pk3,3]) -> fail
        let mut interpreter_stack: Vec<StackEntry> = vec![StackEntry::Signature(sig1)];
        interpreter_stack.push(StackEntry::Num(2));
        interpreter_stack.push(StackEntry::PubKey(pk1));
        interpreter_stack.push(StackEntry::PubKey(pk2));
        interpreter_stack.push(StackEntry::PubKey(pk3));
        interpreter_stack.push(StackEntry::Num(3));
        let b = op_checkmultisig(&mut interpreter_stack);
        assert!(!b);
    }
}
