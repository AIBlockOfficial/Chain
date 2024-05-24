#![allow(unused)]
use crate::constants::*;
use crate::crypto::sha3_256;
use crate::crypto::sign_ed25519 as sign;
use crate::crypto::sign_ed25519::{PublicKey, Signature};
use crate::primitives::asset::{Asset, TokenAmount};
use crate::primitives::transaction::*;
use crate::script::lang::{ConditionStack, Script, Stack};
use crate::script::{OpCodes, ScriptError, StackEntry};
use crate::utils::transaction_utils::construct_address;
use bincode::de;
use bincode::serialize;
use bytes::Bytes;
use hex::encode;
use std::collections::BTreeMap;
use tracing::{debug, error, info, trace};
use tracing_subscriber::field::debug;

/*---- FLOW CONTROL OPS ----*/

/// OP_NOP: Does nothing
///
/// Example: OP_NOP([x]) -> [x]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_nop(stack: &mut Stack) -> Result<(), ScriptError> {
    Ok(())
}

/// OP_IF: Checks if the top item on the stack is not ZERO and executes the next block of instructions
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
/// * `cond_stack`  - mutable reference to the condition stack
pub fn op_if(stack: &mut Stack, cond_stack: &mut ConditionStack) -> Result<(), ScriptError> {
    let cond = if cond_stack.all_true() {
        let n = pop_num(stack)?;
        n != ZERO
    } else {
        false
    };
    cond_stack.push(cond);
    Ok(())
}

/// OP_NOTIF: Checks if the top item on the stack is ZERO and executes the next block of instructions
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
/// * `cond_stack`  - mutable reference to the condition stack
pub fn op_notif(stack: &mut Stack, cond_stack: &mut ConditionStack) -> Result<(), ScriptError> {
    let cond = if cond_stack.all_true() {
        let n = pop_num(stack)?;
        n == ZERO
    } else {
        false
    };
    cond_stack.push(cond);
    Ok(())
}

/// OP_ELSE: Executes the next block of instructions if the previous OP_IF or OP_NOTIF was not executed
///
/// ### Arguments
///
/// * `cond_stack`  - mutable reference to the condition stack
pub fn op_else(cond_stack: &mut ConditionStack) -> Result<(), ScriptError> {
    if cond_stack.is_empty() {
        return Err(ScriptError::EmptyCondition);
    }
    cond_stack.toggle();
    Ok(())
}

/// OP_ENDIF: Ends an OP_IF or OP_NOTIF block
///
/// ### Arguments
///
/// * `cond_stack`  - mutable reference to the condition stack
pub fn op_endif(cond_stack: &mut ConditionStack) -> Result<(), ScriptError> {
    if cond_stack.is_empty() {
        return Err(ScriptError::EmptyCondition);
    }
    cond_stack.pop();
    Ok(())
}

/// OP_VERIFY: Removes the top item from the stack and ends execution with an error if it is ZERO
///
/// Example: OP_VERIFY([x]) -> []   if x != 0
///          OP_VERIFY([x]) -> fail if x == 0
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_verify(stack: &mut Stack) -> Result<(), ScriptError> {
    let x = pop_num(stack)?;
    if x == ZERO {
        return Err(ScriptError::Verify);
    }
    Ok(())
}

/// OP_BURN: Ends execution with an error
///
/// Example: OP_BURN([x]) -> fail
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_burn(stack: &mut Stack) -> Result<(), ScriptError> {
    Err(ScriptError::Burn)
}

/*---- STACK OPS ----*/

/// OP_TOALTSTACK: Moves the top item from the main stack to the top of the alt stack
///                
///
/// Example: OP_TOALTSTACK([x], []) -> [], [x]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_toaltstack(stack: &mut Stack) -> Result<(), ScriptError> {
    let x = stack.pop()?;
    stack.push_alt(x)
}

/// OP_FROMALTSTACK: Moves the top item from the alt stack to the top of the main stack
///                  
/// Example: OP_FROMALTSTACK([], [x]) -> [x], []
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_fromaltstack(stack: &mut Stack) -> Result<(), ScriptError> {
    let x = stack.pop_alt()?;
    stack.push(x)
}

/// OP_2DROP: Removes the top two items from the stack
///
/// Example: OP_2DROP([x1, x2]) -> []
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_2drop(stack: &mut Stack) -> Result<(), ScriptError> {
    stack.pop()?;
    stack.pop()?;
    Ok(())
}

/// OP_2DUP: Duplicates the top two items on the stack
///
/// Example: OP_2DUP([x1, x2]) -> [x1, x2, x1, x2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_2dup(stack: &mut Stack) -> Result<(), ScriptError> {
    let len = stack.depth();
    if len < TWO {
        return Err(ScriptError::StackEmpty);
    }
    stack.main_stack.extend_from_within(len - TWO..);
    Ok(())
}

/// OP_3DUP: Duplicates the top three items on the stack
///
/// Example: OP_3DUP([x1, x2, x3]) -> [x1, x2, x3, x1, x2, x3]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_3dup(stack: &mut Stack) -> Result<(), ScriptError> {
    let len = stack.depth();
    if len < THREE {
        return Err(ScriptError::StackEmpty);
    }
    stack.main_stack.extend_from_within(len - THREE..);
    Ok(())
}

/// OP_2OVER: Copies the second-to-top pair of items to the top of the stack
///           
/// Example: OP_2OVER([x1, x2, x3, x4]) -> [x1, x2, x3, x4, x1, x2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_2over(stack: &mut Stack) -> Result<(), ScriptError> {
    let len = stack.depth();
    if len < FOUR {
        return Err(ScriptError::StackEmpty);
    }
    stack.main_stack.extend_from_within(len - FOUR..len - TWO);
    Ok(())
}

/// OP_2ROT: Moves the third-to-top pair of items to the top of the stack
///          
/// Example: OP_2ROT([x1, x2, x3, x4, x5, x6]) -> [x3, x4, x5, x6, x1, x2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_2rot(stack: &mut Stack) -> Result<(), ScriptError> {
    let len = stack.depth();
    if len < SIX {
        return Err(ScriptError::StackEmpty);
    }
    let items = stack.main_stack[len - SIX..len - FOUR].to_vec();
    stack.main_stack.drain(len - SIX..len - FOUR);
    stack.main_stack.extend_from_slice(&items);
    Ok(())
}

/// OP_2SWAP: Swaps the top two pairs of items on the stack
///
/// Example: OP_2SWAP([x1, x2, x3, x4]) -> [x3, x4, x1, x2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_2swap(stack: &mut Stack) -> Result<(), ScriptError> {
    let len = stack.depth();
    if len < FOUR {
        return Err(ScriptError::StackEmpty);
    }
    stack.main_stack.swap(len - FOUR, len - TWO);
    stack.main_stack.swap(len - THREE, len - ONE);
    Ok(())
}

/// OP_IFDUP: Duplicates the top item on the stack if it is not ZERO
///           
/// Example: OP_IFDUP([x]) -> [x, x] if x != 0
///          OP_IFDUP([x]) -> [x]    if x == 0
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_ifdup(stack: &mut Stack) -> Result<(), ScriptError> {
    let x = stack.peek()?;
    if *x != StackEntry::Num(ZERO) {
        stack.push(x.clone())
    } else {
        Ok(())
    }
}

/// OP_DEPTH: Pushes the stack size onto the stack
///
/// Example: OP_DEPTH([x1, x2, x3, x4]) -> [x1, x2, x3, x4, 4]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_depth(stack: &mut Stack) -> Result<(), ScriptError> {
    stack.push(StackEntry::Num(stack.depth()))
}

/// OP_DROP: Removes the top item from the stack
///
/// Example: OP_DROP([x]) -> []
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_drop(stack: &mut Stack) -> Result<(), ScriptError> {
    stack.pop()?;
    Ok(())
}

/// OP_DUP: Duplicates the top item on the stack
///
/// Example: OP_DUP([x]) -> [x, x]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_dup(stack: &mut Stack) -> Result<(), ScriptError> {
    stack.push(stack.last()?)
}

/// OP_NIP: Removes the second-to-top item from the stack
///
/// Example: OP_NIP([x1, x2]) -> [x2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_nip(stack: &mut Stack) -> Result<(), ScriptError> {
    let len = stack.depth();
    if len < TWO {
        return Err(ScriptError::StackEmpty);
    }
    stack.main_stack.remove(len - TWO);
    Ok(())
}

/// OP_OVER: Copies the second-to-top item to the top of the stack
///
/// Example: OP_OVER([x1, x2]) -> [x1, x2, x1]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_over(stack: &mut Stack) -> Result<(), ScriptError> {
    let len = stack.depth();
    if len < TWO {
        return Err(ScriptError::StackEmpty);
    }
    let x1 = stack.main_stack[len - TWO].clone();
    stack.push(x1)
}

/// OP_PICK: Copies the (n+1)th-to-top item to the top of the stack, where n is the top item on the stack
///
/// Example: OP_PICK([x, x2, x1, x0, 3]) -> [x, x2, x1, x0, x]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_pick(stack: &mut Stack) -> Result<(), ScriptError> {
    let n = pop_num(stack)?;
    let len = stack.depth();
    if n >= len {
        return Err(ScriptError::StackIndexBounds(n, len));
    }
    let x = stack.main_stack[len - ONE - n].clone();
    stack.push(x)
}

/// OP_ROLL: Moves the (n+1)th-to-top item to the top of the stack, where n is the top item on the stack
///
/// Example: OP_ROLL([x, x2, x1, x0, 3]) -> [x2, x1, x0, x]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_roll(stack: &mut Stack) -> Result<(), ScriptError> {
    let n = pop_num(stack)?;
    let len = stack.depth();
    if n >= len {
        return Err(ScriptError::StackIndexBounds(n, len));
    }
    let x = stack.main_stack.remove(len - ONE - n);
    stack.push(x)
}

/// OP_ROT: Moves the third-to-top item to the top of the stack
///
/// Example: OP_ROT([x1, x2, x3]) -> [x2, x3, x1]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_rot(stack: &mut Stack) -> Result<(), ScriptError> {
    let len = stack.depth();
    if len < THREE {
        return Err(ScriptError::StackEmpty);
    }
    stack.main_stack.swap(len - THREE, len - TWO);
    stack.main_stack.swap(len - TWO, len - ONE);
    Ok(())
}

/// OP_SWAP: Swaps the top two items on the stack
///
/// Example: OP_SWAP([x1, x2]) -> [x2, x1]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_swap(stack: &mut Stack) -> Result<(), ScriptError> {
    let len = stack.depth();
    if len < TWO {
        return Err(ScriptError::StackEmpty);
    }
    stack.main_stack.swap(len - TWO, len - ONE);
    Ok(())
}

/// OP_TUCK: Copies the top item behind the second-to-top item on the stack
///
/// Example: OP_TUCK([x1, x2]) -> [x2, x1, x2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_tuck(stack: &mut Stack) -> Result<(), ScriptError> {
    let len = stack.depth();
    if len < TWO {
        return Err(ScriptError::StackEmpty);
    }
    let x2 = stack.main_stack[len - ONE].clone();
    stack.main_stack.insert(len - TWO, x2); // TODO: this doesn't enforce the stack validity rules
    Ok(())
}

/*---- SPLICE OPS ----*/

/// OP_CAT: Concatenates the two strings on top of the stack
///
/// Example: OP_CAT([s1, s2]) -> [s1s2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_cat(stack: &mut Stack) -> Result<(), ScriptError> {
    let s2 = pop_bytes(stack)?;
    let s1 = pop_bytes(stack)?;
    let cat = [s1, s2].concat();
    stack.push(StackEntry::Bytes(cat))
}

/// OP_SUBSTR: Extracts a substring from the third-to-top item on the stack
///
/// Example: OP_SUBSTR([s, n1, n2]) -> [s[n1..n1+n2-1]]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_substr(stack: &mut Stack) -> Result<(), ScriptError> {
    let n2 = pop_num(stack)?;
    let n1 = pop_num(stack)?;
    let s = pop_bytes(stack)?;
    // TODO: As this was previously a hex string, the indices don't exactly correspond to what
    //       they did originally. However, I don't think there are any existing transactions
    //       on the chain which actually use this opcode, so I'm fairly confident it won't
    //       matter. Double-check that this is the case before merging!
    if n1 >= s.len() || n2 > s.len() || n1 + n2 > s.len() {
        return Err(ScriptError::SliceBounds(n1, n2, s.len()))
    }
    let substr = s[n1..n1 + n2].to_vec();
    stack.push(StackEntry::Bytes(substr))
}

/// OP_LEFT: Extracts a left substring from the second-to-top item on the stack
///
/// Example: OP_LEFT([s, n]) -> [s[..n-1]] if n < len(s)
///          OP_LEFT([s, n]) -> [s]        if n >= len(s)
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_left(stack: &mut Stack) -> Result<(), ScriptError> {
    let n = pop_num(stack)?;
    let s = pop_bytes(stack)?;
    if n >= s.len() {
        stack.push(StackEntry::Bytes(s))
    } else {
        // TODO: As this was previously a hex string, the indices don't exactly correspond to what
        //       they did originally. However, I don't think there are any existing transactions
        //       on the chain which actually use this opcode, so I'm fairly confident it won't
        //       matter. Double-check that this is the case before merging!
        let left = s[..n].to_vec();
        stack.push(StackEntry::Bytes(left))
    }
}

/// OP_RIGHT: Extracts a right substring from the second-to-top item on the stack
///
/// Example: OP_RIGHT([s, n]) -> [s[n..]] if n < len(s)
///          OP_RIGHT([s, n]) -> [""]     if n >= len(s)
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_right(stack: &mut Stack) -> Result<(), ScriptError> {
    let n = pop_num(stack)?;
    let s = pop_bytes(stack)?;
    if n >= s.len() {
        stack.push(StackEntry::Bytes(Vec::new()))
    } else {
        // TODO: As this was previously a hex string, the indices don't exactly correspond to what
        //       they did originally. However, I don't think there are any existing transactions
        //       on the chain which actually use this opcode, so I'm fairly confident it won't
        //       matter. Double-check that this is the case before merging!
        let right = s[n..].to_vec();
        stack.push(StackEntry::Bytes(right))
    }
}

/// OP_SIZE: Computes the size in bytes of the string on top of the stack
///
/// Example: OP_SIZE([s]) -> [s, len(s)]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_size(stack: &mut Stack) -> Result<(), ScriptError> {
    let len = peek_bytes(&stack)?.len();
    // TODO: As this was previously a hex string, the length doesn't exactly correspond to what
    //       it did originally. However, I don't think there are any existing transactions
    //       on the chain which actually use this opcode, so I'm fairly confident it won't
    //       matter. Double-check that this is the case before merging!
    stack.push(StackEntry::Num(len))
}

/*---- BITWISE LOGIC OPS ----*/

/// OP_INVERT: Computes bitwise NOT of the number on top of the stack
///
/// Example: OP_INVERT([n]) -> [!n]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_invert(stack: &mut Stack) -> Result<(), ScriptError> {
    let n = pop_num(stack)?;
    stack.push(StackEntry::Num(!n))
}

/// OP_AND: Computes bitwise AND between the two numbers on top of the stack
///
/// Example: OP_AND([n1, n2]) -> [n1&n2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_and(stack: &mut Stack) -> Result<(), ScriptError> {
    let n2 = pop_num(stack)?;
    let n1 = pop_num(stack)?;
    stack.push(StackEntry::Num(n1 & n2))
}

/// OP_OR: Computes bitwise OR between the two numbers on top of the stack
///
/// Example: OP_OR([n1, n2]) -> [n1|n2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_or(stack: &mut Stack) -> Result<(), ScriptError> {
    let n2 = pop_num(stack)?;
    let n1 = pop_num(stack)?;
    stack.push(StackEntry::Num(n1 | n2))
}

/// OP_XOR: Computes bitwise XOR between the two numbers on top of the stack
///
/// Example: OP_XOR([n1, n2]) -> [n1^n2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_xor(stack: &mut Stack) -> Result<(), ScriptError> {
    let n2 = pop_num(stack)?;
    let n1 = pop_num(stack)?;
    stack.push(StackEntry::Num(n1 ^ n2))
}

/// OP_EQUAL: Substitutes the top two items on the stack with ONE if they are equal, with ZERO otherwise.
///
/// Example: OP_EQUAL([x1, x2]) -> [1] if x1 == x2
///          OP_EQUAL([x1, x2]) -> [0] if x1 != x2
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_equal(stack: &mut Stack) -> Result<(), ScriptError> {
    let x2 = stack.pop()?;
    let x1 = stack.pop()?;
    if x1 == x2 {
        stack.push(StackEntry::Num(ONE))
    } else {
        stack.push(StackEntry::Num(ZERO))
    }
}

/// OP_EQUALVERIFY: Computes OP_EQUAL and OP_VERIFY in sequence
///
/// Example: OP_EQUALVERIFY([x1, x2]) -> []   if x1 == x2
///          OP_EQUALVERIFY([x1, x2]) -> fail if x1 != x2
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_equalverify(stack: &mut Stack) -> Result<(), ScriptError> {
    let x2 = stack.pop()?;
    let x1 = stack.pop()?;
    if x1 != x2 {
        return Err(ScriptError::ItemsNotEqual);
    }
    Ok(())
}

/*---- ARITHMETIC OPS ----*/

/// OP_1ADD: Adds ONE to the number on top of the stack
///
/// Example: OP_1ADD([n]) -> [n+1]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_1add(stack: &mut Stack) -> Result<(), ScriptError> {
    let n = pop_num(stack)?;
    match n.checked_add(ONE) {
        Some(n) => stack.push(StackEntry::Num(n)),
        _ => Err(ScriptError::Overflow),
    }
}

/// OP_1SUB: Subtracts ONE from the number on top of the stack.
///
/// Example: OP_1SUB([n]) -> [n-1]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_1sub(stack: &mut Stack) -> Result<(), ScriptError> {
    let n = pop_num(stack)?;
    match n.checked_sub(ONE) {
        Some(n) => stack.push(StackEntry::Num(n)),
        _ => Err(ScriptError::Overflow),
    }
}

/// OP_2MUL: Multiplies by TWO the number on top of the stack
///
/// Example: OP_2MUL([n]) -> [n*2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_2mul(stack: &mut Stack) -> Result<(), ScriptError> {
    let n = pop_num(stack)?;
    match n.checked_mul(TWO) {
        Some(n) => stack.push(StackEntry::Num(n)),
        _ => Err(ScriptError::Overflow),
    }
}

/// OP_2DIV: Divides by TWO the number on top of the stack
///
/// Example: OP_2DIV([n]) -> [n/2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_2div(stack: &mut Stack) -> Result<(), ScriptError> {
    let n = pop_num(stack)?;
    stack.push(StackEntry::Num(n / TWO))
}

/// OP_NOT: Substitutes the number on top of the stack with ONE if it is equal to ZERO, with ZERO otherwise
///
/// Example: OP_NOT([n]) -> [1] if n == 0
///          OP_NOT([n]) -> [0] if n != 0
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_not(stack: &mut Stack) -> Result<(), ScriptError> {
    let n = pop_num(stack)?;
    if n == ZERO {
        stack.push(StackEntry::Num(ONE))
    } else {
        stack.push(StackEntry::Num(ZERO))
    }
}

/// OP_0NOTEQUAL: Substitutes the number on top of the stack with ONE if it is not equal to ZERO, with ZERO otherwise
///
/// Example: OP_0NOTEQUAL([n]) -> [1] if n != 0
///          OP_0NOTEQUAL([n]) -> [0] if n == 0
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_0notequal(stack: &mut Stack) -> Result<(), ScriptError> {
    let n = pop_num(stack)?;
    if n != ZERO {
        stack.push(StackEntry::Num(ONE))
    } else {
        stack.push(StackEntry::Num(ZERO))
    }
}

/// OP_ADD: Adds the two numbers on top of the stack
///
/// Example: OP_ADD([n1, n2]) -> [n1+n2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_add(stack: &mut Stack) -> Result<(), ScriptError> {
    let n2 = pop_num(stack)?;
    let n1 = pop_num(stack)?;
    match n1.checked_add(n2) {
        Some(n) => stack.push(StackEntry::Num(n)),
        _ => Err(ScriptError::Overflow),
    }
}

/// OP_SUB: Subtracts the number on top of the stack from the second-to-top number on the stack
///
/// Example: OP_SUB([n1, n2]) -> [n1-n2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_sub(stack: &mut Stack) -> Result<(), ScriptError> {
    let n2 = pop_num(stack)?;
    let n1 = pop_num(stack)?;
    match n1.checked_sub(n2) {
        Some(n) => stack.push(StackEntry::Num(n)),
        _ => Err(ScriptError::Overflow),
    }
}

/// OP_MUL: Multiplies the second-to-top number by the number on top of the stack
///
/// Example: OP_MUL([n1, n2]) -> [n1*n2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_mul(stack: &mut Stack) -> Result<(), ScriptError> {
    let n2 = pop_num(stack)?;
    let n1 = pop_num(stack)?;
    match n1.checked_mul(n2) {
        Some(n) => stack.push(StackEntry::Num(n)),
        _ => Err(ScriptError::Overflow),
    }
}

/// OP_DIV: Divides the second-to-top number by the number on top of the stack
///
/// Example: OP_DIV([n1, n2]) -> [n1/n2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_div(stack: &mut Stack) -> Result<(), ScriptError> {
    let n2 = pop_num(stack)?;
    let n1 = pop_num(stack)?;
    match n1.checked_div(n2) {
        Some(n) => stack.push(StackEntry::Num(n)),
        _ => Err(ScriptError::DivideByZero),
    }
}

/// OP_MOD: Computes the remainder of the division of the second-to-top number by the number on top of the stack
///
/// Example: OP_MOD([n1, n2]) -> [n1%n2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_mod(stack: &mut Stack) -> Result<(), ScriptError> {
    let n2 = pop_num(stack)?;
    let n1 = pop_num(stack)?;
    match n1.checked_rem(n2) {
        Some(n) => stack.push(StackEntry::Num(n)),
        _ => Err(ScriptError::DivideByZero),
    }
}

/// OP_LSHIFT: Computes the left shift of the second-to-top number by the number on top of the stack
///
/// Example: OP_LSHIFT([n1, n2]) -> [n1<<n2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_lshift(stack: &mut Stack) -> Result<(), ScriptError> {
    let n2 = pop_num(stack)?;
    let n1 = pop_num(stack)?;
    match n1.checked_shl(n2 as u32) {
        Some(n) => stack.push(StackEntry::Num(n)),
        _ => Err(ScriptError::DivideByZero),
    }
}

/// OP_RSHIFT: Computes the right shift of the second-to-top number by the number on top of the stack
///
/// Example: OP_RSHIFT([n1, n2]) -> [n1>>n2]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_rshift(stack: &mut Stack) -> Result<(), ScriptError> {
    let n2 = pop_num(stack)?;
    let n1 = pop_num(stack)?;
    match n1.checked_shr(n2 as u32) {
        Some(n) => stack.push(StackEntry::Num(n)),
        _ => Err(ScriptError::DivideByZero),
    }
}

/// OP_BOOLAND: Substitutes the two numbers on top of the stack with ONE if they are both non-zero, with ZERO otherwise
///
/// Example: OP_BOOLAND([n1, n2]) -> [1] if n1 != 0 and n2 != 0
///          OP_BOOLAND([n1, n2]) -> [0] if n1 == 0 or n2 == 0
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_booland(stack: &mut Stack) -> Result<(), ScriptError> {
    let n2 = pop_num(stack)?;
    let n1 = pop_num(stack)?;
    if n1 != ZERO && n2 != ZERO {
        stack.push(StackEntry::Num(ONE))
    } else {
        stack.push(StackEntry::Num(ZERO))
    }
}

/// OP_BOOLOR: Substitutes the two numbers on top of the stack with ONE if they are not both ZERO, with ZERO otherwise
///
/// Example: OP_BOOLOR([n1, n2]) -> [1] if n1 != 0 or n2 != 0
///          OP_BOOLOR([n1, n2]) -> [0] if n1 == 0 and n2 == 0
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_boolor(stack: &mut Stack) -> Result<(), ScriptError> {
    let n2 = pop_num(stack)?;
    let n1 = pop_num(stack)?;
    if n1 != ZERO || n2 != ZERO {
        stack.push(StackEntry::Num(ONE))
    } else {
        stack.push(StackEntry::Num(ZERO))
    }
}

/// OP_NUMEQUAL: Substitutes the two numbers on top of the stack with ONE if they are equal, with ZERO otherwise
///
/// Example: OP_NUMEQUAL([n1, n2]) -> [1] if n1 == n2
///          OP_NUMEQUAL([n1, n2]) -> [0] if n1 != n2
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_numequal(stack: &mut Stack) -> Result<(), ScriptError> {
    let n2 = pop_num(stack)?;
    let n1 = pop_num(stack)?;
    if n1 == n2 {
        stack.push(StackEntry::Num(ONE))
    } else {
        stack.push(StackEntry::Num(ZERO))
    }
}

/// OP_NUMEQUALVERIFY: Computes OP_NUMEQUAL and OP_VERIFY in sequence
///
/// Example: OP_NUMEQUALVERIFY([n1, n2]) -> []   if n1 == n2
///          OP_NUMEQUALVERIFY([n1, n2]) -> fail if n1 != n2
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_numequalverify(stack: &mut Stack) -> Result<(), ScriptError> {
    let n2 = pop_num(stack)?;
    let n1 = pop_num(stack)?;
    if n1 != n2 {
        return Err(ScriptError::ItemsNotEqual);
    }
    Ok(())
}

/// OP_NUMNOTEQUAL: Substitutes the two numbers on top of the stack with ONE if they are not equal, with ZERO otherwise
///
/// Example: OP_NUMNOTEQUAL([n1, n2]) -> [1] if n1 != n2
///          OP_NUMNOTEQUAL([n1, n2]) -> [0] if n1 == n2
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_numnotequal(stack: &mut Stack) -> Result<(), ScriptError> {
    let n2 = pop_num(stack)?;
    let n1 = pop_num(stack)?;
    if n1 != n2 {
        stack.push(StackEntry::Num(ONE))
    } else {
        stack.push(StackEntry::Num(ZERO))
    }
}

/// OP_LESSTHAN: Substitutes the two numbers on top of the stack with ONE if the second-to-top is less than the top item, with ZERO otherwise
///
/// Example: OP_LESSTHAN([n1, n2]) -> [1] if n1 < n2
///          OP_LESSTHAN([n1, n2]) -> [0] if n1 >= n2
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_lessthan(stack: &mut Stack) -> Result<(), ScriptError> {
    let n2 = pop_num(stack)?;
    let n1 = pop_num(stack)?;
    if n1 < n2 {
        stack.push(StackEntry::Num(ONE))
    } else {
        stack.push(StackEntry::Num(ZERO))
    }
}

/// OP_GREATERTHAN: Substitutes the two numbers on top of the stack with ONE if the second-to-top is greater than the top item, with ZERO otherwise
///
/// Example: OP_GREATERTHAN([n1, n2]) -> [1] if n1 > n2
///          OP_GREATERTHAN([n1, n2]) -> [0] if n1 <= n2
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_greaterthan(stack: &mut Stack) -> Result<(), ScriptError> {
    let n2 = pop_num(stack)?;
    let n1 = pop_num(stack)?;
    if n1 > n2 {
        stack.push(StackEntry::Num(ONE))
    } else {
        stack.push(StackEntry::Num(ZERO))
    }
}

/// OP_LESSTHANOREQUAL: Substitutes the two numbers on top of the stack with ONE if the second-to-top is less than or equal to the top item, with ZERO otherwise
///
/// Example: OP_LESSTHANOREQUAL([n1, n2]) -> [1] if n1 <= n2
///          OP_LESSTHANOREQUAL([n1, n2]) -> [0] if n1 > n2
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_lessthanorequal(stack: &mut Stack) -> Result<(), ScriptError> {
    let n2 = pop_num(stack)?;
    let n1 = pop_num(stack)?;
    if n1 <= n2 {
        stack.push(StackEntry::Num(ONE))
    } else {
        stack.push(StackEntry::Num(ZERO))
    }
}

/// OP_GREATERTHANOREQUAL: Substitutes the two numbers on top of the stack with ONE if the second-to-top is greater than or equal to the top item, with ZERO otherwise
///
/// Example: OP_GREATERTHANOREQUAL([n1, n2]) -> [1] if n1 >= n2
///          OP_GREATERTHANOREQUAL([n1, n2]) -> [0] if n1 < n2
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_greaterthanorequal(stack: &mut Stack) -> Result<(), ScriptError> {
    let n2 = pop_num(stack)?;
    let n1 = pop_num(stack)?;
    if n1 >= n2 {
        stack.push(StackEntry::Num(ONE))
    } else {
        stack.push(StackEntry::Num(ZERO))
    }
}

/// OP_MIN: Substitutes the two numbers on top of the stack with the minimum between the two
///
/// Example: OP_MIN([n1, n2]) -> [n1] if n1 <= n2
///          OP_MIN([n1, n2]) -> [n2] if n1 > n2
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_min(stack: &mut Stack) -> Result<(), ScriptError> {
    let n2 = pop_num(stack)?;
    let n1 = pop_num(stack)?;
    stack.push(StackEntry::Num(n1.min(n2)))
}

/// OP_MAX: Substitutes the two numbers on top of the stack with the maximum between the two
///
/// Example: OP_MAX([n1, n2]) -> [n1] if n1 >= n2
///          OP_MAX([n1, n2]) -> [n2] if n1 < n2
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_max(stack: &mut Stack) -> Result<(), ScriptError> {
    let n2 = pop_num(stack)?;
    let n1 = pop_num(stack)?;
    stack.push(StackEntry::Num(n1.max(n2)))
}

/// OP_WITHIN: Substitutes the three numbers on top of the the stack with ONE if the third-to-top is greater or equal to the second-to-top and less than the top item, with ZERO otherwise
///
/// Example: OP_WITHIN([n1, n2, n3]) -> [1] if n1 >= n2 and n1 < n3
///          OP_WITHIN([n1, n2, n3]) -> [0] if n1 < n2 or n1 >= n3
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_within(stack: &mut Stack) -> Result<(), ScriptError> {
    let n3 = pop_num(stack)?;
    let n2 = pop_num(stack)?;
    let n1 = pop_num(stack)?;
    if n1 >= n2 && n1 < n3 {
        stack.push(StackEntry::Num(ONE))
    } else {
        stack.push(StackEntry::Num(ZERO))
    }
}

/*---- CRYPTO OPS ----*/

/// OP_SHA3: Hashes the top item on the stack using SHA3-256
///
/// Example: OP_SHA3([x]) -> [SHA3-256(x)]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_sha3(stack: &mut Stack) -> Result<(), ScriptError> {
    let data = match stack.pop()? {
        StackEntry::Signature(sig) => sig.as_ref().to_owned(),
        StackEntry::PubKey(pk) => pk.as_ref().to_owned(),
        StackEntry::Bytes(s) => {
            // For legacy reasons, the hashed data is the hex representation of the data rather than
            // the data itself.
            hex::encode(&s).as_bytes().to_owned()
        },
        _ => return Err(ScriptError::ItemType),
    };
    let hash = sha3_256::digest(&data).to_vec();
    // TODO: Originally, the hash was converted back to hex!
    stack.push(StackEntry::Bytes(hash))
}

/// OP_HASH256: Creates standard address from public key and pushes it onto the stack
///
/// Example: OP_HASH256([pk]) -> [addr]
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_hash256(stack: &mut Stack) -> Result<(), ScriptError> {
    let pk = pop_pubkey(stack)?;
    let addr = construct_address(&pk);
    stack.push(StackEntry::Bytes(hex::decode(addr).unwrap()))
}

/// OP_CHECKSIG: Pushes ONE onto the stack if the signature is valid, ZERO otherwise
///
/// Example: OP_CHECKSIG([msg, sig, pk]) -> [1] if Verify(sig, msg, pk) == 1
///          OP_CHECKSIG([msg, sig, pk]) -> [0] if Verify(sig, msg, pk) == 0
///
/// Info: It allows signature verification on arbitrary messsages, not only transactions
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_checksig(stack: &mut Stack) -> Result<(), ScriptError> {
    let pk = pop_pubkey(stack)?;
    let sig = pop_sig(stack)?;
    let msg = pop_bytes(stack)?;

    // For legacy reasons, the signed message is the hex representation of the message rather than
    // the message itself.
    let msg_hex = hex::encode(msg);

    trace!("Signature: {:?}", msg_hex);
    if (!sign::verify_detached(&sig, msg_hex.as_bytes(), &pk)) {
        trace!("Signature verification failed");
        stack.push(StackEntry::Num(ZERO))
    } else {
        trace!("Signature verification succeeded");
        stack.push(StackEntry::Num(ONE))
    }
}

/// OP_CHECKSIGVERIFY: Runs OP_CHECKSIG and OP_VERIFY in sequence
///
/// Example: OP_CHECKSIGVERIFY([msg, sig, pk]) -> []   if Verify(sig, msg, pk) == 1
///          OP_CHECKSIGVERIFY([msg, sig, pk]) -> fail if Verify(sig, msg, pk) == 0
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_checksigverify(stack: &mut Stack) -> Result<(), ScriptError> {
    op_checksig(stack)?;
    op_verify(stack)
}

/// OP_CHECKMULTISIG: Pushes ONE onto the stack if the m-of-n multi-signature is valid, ZERO otherwise
///
/// Example: OP_CHECKMULTISIG([msg, sig1, sig2, m, pk1, pk2, pk3, n]) -> [1] if Verify(sig1, sig2, msg, pk1, pk2, pk3) == 1
///          OP_CHECKMULTISIG([msg, sig1, sig2, m, pk1, pk2, pk3, n]) -> [0] if Verify(sig1, sig2, msg, pk1, pk2, pk3) == 0
///
/// Info: It allows multi-signature verification on arbitrary messsages, not only transactions
///       Ordering of signatures and public keys is not relevant
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_checkmultisig(stack: &mut Stack) -> Result<(), ScriptError> {
    let n = pop_num(stack)?;
    if n > MAX_PUB_KEYS_PER_MULTISIG as usize {
        return Err(ScriptError::NumPubkeys);
    }
    let mut pks = Vec::with_capacity(n);
    for i in 0..n {
        if let Ok(StackEntry::PubKey(pk)) = stack.pop() {
            pks.push(pk);
        }
    }
    if pks.len() != n {
        return Err(ScriptError::NumPubkeys);
    }
    let m = pop_num(stack)?;
    if m > n {
        return Err(ScriptError::NumSignatures);
    }
    let mut sigs = Vec::with_capacity(m);
    for i in 0..m {
        if let Ok(StackEntry::Signature(sig)) = stack.pop() {
            sigs.push(sig);
        }
    }
    if sigs.len() != m {
        return Err(ScriptError::NumSignatures);
    }
    let msg = pop_bytes(stack)?;
    if !verify_multisig(&sigs, &msg, &mut pks) {
        stack.push(StackEntry::Num(ZERO))
    } else {
        stack.push(StackEntry::Num(ONE))
    }
}

/// OP_CHECKMULTISIGVERIFY: Runs OP_CHECKMULTISIG and OP_VERIFY in sequence
///
/// Example: OP_CHECKMULTISIGVERIFY([msg, sig1, sig2, m, pk1, pk2, pk3, n]) -> []   if Verify(sig1, sig2, msg, pk1, pk2, pk3) == 1
///          OP_CHECKMULTISIGVERIFY([msg, sig1, sig2, m, pk1, pk2, pk3, n]) -> fail if Verify(sig1, sig2, msg, pk1, pk2, pk3) == 0
///
/// ### Arguments
///
/// * `stack`  - mutable reference to the stack
pub fn op_checkmultisigverify(stack: &mut Stack) -> Result<(), ScriptError> {
    op_checkmultisig(stack)?;
    op_verify(stack)
}

/// Verifies an m-of-n multi-signature
///
/// ### Arguments
///
/// * `sigs` - signatures to verify
/// * `msg`  - data to verify against
/// * `pks`  - public keys to match against
fn verify_multisig(sigs: &[Signature], msg: &[u8], pks: &mut Vec<PublicKey>) -> bool {
    // For legacy reasons, the signed message is the hex representation of the message rather than
    // the message itself.
    let msg_hex = hex::encode(msg);

    let mut num_valid_sigs = ZERO;
    for sig in sigs {
        if let Some((index, _)) = pks
            .iter()
            .enumerate()
            .find(|(_, pk)| sign::verify_detached(sig, msg_hex.as_bytes(), pk))
        {
            num_valid_sigs += ONE;
            pks.remove(index);
        }
    }
    num_valid_sigs == sigs.len()
}

/// Pops a number from the top of the stack
///
/// ### Arguments
///
/// * `stack` - a reference to the stack
fn pop_num(stack: &mut Stack) -> Result<usize, ScriptError> {
    match stack.pop()? {
        StackEntry::Num(n) => Ok(n),
        _ => return Err(ScriptError::ItemType),
    }
}

/// Pops bytes from the top of the stack
///
/// ### Arguments
///
/// * `stack` - a reference to the stack
fn pop_bytes(stack: &mut Stack) -> Result<Vec<u8>, ScriptError> {
    match stack.pop()? {
        StackEntry::Bytes(b) => Ok(b),
        _ => return Err(ScriptError::ItemType),
    }
}

/// Pops a public key from the top of the stack
///
/// ### Arguments
///
/// * `stack` - a reference to the stack
fn pop_pubkey(stack: &mut Stack) -> Result<PublicKey, ScriptError> {
    match stack.pop()? {
        StackEntry::PubKey(pubkey) => Ok(pubkey),
        _ => return Err(ScriptError::ItemType),
    }
}

/// Pops a signature from the top of the stack
///
/// ### Arguments
///
/// * `stack` - a reference to the stack
fn pop_sig(stack: &mut Stack) -> Result<Signature, ScriptError> {
    match stack.pop()? {
        StackEntry::Signature(sig) => Ok(sig),
        _ => return Err(ScriptError::ItemType),
    }
}

/// Gets the bytes at the top of the stack without popping them
///
/// ### Arguments
///
/// * `stack` - a reference to the stack
fn peek_bytes(stack: &Stack) -> Result<&Vec<u8>, ScriptError> {
    match stack.peek()? {
        StackEntry::Bytes(b) => Ok(b),
        _ => return Err(ScriptError::ItemType),
    }
}
