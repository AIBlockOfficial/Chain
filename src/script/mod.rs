#![allow(unused)]
pub mod interface_ops;
pub mod lang;

use crate::crypto::sign_ed25519::{PublicKey, Signature};
use crate::constants::*;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Stack entry enum
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum StackEntry {
    Op(OpCodes),
    Signature(Signature),
    PubKey(PublicKey),
    // TODO: This should probably be u64, as usize doesn't have a consistent range on all platforms
    Num(usize),
    Bytes(Vec<u8>),
}

macro_rules! opcodes_enum {
    ($($id:ident = $ord:literal; $desc:literal),* ,) => {
        #[allow(non_camel_case_types, clippy::upper_case_acronyms)]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Serialize, Deserialize)]
        pub enum OpCodes {
            $($id = $ord),*
        }

        impl OpCodes {
            /// This opcode's string name
            pub fn name(&self) -> &str {
                match self {
                    $( Self::$id => stringify!($id) ),*
                }
            }

            /// This opcode's string name
            pub fn desc(&self) -> &str {
                match self {
                    $( Self::$id => $desc ),*
                }
            }
        }
    };
}

/// Opcodes enum
opcodes_enum!(
    // constants
    OP_0 = 0x00; "Pushes the constant 0 onto the stack",
    OP_1 = 0x01; "Pushes the constant 1 onto the stack",
    OP_2 = 0x02; "Pushes the constant 2 onto the stack",
    OP_3 = 0x03; "Pushes the constant 3 onto the stack",
    OP_4 = 0x04; "Pushes the constant 4 onto the stack",
    OP_5 = 0x05; "Pushes the constant 5 onto the stack",
    OP_6 = 0x06; "Pushes the constant 6 onto the stack",
    OP_7 = 0x07; "Pushes the constant 7 onto the stack",
    OP_8 = 0x08; "Pushes the constant 8 onto the stack",
    OP_9 = 0x09; "Pushes the constant 9 onto the stack",
    OP_10 = 0x0a; "Pushes the constant 10 onto the stack",
    OP_11 = 0x0b; "Pushes the constant 11 onto the stack",
    OP_12 = 0x0c; "Pushes the constant 12 onto the stack",
    OP_13 = 0x0d; "Pushes the constant 13 onto the stack",
    OP_14 = 0x0e; "Pushes the constant 14 onto the stack",
    OP_15 = 0x0f; "Pushes the constant 15 onto the stack",
    OP_16 = 0x10; "Pushes the constant 16 onto the stack",
    // flow control
    OP_NOP = 0x20; "Does nothing",
    OP_IF = 0x21; "Checks if the top item on the stack is not ZERO and executes the next block of instructions",
    OP_NOTIF = 0x22; "Checks if the top item on the stack is ZERO and executes the next block of instructions",
    OP_ELSE = 0x23; "Executes the next block of instructions if the previous OP_IF or OP_NOTIF was not executed",
    OP_ENDIF = 0x24; "Ends an OP_IF or OP_NOTIF block",
    OP_VERIFY = 0x25; "Removes the top item from the stack and ends execution with an error if it is ZERO",
    OP_BURN = 0x26; "Ends execution with an error",
    // stack
    OP_TOALTSTACK = 0x30; "Moves the top item from the main stack to the top of the alt stack",
    OP_FROMALTSTACK = 0x31; "Moves the top item from the alt stack to the top of the main stack",
    OP_2DROP = 0x32; "Removes the top two items from the stack",
    OP_2DUP = 0x33; "Duplicates the top two items on the stack",
    OP_3DUP = 0x34; "Duplicates the top three items on the stack",
    OP_2OVER = 0x35; "Copies the second-to-top pair of items to the top of the stack",
    OP_2ROT = 0x36; "Moves the third-to-top pair of items to the top of the stack",
    OP_2SWAP = 0x37; "Swaps the top two pairs of items on the stack",
    OP_IFDUP = 0x38; "Duplicates the top item on the stack if it is not ZERO",
    OP_DEPTH = 0x39; "Pushes the stack size onto the stack",
    OP_DROP = 0x3a; "Removes the top item from the stack",
    OP_DUP = 0x3b; "Duplicates the top item on the stack",
    OP_NIP = 0x3c; "Removes the second-to-top item from the stack",
    OP_OVER = 0x3d; "Copies the second-to-top item to the top of the stack",
    OP_PICK = 0x3e; "Copies the nth-to-top item to the top of the stack, where n is the top item on the stack",
    OP_ROLL = 0x3f; "Moves the nth-to-top item to the top of the stack, where n is the top item on the stack",
    OP_ROT = 0x40; "Moves the third-to-top item to the top of the stack",
    OP_SWAP = 0x41; "Swaps the top two items on the stack",
    OP_TUCK = 0x42; "Copies the top item behind the second-to-top item on the stack",
    // splice
    OP_CAT = 0x50; "Concatenates the two strings on top of the stack",
    OP_SUBSTR = 0x51; "Extracts a substring from the third-to-top item on the stack",
    OP_LEFT = 0x52; "Extracts a left substring from the second-to-top item on the stack",
    OP_RIGHT = 0x53; "Extracts a right substring from the second-to-top item on the stack",
    OP_SIZE = 0x54; "Computes the size in bytes of the string on top of the stack",
    // bitwise logic
    OP_INVERT = 0x60; "Computes bitwise NOT of the number on top of the stack",
    OP_AND = 0x61; "Computes bitwise AND between the two numbers on top of the stack",
    OP_OR = 0x62; "Computes bitwise OR between the two numbers on top of the stack",
    OP_XOR = 0x63; "Computes bitwise XOR between the two numbers on top of the stack",
    OP_EQUAL = 0x64; "Substitutes the top two items on the stack with ONE if they are equal, with ZERO otherwise",
    OP_EQUALVERIFY = 0x65; "Computes OP_EQUAL and OP_VERIFY in sequence",
    // arithmetic
    OP_1ADD = 0x70; "Adds ONE to the number on top of the stack",
    OP_1SUB = 0x71; "Subtracts ONE from the number on top of the stack",
    OP_2MUL = 0x72; "Multiplies by TWO the number on top of the stack",
    OP_2DIV = 0x73; "Divides by TWO the number on top of the stack",
    OP_NOT = 0x74; "Substitutes the number on top of the stack with ONE if it is equal to ZERO, with ZERO otherwise",
    OP_0NOTEQUAL = 0x75; "Substitutes the number on top of the stack with ONE if it is not equal to ZERO, with ZERO otherwise",
    OP_ADD = 0x76; "Adds the two numbers on top of the stack",
    OP_SUB = 0x77; "Subtracts the number on top of the stack from the second-to-top number on the stack",
    OP_MUL = 0x78; "Multiplies the second-to-top number by the number on top of the stack",
    OP_DIV = 0x79; "Divides the second-to-top number by the number on top of the stack",
    OP_MOD = 0x7a; "Computes the remainder of the division of the second-to-top number by the number on top of the stack",
    OP_LSHIFT = 0x7b; "Computes the left shift of the second-to-top number by the number on top of the stack",
    OP_RSHIFT = 0x7c; "Computes the right shift of the second-to-top number by the number on top of the stack",
    OP_BOOLAND = 0x7d; "Substitutes the two numbers on top of the stack with ONE if they are both non-zero, with ZERO otherwise",
    OP_BOOLOR = 0x7e; "Substitutes the two numbers on top of the stack with ONE if they are not both ZERO, with ZERO otherwise",
    OP_NUMEQUAL = 0x7f; "Substitutes the two numbers on top of the stack with ONE if they are equal, with ZERO otherwise",
    OP_NUMEQUALVERIFY = 0x80; "Computes OP_NUMEQUAL and OP_VERIFY in sequence",
    OP_NUMNOTEQUAL = 0x81; "Substitutes the two numbers on top of the stack with ONE if they are not equal, with ZERO otherwise",
    OP_LESSTHAN = 0x82; "Substitutes the two numbers on top of the stack with ONE if the second-to-top is less than the top item, with ZERO otherwise",
    OP_GREATERTHAN = 0x83; "Substitutes the two numbers on top of the stack with ONE if the second-to-top is greater than the top item, with ZERO otherwise",
    OP_LESSTHANOREQUAL = 0x84; "Substitutes the two numbers on top of the stack with ONE if the second-to-top is less than or equal to the top item, with ZERO otherwise",
    OP_GREATERTHANOREQUAL = 0x85; "Substitutes the two numbers on top of the stack with ONE if the second-to-top is greater than or equal to the top item, with ZERO otherwise",
    OP_MIN = 0x86; "Substitutes the two numbers on top of the stack with the minimum between the two",
    OP_MAX = 0x87; "Substitutes the two numbers on top of the stack with the maximum between the two",
    OP_WITHIN = 0x88; "Substitutes the three numbers on top of the the stack with ONE if the third-to-top is greater or equal to the second-to-top and less than the top item, with ZERO otherwise",
    // crypto
    OP_SHA3 = 0x90; "Hashes the top item on the stack using SHA3-256",
    OP_HASH256 = 0x91; "Creates standard address from public key and pushes it onto the stack", // TODO: this is redundant, as OP_SHA3 already does the same thing
    OP_CHECKSIG = 0x94; "Pushes ONE onto the stack if the signature is valid, ZERO otherwise",
    OP_CHECKSIGVERIFY = 0x95; "Runs OP_CHECKSIG and OP_VERIFY in sequence",
    OP_CHECKMULTISIG = 0x96; "Pushes ONE onto the stack if the m-of-n multi-signature is valid, ZERO otherwise",
    OP_CHECKMULTISIGVERIFY = 0x97; "Runs OP_CHECKMULTISIG and OP_VERIFY in sequence",
    // smart data
    OP_CREATE = 0xa0; "",
    // reserved
    OP_NOP1 = 0xb0; "",
    OP_NOP2 = 0xb1; "",
    OP_NOP3 = 0xb2; "",
    OP_NOP4 = 0xb3; "",
    OP_NOP5 = 0xb4; "",
    OP_NOP6 = 0xb5; "",
    OP_NOP7 = 0xb6; "",
    OP_NOP8 = 0xb7; "",
    OP_NOP9 = 0xb8; "",
    OP_NOP10 = 0xb9; "",
    OP_NOP11 = 0x92; "", // Formerly OP_HASH256_V0
    OP_NOP12 = 0x93; "", // Formerly OP_HASH256_TEMP
);

impl OpCodes {
    /// Returns true if the opcode is a conditional
    pub fn is_conditional(&self) -> bool {
        matches!(
            self,
            OpCodes::OP_IF | OpCodes::OP_NOTIF | OpCodes::OP_ELSE | OpCodes::OP_ENDIF
        )
    }
}

/// Allows for string casting
impl fmt::Display for OpCodes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.name())
    }
}

make_error_type!(#[derive(Eq, PartialEq)] pub ScriptError {
    // opcode
    EmptyCondition; "Condition stack is empty",
    Verify; "The top item on the stack is ZERO",
    Burn; "OP_BURN executed",
    StackEmpty; "Not enough items on the stack",
    StackFull; "Too many items on the stack",
    ItemType; "Item type is not correct",
    StackIndexBounds(index: usize, length: usize);
            "Index {index} is out of bounds for stack of height {length}",
    IndexBounds(index: usize, length: usize);
            "Index {index} is out of bounds for operand of length {length}",
    SliceBounds(start: usize, n: usize, length: usize);
            "Index range [{start}..{start}+{n}] is out of bounds for operand of length {length}",
    ItemSize(size: usize, limit: usize); "Item size {size} exceeds {limit}-byte limit",
    ItemsNotEqual; "The two top items are not equal",
    Overflow; "Integer overflow",
    DivideByZero; "Attempt to divide by ZERO",
    InvalidSignature; "Signature is not valid",
    InvalidMultisignature; "Multi-signature is not valid",
    NumPubkeys; "Number of public keys provided is not correct",
    NumSignatures; "Number of signatures provided is not correct",
    ReservedOpcode(op: OpCodes); "Reserved opcode: {op}",

    EndStackDepth(depth: usize); "Stack depth after script evaluation is not 1: {depth}",
    LastEntryIsZero; "Last stack entry is zero",
    NotEmptyCondition; "Condition stack after script evaluation is non-empty",
    // script
    MaxScriptSize(size: usize); "Script size {size} exceeds {MAX_SCRIPT_SIZE}-byte limit",
    MaxScriptOps(count: usize); "Script opcode count {count} exceeds limit {MAX_OPS_PER_SCRIPT}",
    DuplicateElse; "Conditional block contains multiple OP_ELSE opcodes",
});
