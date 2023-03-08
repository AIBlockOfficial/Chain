#![allow(unused)]
pub mod interface_ops;
pub mod lang;

use crate::crypto::sign_ed25519::{PublicKey, Signature};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Stack entry enum which embodies the range of possible
/// operations that could be performed in a Script stack process
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum StackEntry {
    Op(OpCodes),
    Signature(Signature),
    PubKey(PublicKey),
    PubKeyHash(String),
    Num(usize),
    Bytes(String),
}

/// Ops code for stack scripts
#[allow(non_camel_case_types, clippy::upper_case_acronyms)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Serialize, Deserialize)]
pub enum OpCodes {
    // constants
    OP_0 = 0x00,         // implemented, tested, added to interpret_script
    OP_PUSHDATA1 = 0x4c, // not implemented: we use push_entry_to_stack
    OP_PUSHDATA2 = 0x4d, // not implemented: we use push_entry_to_stack
    OP_PUSHDATA4 = 0x4e, // not implemented: we use push_entry_to_stack
    OP_1NEGATE = 0x4f,   // not implemented: we do not allow negative numbers on the stack
    OP_1 = 0x51,         // implemented, tested, added to interpret_script
    OP_2 = 0x52,         // implemented, tested, added to interpret_script
    OP_3 = 0x53,         // implemented, tested, added to interpret_script
    OP_4 = 0x54,         // implemented, tested, added to interpret_script
    OP_5 = 0x55,         // implemented, tested, added to interpret_script
    OP_6 = 0x56,         // implemented, tested, added to interpret_script
    OP_7 = 0x57,         // implemented, tested, added to interpret_script
    OP_8 = 0x58,         // implemented, tested, added to interpret_script
    OP_9 = 0x59,         // implemented, tested, added to interpret_script
    OP_10 = 0x5a,        // implemented, tested, added to interpret_script
    OP_11 = 0x5b,        // implemented, tested, added to interpret_script
    OP_12 = 0x5c,        // implemented, tested, added to interpret_script
    OP_13 = 0x5d,        // implemented, tested, added to interpret_script
    OP_14 = 0x5e,        // implemented, tested, added to interpret_script
    OP_15 = 0x5f,        // implemented, tested, added to interpret_script
    OP_16 = 0x60,        // implemented, tested, added to interpret_script

    // flow control
    OP_NOP = 0x61,
    OP_VER = 0x62,
    OP_IF = 0x63,
    OP_NOTIF = 0x64,
    OP_VERIF = 0x65,
    OP_VERNOTIF = 0x66,
    OP_ELSE = 0x67,
    OP_ENDIF = 0x68,
    OP_VERIFY = 0x69,
    OP_RETURN = 0x6a,

    // stack
    OP_TOALTSTACK = 0x6b,   // implemented, tested, added to interpret_script
    OP_FROMALTSTACK = 0x6c, // implemented, tested, added to interpret_script
    OP_2DROP = 0x6d,        // implemented, tested, added to interpret_script
    OP_2DUP = 0x6e,         // implemented, tested, added to interpret_script
    OP_3DUP = 0x6f,         // implemented, tested, added to interpret_script
    OP_2OVER = 0x70,        // implemented, tested, added to interpret_script
    OP_2ROT = 0x71,         // implemented, tested, added to interpret_script
    OP_2SWAP = 0x72,        // implemented, tested, added to interpret_script
    OP_IFDUP = 0x73,        // implemented, tested, added to interpret_script
    OP_DEPTH = 0x74,        // implemented, tested, added to interpret_script
    OP_DROP = 0x75,         // implemented, tested, added to interpret_script
    OP_DUP = 0x76,          // implemented, tested, added to interpret_script
    OP_NIP = 0x77,          // implemented, tested, added to interpret_script
    OP_OVER = 0x78,         // implemented, tested, added to interpret_script
    OP_PICK = 0x79,         // implemented, tested, added to interpret_script
    OP_ROLL = 0x7a,         // implemented, tested, added to interpret_script
    OP_ROT = 0x7b,          // implemented, tested, added to interpret_script
    OP_SWAP = 0x7c,         // implemented, tested, added to interpret_script
    OP_TUCK = 0x7d,         // implemented, tested, added to interpret_script

    // splice
    OP_CAT = 0x7e,    // implemented, tested, currently disabled
    OP_SUBSTR = 0x7f, // implemented, tested, currently disabled
    OP_LEFT = 0x80,   // implemented, tested, currently disabled
    OP_RIGHT = 0x81,  // implemented, tested, currently disabled
    OP_SIZE = 0x82,   // implemented, tested, added to interpret_script

    // bitwise logic
    OP_INVERT = 0x83,      // implemented, tested, currently disabled
    OP_AND = 0x84,         // implemented, tested, currently disabled
    OP_OR = 0x85,          // implemented, tested, currently disabled
    OP_XOR = 0x86,         // implemented, tested, currently disabled
    OP_EQUAL = 0x87,       // implemented, tested, added to interpret_script
    OP_EQUALVERIFY = 0x88, // implemented, tested, added to interpret_script

    // arithmetic
    OP_1ADD = 0x8b,               // implemented, tested, added to interpret_script
    OP_1SUB = 0x8c,               // implemented, tested, added to interpret_script
    OP_2MUL = 0x8d,               // implemented, tested, currently disabled
    OP_2DIV = 0x8e,               // implemented, tested, currently disabled
    OP_NEGATE = 0x8f,             // not implemented: we do not allow negative numbers on the stack
    OP_ABS = 0x90,                // not implemented: we do not allow negative numbers on the stack
    OP_NOT = 0x91,                // implemented, tested, added to interpret_script
    OP_0NOTEQUAL = 0x92,          // implemented, tested, added to interpret_script
    OP_ADD = 0x93,                // implemented, tested, added to interpret_script
    OP_SUB = 0x94,                // implemented, tested, added to interpret_script
    OP_MUL = 0x95,                // implemented, tested, currently disabled
    OP_DIV = 0x96,                // implemented, tested, currently disabled
    OP_MOD = 0x97,                // implemented, tested, currently disabled
    OP_LSHIFT = 0x98,             // implemented, tested, currently disabled
    OP_RSHIFT = 0x99,             // implemented, tested, currently disabled
    OP_BOOLAND = 0x9a,            // implemented, tested, added to interpret_script
    OP_BOOLOR = 0x9b,             // implemented, tested, added to interpret_script
    OP_NUMEQUAL = 0x9c,           // implemented, tested, added to interpret_script
    OP_NUMEQUALVERIFY = 0x9d,     // implemented, tested, added to interpret_script
    OP_NUMNOTEQUAL = 0x9e,        // implemented, tested, added to interpret_script
    OP_LESSTHAN = 0x9f,           // implemented, tested, added to interpret_script
    OP_GREATERTHAN = 0xa0,        // implemented, tested, added to interpret_script
    OP_LESSTHANOREQUAL = 0xa1,    // implemented, tested, added to interpret_script
    OP_GREATERTHANOREQUAL = 0xa2, // implemented, tested, added to interpret_script
    OP_MIN = 0xa3,                // implemented, tested, added to interpret_script
    OP_MAX = 0xa4,                // implemented, tested, added to interpret_script
    OP_WITHIN = 0xa5,             // implemented, tested, added to interpret_script

    // crypto
    OP_RIPEMD160 = 0xa6,      // not implemented: we do not need it
    OP_SHA1 = 0xa7,           // not implemented: we do not need it
    OP_SHA256 = 0xa8,         // not implemented: we do not need it
    OP_SHA3 = 0xa9,           // implemented, tested, added to interpret_script
    OP_HASH256 = 0xaa,        // implemented, tested, added to interpret_script
    OP_HASH256V0 = 0xc1,      // implemented, tested, added to interpret_script
    OP_HASH256TEMP = 0xc2,    // implemented, tested, added to interpret_script
    OP_CODESEPARATOR = 0xab,  // not implemented: we do not need it
    OP_CHECKSIG = 0xac,       // implemented, tested, added to interpret_script
    OP_CHECKSIGVERIFY = 0xad, // implemented, tested, added to interpret_script
    OP_CHECKMULTISIG = 0xae,
    OP_CHECKMULTISIGVERIFY = 0xaf,

    // locktime
    OP_CHECKLOCKTIMEVERIFY = 0xb1,
    OP_CHECKSEQUENCEVERIFY = 0xb2,

    // pseudo-words
    OP_INVALIDOPCODE = 0xff,

    // reserved
    OP_RESERVED = 0x50,
    OP_RESERVED1 = 0x89,
    OP_RESERVED2 = 0x8a,
    OP_NOP1 = 0xb0,
    OP_NOP4 = 0xb3,
    OP_NOP5 = 0xb4,
    OP_NOP6 = 0xb5,
    OP_NOP7 = 0xb6,
    OP_NOP8 = 0xb7,
    OP_NOP9 = 0xb8,
    OP_NOP10 = 0xb9,

    // data
    OP_CREATE = 0xc0,
}

impl OpCodes {
    pub const OP_NOP2: OpCodes = OpCodes::OP_CHECKLOCKTIMEVERIFY;
    pub const OP_NOP3: OpCodes = OpCodes::OP_CHECKSEQUENCEVERIFY;
    pub const MAX_OPCODE: OpCodes = OpCodes::OP_CREATE;
}

// Allows for string casting
impl fmt::Display for OpCodes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
