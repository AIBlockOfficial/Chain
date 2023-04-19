#![allow(unused)]
use crate::constants::*;
use crate::crypto::sha3_256;
use crate::crypto::sign_ed25519::{
    PublicKey, Signature, ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN,
};
use crate::script::interface_ops::*;
use crate::script::{OpCodes, StackEntry};
use crate::utils::error_utils::*;
use crate::utils::transaction_utils::{construct_address, construct_address_for};
use bincode::serialize;
use bytes::Bytes;
use hex::encode;
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

/// Stack for script execution
#[derive(Clone, Debug, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub struct Stack {
    pub main_stack: Vec<StackEntry>,
    pub alt_stack: Vec<StackEntry>,
}

impl Default for Stack {
    fn default() -> Self {
        Self::new()
    }
}

impl Stack {
    /// Creates a new stack
    pub fn new() -> Self {
        Self {
            main_stack: Vec::with_capacity(MAX_STACK_SIZE as usize),
            alt_stack: Vec::with_capacity(MAX_STACK_SIZE as usize),
        }
    }

    /// Checks if the stack is valid
    pub fn is_valid(&self) -> bool {
        if self.main_stack.len() + self.alt_stack.len() > MAX_STACK_SIZE as usize {
            error_max_stack_size();
            return false;
        }
        true
    }

    /// Pops the top item from the stack
    pub fn pop(&mut self) -> Option<StackEntry> {
        self.main_stack.pop()
    }

    /// Returns the top item on the stack
    pub fn last(&self) -> Option<StackEntry> {
        self.main_stack.last().cloned()
    }

    /// Pushes a new entry onto the stack
    pub fn push(&mut self, stack_entry: StackEntry) -> bool {
        match stack_entry.clone() {
            StackEntry::Op(_) => {
                return false;
            }
            StackEntry::PubKeyHash(s) | StackEntry::Bytes(s) => {
                if s.len() > MAX_SCRIPT_ITEM_SIZE as usize {
                    return false;
                }
            }
            _ => (),
        }
        self.main_stack.push(stack_entry);
        true
    }
}

impl From<Vec<StackEntry>> for Stack {
    /// Creates a new stack with a pre-filled main stack
    fn from(stack: Vec<StackEntry>) -> Self {
        Stack {
            main_stack: stack,
            alt_stack: Vec::with_capacity(MAX_STACK_SIZE as usize),
        }
    }
}

/// Stack for conditionals
#[derive(Clone, Debug, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConditionStack {
    pub size: usize,
    pub first_false_pos: Option<usize>,
}

impl Default for ConditionStack {
    fn default() -> Self {
        Self::new()
    }
}

impl ConditionStack {
    /// Creates a new stack for conditionals
    pub fn new() -> Self {
        Self {
            size: ZERO,
            first_false_pos: None,
        }
    }

    /// Checks if all values are true
    pub fn all_true(&self) -> bool {
        self.first_false_pos.is_none()
    }

    /// Checks if the condition stack is empty
    pub fn is_empty(&self) -> bool {
        self.size == ZERO
    }

    /// Pushes a new value onto the condition stack
    pub fn push(&mut self, cond: bool) {
        if self.first_false_pos.is_none() && !cond {
            self.first_false_pos = Some(self.size);
        }
        self.size += ONE;
    }

    /// Pops the top value from the condition stack
    pub fn pop(&mut self) {
        self.size -= ONE;
        if let Some(pos) = self.first_false_pos {
            if pos == self.size {
                self.first_false_pos.take();
            }
        }
    }

    /// Toggles the top value on the condition stack
    pub fn toggle(&mut self) {
        match self.first_false_pos {
            Some(pos) => {
                if pos == self.size - ONE {
                    self.first_false_pos = None;
                }
            }
            _ => {
                self.first_false_pos = Some(self.size - ONE);
            }
        }
    }
}

/// Scripts are defined as a sequence of stack entries
/// NOTE: A tuple struct could probably work here as well
#[derive(Clone, Debug, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
pub struct Script {
    pub stack: Vec<StackEntry>,
}

impl Default for Script {
    fn default() -> Self {
        Self::new()
    }
}

impl Script {
    /// Constructs a new script
    pub fn new() -> Self {
        Self { stack: Vec::new() }
    }

    /// Checks if a script is valid
    pub fn is_valid(&self) -> bool {
        let mut len = ZERO; // script length in bytes
        let mut ops_count = ZERO; // number of opcodes in script
        for entry in &self.stack {
            match entry {
                StackEntry::Op(_) => {
                    len += ONE;
                    ops_count += ONE;
                }
                StackEntry::Signature(_) => len += ED25519_SIGNATURE_LEN,
                StackEntry::PubKey(_) => len += ED25519_PUBLIC_KEY_LEN,
                StackEntry::PubKeyHash(s) | StackEntry::Bytes(s) => len += s.len(),
                StackEntry::Num(_) => len += usize::BITS as usize / EIGHT,
            };
        }
        if len > MAX_SCRIPT_SIZE as usize {
            error_max_script_size();
            return false;
        }
        if ops_count > MAX_OPS_PER_SCRIPT as usize {
            error_max_ops_script();
            return false;
        }
        true
    }

    /// Interprets and executes a script
    pub fn interpret(&self) -> bool {
        if !self.is_valid() {
            return false;
        }
        let mut stack = Stack::new();
        let mut cond_stack = ConditionStack::new();
        let mut test_for_return = true;
        for stack_entry in &self.stack {
            match stack_entry.clone() {
                /*---- OPCODE ----*/
                StackEntry::Op(op) => {
                    if !cond_stack.all_true() && !op.is_conditional() {
                        // skip opcode if latest condition check failed
                        continue;
                    }
                    match op {
                        // constants
                        OpCodes::OP_0 => test_for_return &= op_0(&mut stack),
                        OpCodes::OP_1 => test_for_return &= op_1(&mut stack),
                        OpCodes::OP_2 => test_for_return &= op_2(&mut stack),
                        OpCodes::OP_3 => test_for_return &= op_3(&mut stack),
                        OpCodes::OP_4 => test_for_return &= op_4(&mut stack),
                        OpCodes::OP_5 => test_for_return &= op_5(&mut stack),
                        OpCodes::OP_6 => test_for_return &= op_6(&mut stack),
                        OpCodes::OP_7 => test_for_return &= op_7(&mut stack),
                        OpCodes::OP_8 => test_for_return &= op_8(&mut stack),
                        OpCodes::OP_9 => test_for_return &= op_9(&mut stack),
                        OpCodes::OP_10 => test_for_return &= op_10(&mut stack),
                        OpCodes::OP_11 => test_for_return &= op_11(&mut stack),
                        OpCodes::OP_12 => test_for_return &= op_12(&mut stack),
                        OpCodes::OP_13 => test_for_return &= op_13(&mut stack),
                        OpCodes::OP_14 => test_for_return &= op_14(&mut stack),
                        OpCodes::OP_15 => test_for_return &= op_15(&mut stack),
                        OpCodes::OP_16 => test_for_return &= op_16(&mut stack),
                        // flow control
                        OpCodes::OP_NOP => test_for_return &= op_nop(&mut stack),
                        OpCodes::OP_IF => test_for_return &= op_if(&mut stack, &mut cond_stack),
                        OpCodes::OP_NOTIF => {
                            test_for_return &= op_notif(&mut stack, &mut cond_stack)
                        }
                        OpCodes::OP_ELSE => test_for_return &= op_else(&mut cond_stack),
                        OpCodes::OP_ENDIF => test_for_return &= op_endif(&mut cond_stack),
                        OpCodes::OP_VERIFY => test_for_return &= op_verify(&mut stack),
                        OpCodes::OP_RETURN => test_for_return &= op_return(&mut stack),
                        // stack
                        OpCodes::OP_TOALTSTACK => test_for_return &= op_toaltstack(&mut stack),
                        OpCodes::OP_FROMALTSTACK => test_for_return &= op_fromaltstack(&mut stack),
                        OpCodes::OP_2DROP => test_for_return &= op_2drop(&mut stack),
                        OpCodes::OP_2DUP => test_for_return &= op_2dup(&mut stack),
                        OpCodes::OP_3DUP => test_for_return &= op_3dup(&mut stack),
                        OpCodes::OP_2OVER => test_for_return &= op_2over(&mut stack),
                        OpCodes::OP_2ROT => test_for_return &= op_2rot(&mut stack),
                        OpCodes::OP_2SWAP => test_for_return &= op_2swap(&mut stack),
                        OpCodes::OP_IFDUP => test_for_return &= op_ifdup(&mut stack),
                        OpCodes::OP_DEPTH => test_for_return &= op_depth(&mut stack),
                        OpCodes::OP_DROP => test_for_return &= op_drop(&mut stack),
                        OpCodes::OP_DUP => test_for_return &= op_dup(&mut stack),
                        OpCodes::OP_NIP => test_for_return &= op_nip(&mut stack),
                        OpCodes::OP_OVER => test_for_return &= op_over(&mut stack),
                        OpCodes::OP_PICK => test_for_return &= op_pick(&mut stack),
                        OpCodes::OP_ROLL => test_for_return &= op_roll(&mut stack),
                        OpCodes::OP_ROT => test_for_return &= op_rot(&mut stack),
                        OpCodes::OP_SWAP => test_for_return &= op_swap(&mut stack),
                        OpCodes::OP_TUCK => test_for_return &= op_tuck(&mut stack),
                        // splice
                        OpCodes::OP_CAT => test_for_return &= op_cat(&mut stack),
                        OpCodes::OP_SUBSTR => test_for_return &= op_substr(&mut stack),
                        OpCodes::OP_LEFT => test_for_return &= op_left(&mut stack),
                        OpCodes::OP_RIGHT => test_for_return &= op_right(&mut stack),
                        OpCodes::OP_SIZE => test_for_return &= op_size(&mut stack),
                        // bitwise logic
                        OpCodes::OP_INVERT => test_for_return &= op_invert(&mut stack),
                        OpCodes::OP_AND => test_for_return &= op_and(&mut stack),
                        OpCodes::OP_OR => test_for_return &= op_or(&mut stack),
                        OpCodes::OP_XOR => test_for_return &= op_xor(&mut stack),
                        OpCodes::OP_EQUAL => test_for_return &= op_equal(&mut stack),
                        OpCodes::OP_EQUALVERIFY => test_for_return &= op_equalverify(&mut stack),
                        // arithmetic
                        OpCodes::OP_1ADD => test_for_return &= op_1add(&mut stack),
                        OpCodes::OP_1SUB => test_for_return &= op_1sub(&mut stack),
                        OpCodes::OP_2MUL => test_for_return &= op_2mul(&mut stack),
                        OpCodes::OP_2DIV => test_for_return &= op_2div(&mut stack),
                        OpCodes::OP_NOT => test_for_return &= op_not(&mut stack),
                        OpCodes::OP_0NOTEQUAL => test_for_return &= op_0notequal(&mut stack),
                        OpCodes::OP_ADD => test_for_return &= op_add(&mut stack),
                        OpCodes::OP_SUB => test_for_return &= op_sub(&mut stack),
                        OpCodes::OP_MUL => test_for_return &= op_mul(&mut stack),
                        OpCodes::OP_DIV => test_for_return &= op_div(&mut stack),
                        OpCodes::OP_MOD => test_for_return &= op_mod(&mut stack),
                        OpCodes::OP_LSHIFT => test_for_return &= op_lshift(&mut stack),
                        OpCodes::OP_RSHIFT => test_for_return &= op_rshift(&mut stack),
                        OpCodes::OP_BOOLAND => test_for_return &= op_booland(&mut stack),
                        OpCodes::OP_BOOLOR => test_for_return &= op_boolor(&mut stack),
                        OpCodes::OP_NUMEQUAL => test_for_return &= op_numequal(&mut stack),
                        OpCodes::OP_NUMEQUALVERIFY => {
                            test_for_return &= op_numequalverify(&mut stack)
                        }
                        OpCodes::OP_NUMNOTEQUAL => test_for_return &= op_numnotequal(&mut stack),
                        OpCodes::OP_LESSTHAN => test_for_return &= op_lessthan(&mut stack),
                        OpCodes::OP_GREATERTHAN => test_for_return &= op_greaterthan(&mut stack),
                        OpCodes::OP_LESSTHANOREQUAL => {
                            test_for_return &= op_lessthanorequal(&mut stack)
                        }
                        OpCodes::OP_GREATERTHANOREQUAL => {
                            test_for_return &= op_greaterthanorequal(&mut stack)
                        }
                        OpCodes::OP_MIN => test_for_return &= op_min(&mut stack),
                        OpCodes::OP_MAX => test_for_return &= op_max(&mut stack),
                        OpCodes::OP_WITHIN => test_for_return &= op_within(&mut stack),
                        // crypto
                        OpCodes::OP_SHA3 => test_for_return &= op_sha3(&mut stack),
                        OpCodes::OP_HASH256 => test_for_return &= op_hash256(&mut stack),
                        OpCodes::OP_HASH256_V0 => test_for_return &= op_hash256_v0(&mut stack),
                        OpCodes::OP_HASH256_TEMP => test_for_return &= op_hash256_temp(&mut stack),
                        OpCodes::OP_CHECKSIG => test_for_return &= op_checksig(&mut stack),
                        OpCodes::OP_CHECKSIGVERIFY => {
                            test_for_return &= op_checksigverify(&mut stack)
                        }
                        OpCodes::OP_CHECKMULTISIG => {
                            test_for_return &= op_checkmultisig(&mut stack)
                        }
                        OpCodes::OP_CHECKMULTISIGVERIFY => {
                            test_for_return &= op_checkmultisigverify(&mut stack)
                        }
                        // locktime
                        OpCodes::OP_CHECKLOCKTIMEVERIFY => {
                            test_for_return &= op_checklocktimeverify(&mut stack)
                        }
                        OpCodes::OP_CHECKSEQUENCEVERIFY => {
                            test_for_return &= op_checksequenceverify(&mut stack)
                        }
                        // smart data
                        OpCodes::OP_CREATE => (),
                        // invalid opcode
                        _ => {
                            error_invalid_opcode();
                            return false;
                        }
                    }
                }
                /*---- SIGNATURE | PUBKEY | PUBKEYHASH | NUM | BYTES ----*/
                StackEntry::Signature(_)
                | StackEntry::PubKey(_)
                | StackEntry::PubKeyHash(_)
                | StackEntry::Num(_)
                | StackEntry::Bytes(_) => {
                    if cond_stack.all_true() {
                        test_for_return &= stack.push(stack_entry.clone())
                    }
                }
            }
            if !test_for_return || !stack.is_valid() {
                return false;
            }
        }
        test_for_return && stack.last() != Some(StackEntry::Num(ZERO))
    }

    /// Constructs a new script for coinbase
    ///
    /// ### Arguments
    ///
    /// * `block_number`  - The block time to push
    pub fn new_for_coinbase(block_number: u64) -> Self {
        Self {
            stack: vec![StackEntry::Num(block_number as usize)],
        }
    }

    /// Constructs a new script for an asset creation
    ///
    /// ### Arguments
    ///
    /// * `block_number`    - The block time
    /// * `asset_hash`      - The hash of the asset
    /// * `signature`       - The signature of the asset contents
    /// * `pub_key`         - The public key used in creating the signed content
    pub fn new_create_asset(
        block_number: u64,
        asset_hash: String,
        signature: Signature,
        pub_key: PublicKey,
    ) -> Self {
        let mut new_script = Script::new();

        new_script.stack.push(StackEntry::Op(OpCodes::OP_CREATE));
        new_script
            .stack
            .push(StackEntry::Num(block_number as usize));
        new_script.stack.push(StackEntry::Op(OpCodes::OP_DROP));
        new_script.stack.push(StackEntry::Bytes(asset_hash));
        new_script.stack.push(StackEntry::Signature(signature));
        new_script.stack.push(StackEntry::PubKey(pub_key));
        new_script.stack.push(StackEntry::Op(OpCodes::OP_CHECKSIG));

        new_script
    }

    /// Constructs a pay to public key hash script
    ///
    /// ### Arguments
    ///
    /// * `check_data`  - Check data to provide signature
    /// * `signature`   - Signature of check data
    /// * `pub_key`     - Public key of the payer
    pub fn pay2pkh(
        check_data: String,
        signature: Signature,
        pub_key: PublicKey,
        address_version: Option<u64>,
    ) -> Self {
        let mut new_script = Script::new();
        let pub_key_stack_entry = StackEntry::PubKey(pub_key);
        let new_key = construct_address_for(&pub_key, address_version);

        let op_hash_256 = match address_version {
            Some(NETWORK_VERSION_V0) => OpCodes::OP_HASH256_V0,
            Some(NETWORK_VERSION_TEMP) => OpCodes::OP_HASH256_TEMP,
            _ => OpCodes::OP_HASH256,
        };

        new_script.stack.push(StackEntry::Bytes(check_data));
        new_script.stack.push(StackEntry::Signature(signature));
        new_script.stack.push(pub_key_stack_entry);
        new_script.stack.push(StackEntry::Op(OpCodes::OP_DUP));
        new_script.stack.push(StackEntry::Op(op_hash_256));
        new_script.stack.push(StackEntry::PubKeyHash(new_key));
        new_script
            .stack
            .push(StackEntry::Op(OpCodes::OP_EQUALVERIFY));
        new_script.stack.push(StackEntry::Op(OpCodes::OP_CHECKSIG));

        new_script
    }

    /// Constructs one part of a multiparty transaction script
    ///
    /// ### Arguments
    ///
    /// * `check_data`  - Data to be signed for verification
    /// * `pub_key`     - Public key of this party
    /// * `signature`   - Signature of this party
    pub fn member_multisig(check_data: String, pub_key: PublicKey, signature: Signature) -> Self {
        let mut new_script = Script::new();

        new_script.stack.push(StackEntry::Bytes(check_data));
        new_script.stack.push(StackEntry::Signature(signature));
        new_script.stack.push(StackEntry::PubKey(pub_key));
        new_script.stack.push(StackEntry::Op(OpCodes::OP_CHECKSIG));

        new_script
    }

    /// Constructs a multisig locking script
    ///
    /// ### Arguments
    ///
    /// * `m`           - Number of signatures required to unlock
    /// * `n`           - Number of valid signatures total
    /// * `check_data`  - Data to have checked against signatures
    /// * `pub_keys`    - The constituent public keys
    pub fn multisig_lock(m: usize, n: usize, check_data: String, pub_keys: Vec<PublicKey>) -> Self {
        let mut new_script = Script::new();

        if n > pub_keys.len() || m > pub_keys.len() {
            error!("The number of keys required for multisig is greater than the number of keys provided");
        } else if m > n {
            error!("Multisig requiring more keys to lock than the total number of keys");
        } else {
            let mut new_stack = Vec::with_capacity(3 + pub_keys.len());

            new_stack.push(StackEntry::Bytes(check_data));
            new_stack.push(StackEntry::Num(m));
            new_stack.append(&mut pub_keys.iter().map(|e| StackEntry::PubKey(*e)).collect());
            new_stack.push(StackEntry::Num(n));
            new_stack.push(StackEntry::Op(OpCodes::OP_CHECKMULTISIG));

            new_script.stack = new_stack;
        }

        new_script
    }

    /// Constructs a multisig unlocking script
    ///
    /// ### Arguments
    ///
    /// * `check_data`  - Data to have signed
    /// * `signatures`  - Signatures to unlock with
    pub fn multisig_unlock(check_data: String, signatures: Vec<Signature>) -> Self {
        let mut new_script = Script::new();
        new_script.stack = vec![StackEntry::Bytes(check_data)];
        new_script.stack.append(
            &mut signatures
                .iter()
                .map(|e| StackEntry::Signature(*e))
                .collect(),
        );

        new_script
    }

    /// Constructs a multisig validation script
    ///
    /// ### Arguments
    ///
    /// * `m`           - Number of signatures to assure validity
    /// * `n`           - Number of public keys that are valid
    /// * `signatures`  - Signatures to validate
    /// * `pub_keys`    - Public keys to validate
    pub fn multisig_validation(
        m: usize,
        n: usize,
        check_data: String,
        signatures: Vec<Signature>,
        pub_keys: Vec<PublicKey>,
    ) -> Self {
        let mut new_script = Script::new();

        if n > pub_keys.len() || m > pub_keys.len() {
            error!("The number of keys required for multisig is greater than the number of keys provided");
        } else if m > n {
            error!("Multisig requiring more keys to lock than the total number of keys");
        } else {
            new_script.stack = vec![StackEntry::Bytes(check_data)];

            // Handle signatures
            new_script.stack.append(
                &mut signatures
                    .iter()
                    .map(|e| StackEntry::Signature(*e))
                    .collect(),
            );

            new_script.stack.push(StackEntry::Num(m));

            // Handle pub keys
            new_script
                .stack
                .append(&mut pub_keys.iter().map(|e| StackEntry::PubKey(*e)).collect());
            new_script.stack.push(StackEntry::Num(n));
            new_script
                .stack
                .push(StackEntry::Op(OpCodes::OP_CHECKMULTISIG));
        }

        new_script
    }
}

impl From<Vec<StackEntry>> for Script {
    /// Creates a new script with a pre-filled stack
    fn from(script: Vec<StackEntry>) -> Self {
        Script { stack: script }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_script() {
        // empty script
        let mut script = Script::new();
        assert!(script.is_valid());
        // OP_0
        let mut script = Script::new();
        script.stack.push(StackEntry::Op(OpCodes::OP_0));
        assert!(script.is_valid());
        // OP_1
        let mut script = Script::new();
        script.stack.push(StackEntry::Op(OpCodes::OP_1));
        assert!(script.is_valid());
        // OP_1 OP_2 OP_ADD OP_3 OP_EQUAL
        let mut script = Script::new();
        script.stack.push(StackEntry::Op(OpCodes::OP_1));
        script.stack.push(StackEntry::Op(OpCodes::OP_2));
        script.stack.push(StackEntry::Op(OpCodes::OP_ADD));
        script.stack.push(StackEntry::Op(OpCodes::OP_3));
        script.stack.push(StackEntry::Op(OpCodes::OP_EQUAL));
        assert!(script.is_valid());
        // script length <= 10000 bytes
        let mut script = Script::new();
        let s = "a".repeat(500);
        for _ in 0..20 {
            script.stack.push(StackEntry::Bytes(s.clone()));
        }
        assert!(script.is_valid());
        // script length > 10000 bytes
        let mut script = Script::new();
        let mut s = String::new();
        let s = "a".repeat(501);
        for _ in 0..20 {
            script.stack.push(StackEntry::Bytes(s.clone()));
        }
        assert!(!script.is_valid());
        // # opcodes <= 201
        let mut script = Script::new();
        for _ in 0..MAX_OPS_PER_SCRIPT {
            script.stack.push(StackEntry::Op(OpCodes::OP_1));
        }
        assert!(script.is_valid());
        // # opcodes > 201
        let mut script = Script::new();
        for _ in 0..=MAX_OPS_PER_SCRIPT {
            script.stack.push(StackEntry::Op(OpCodes::OP_1));
        }
        assert!(!script.is_valid());
    }

    #[test]
    fn test_is_valid_stack() {
        // empty stack
        let mut stack = Stack::new();
        assert!(stack.is_valid());
        // # items on interpreter stack <= 1000
        let mut stack = Stack::new();
        for _ in 0..MAX_STACK_SIZE {
            stack.push(StackEntry::Num(1));
        }
        assert!(stack.is_valid());
        // # items on interpreter stack > 1000
        let mut stack = Stack::new();
        for _ in 0..=MAX_STACK_SIZE {
            stack.push(StackEntry::Num(1));
        }
        assert!(!stack.is_valid());
        // # items on interpreter stack and interpreter alt stack > 1000
        let mut stack = Stack::new();
        for _ in 0..500 {
            stack.push(StackEntry::Num(1));
        }
        for _ in 0..501 {
            stack.push(StackEntry::Num(1));
        }
        assert!(!stack.is_valid());
    }

    #[test]
    fn test_interpret_script() {
        // empty script
        let mut script = Script::new();
        assert!(script.interpret());
        // OP_0
        let mut script = Script::new();
        script.stack.push(StackEntry::Op(OpCodes::OP_0));
        assert!(!script.interpret());
        // OP_1
        let mut script = Script::new();
        script.stack.push(StackEntry::Op(OpCodes::OP_1));
        assert!(script.interpret());
        // OP_1 OP_2 OP_ADD OP_3 OP_EQUAL
        let mut script = Script::new();
        script.stack.push(StackEntry::Op(OpCodes::OP_1));
        script.stack.push(StackEntry::Op(OpCodes::OP_2));
        script.stack.push(StackEntry::Op(OpCodes::OP_ADD));
        script.stack.push(StackEntry::Op(OpCodes::OP_3));
        script.stack.push(StackEntry::Op(OpCodes::OP_EQUAL));
        assert!(script.interpret());
        // script length <= 10000 bytes
        let mut script = Script::new();
        let s = "a".repeat(500);
        for _ in 0..20 {
            script.stack.push(StackEntry::Bytes(s.clone()));
        }
        // script length > 10000 bytes
        let mut script = Script::new();
        let mut s = String::new();
        for _ in 0..501 {
            s.push('a');
        }
        for _ in 0..20 {
            script.stack.push(StackEntry::Bytes(s.clone()));
        }
        assert!(!script.interpret());
        // # opcodes <= 201
        let mut script = Script::new();
        for _ in 0..MAX_OPS_PER_SCRIPT {
            script.stack.push(StackEntry::Op(OpCodes::OP_1));
        }
        // # opcodes > 201
        let mut script = Script::new();
        for _ in 0..=MAX_OPS_PER_SCRIPT {
            script.stack.push(StackEntry::Op(OpCodes::OP_1));
        }
        assert!(!script.interpret());
        // # items on interpreter stack <= 1000
        let mut script = Script::new();
        for _ in 0..MAX_STACK_SIZE {
            script.stack.push(StackEntry::Num(1));
        }
        assert!(script.interpret());
        // # items on interpreter stack > 1000
        let mut script = Script::new();
        for _ in 0..=MAX_STACK_SIZE {
            script.stack.push(StackEntry::Num(1));
        }
        // invalid opcode
        let mut script = Script::new();
        script.stack.push(StackEntry::Op(OpCodes::OP_CAT));
        assert!(!script.interpret());
    }
}