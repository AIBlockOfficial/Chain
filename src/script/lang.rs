#![allow(unused)]
use crate::constants::*;
use crate::crypto::sha3_256;
use crate::crypto::sign_ed25519::{
    PublicKey, Signature, ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN,
};
use crate::script::interface_ops::*;
use crate::script::{OpCodes, ScriptError, StackEntry};
use crate::utils::transaction_utils::construct_address;
use bincode::serialize;
use bytes::Bytes;
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
    pub fn check_preconditions(&self) -> Result<(), ScriptError> {
        if self.main_stack.len() + self.alt_stack.len() > MAX_STACK_SIZE as usize {
            return Err(ScriptError::StackFull);
        }

        Self::check_entries_preconditions(&self.main_stack)?;
        Self::check_entries_preconditions(&self.alt_stack)
    }

    /// Checks that all entries in the given vector are valid
    fn check_entries_preconditions(entries: &Vec<StackEntry>) -> Result<(), ScriptError> {
        for entry in entries {
            Self::check_entry_preconditions(entry)?;
        }
        Ok(())
    }

    /// Checks that the given entry may be pushed on the stack
    fn check_entry_preconditions(entry: &StackEntry) -> Result<(), ScriptError> {
        match entry {
            StackEntry::Op(_) => return Err(ScriptError::ItemType),
            StackEntry::Bytes(s) => {
                if s.len() > MAX_SCRIPT_ITEM_SIZE as usize {
                    return Err(ScriptError::ItemSize(s.len(), MAX_SCRIPT_ITEM_SIZE as usize));
                }
            }
            _ => (),
        };
        Ok(())
    }

    /// Gets the current stack depth
    pub fn depth(&self) -> usize {
        self.main_stack.len()
    }

    /// Pops the top item from the stack
    pub fn pop(&mut self) -> Option<StackEntry> {
        self.main_stack.pop()
    }

    /// Pops the top item from the alt stack
    pub fn pop_alt(&mut self) -> Option<StackEntry> {
        self.alt_stack.pop()
    }

    /// Gets the top item from the stack without popping it
    pub fn peek(&self) -> Option<&StackEntry> {
        self.main_stack.last()
    }

    /// Returns the top item on the stack
    pub fn last(&self) -> Option<StackEntry> {
        self.main_stack.last().cloned()
    }

    /// Checks if the current stack is a valid end state.
    pub fn check_end_state(&self) -> Result<(), ScriptError> {
        if self.main_stack.len() != 1 {
            Err(ScriptError::EndStackDepth(self.main_stack.len()))
        } else if *self.main_stack.last().unwrap() == StackEntry::Num(0) {
            Err(ScriptError::LastEntryIsZero)
        } else {
            Ok(())
        }
    }

    /// Pushes a new entry onto the stack
    pub fn push(&mut self, stack_entry: StackEntry) -> Result<(), ScriptError> {
        Self::push_to(&mut self.main_stack, &self.alt_stack, stack_entry)
    }

    /// Pushes a new entry onto the stack
    pub fn push_alt(&mut self, stack_entry: StackEntry) -> Result<(), ScriptError> {
        Self::push_to(&mut self.alt_stack, &self.main_stack, stack_entry)
    }

    /// Pushes a new entry onto the stack
    fn push_to(dst: &mut Vec<StackEntry>, other: &Vec<StackEntry>, stack_entry: StackEntry) -> Result<(), ScriptError> {
        if dst.len() + other.len() >= MAX_STACK_SIZE as usize {
            return Err(ScriptError::StackFull);
        }

        Self::check_entry_preconditions(&stack_entry)?;
        dst.push(stack_entry);
        Ok(())
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
        self.verify().is_ok()
    }

    /// Checks if a script is valid
    pub fn verify(&self) -> Result<(), ScriptError> {
        // TODO: The length doesn't really make sense, because the actual serialized script
        //       is not actually this size...
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
                StackEntry::Bytes(s) => len += s.len(),
                StackEntry::Num(_) => len += usize::BITS as usize / EIGHT,
            };
        }

        if len > MAX_SCRIPT_SIZE as usize {
            return Err(ScriptError::MaxScriptSize(len));
        } else if ops_count > MAX_OPS_PER_SCRIPT as usize {
            return Err(ScriptError::MaxScriptOps(ops_count));
        }

        // Make sure all IF/NOTIF opcodes have a matching ENDIF, and that there is exactly
        // 0 or 1 ELSE opcodes between them.
        let mut condition_stack : Vec<bool> = Vec::new();
        for entry in &self.stack {
            match entry {
                StackEntry::Op(OpCodes::OP_IF | OpCodes::OP_NOTIF) => condition_stack.push(false),
                StackEntry::Op(OpCodes::OP_ELSE) => match condition_stack.last_mut() {
                    Some(seen_else) => {
                        if *seen_else {
                            return Err(ScriptError::DuplicateElse);
                        }
                        *seen_else = true;
                    },
                    None => return Err(ScriptError::EmptyCondition),
                },
                StackEntry::Op(OpCodes::OP_ENDIF) => match condition_stack.pop() {
                    Some(_) => (),
                    None => return Err(ScriptError::EmptyCondition),
                },
                _ => (),
            }
        }

        Ok(())
    }

    /// Interprets and executes a script
    pub fn interpret(&self) -> bool {
        self.interpret_full().is_ok()
    }

    /// Interprets and executes a script
    pub fn interpret_full(&self) -> Result<(), ScriptError> {
        self.verify()?;

        let mut stack = Stack::new();
        let mut cond_stack = ConditionStack::new();
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
                        OpCodes::OP_0 => stack.push(StackEntry::Num(ZERO)),
                        OpCodes::OP_1 => stack.push(StackEntry::Num(ONE)),
                        OpCodes::OP_2 => stack.push(StackEntry::Num(TWO)),
                        OpCodes::OP_3 => stack.push(StackEntry::Num(THREE)),
                        OpCodes::OP_4 => stack.push(StackEntry::Num(FOUR)),
                        OpCodes::OP_5 => stack.push(StackEntry::Num(FIVE)),
                        OpCodes::OP_6 => stack.push(StackEntry::Num(SIX)),
                        OpCodes::OP_7 => stack.push(StackEntry::Num(SEVEN)),
                        OpCodes::OP_8 => stack.push(StackEntry::Num(EIGHT)),
                        OpCodes::OP_9 => stack.push(StackEntry::Num(NINE)),
                        OpCodes::OP_10 => stack.push(StackEntry::Num(TEN)),
                        OpCodes::OP_11 => stack.push(StackEntry::Num(ELEVEN)),
                        OpCodes::OP_12 => stack.push(StackEntry::Num(TWELVE)),
                        OpCodes::OP_13 => stack.push(StackEntry::Num(THIRTEEN)),
                        OpCodes::OP_14 => stack.push(StackEntry::Num(FOURTEEN)),
                        OpCodes::OP_15 => stack.push(StackEntry::Num(FIFTEEN)),
                        OpCodes::OP_16 => stack.push(StackEntry::Num(SIXTEEN)),
                        // flow control
                        OpCodes::OP_NOP => op_nop(&mut stack),
                        OpCodes::OP_IF => op_if(&mut stack, &mut cond_stack),
                        OpCodes::OP_NOTIF => op_notif(&mut stack, &mut cond_stack),
                        OpCodes::OP_ELSE => op_else(&mut cond_stack),
                        OpCodes::OP_ENDIF => op_endif(&mut cond_stack),
                        OpCodes::OP_VERIFY => op_verify(&mut stack),
                        OpCodes::OP_BURN => op_burn(&mut stack),
                        // stack
                        OpCodes::OP_TOALTSTACK => op_toaltstack(&mut stack),
                        OpCodes::OP_FROMALTSTACK => op_fromaltstack(&mut stack),
                        OpCodes::OP_2DROP => op_2drop(&mut stack),
                        OpCodes::OP_2DUP => op_2dup(&mut stack),
                        OpCodes::OP_3DUP => op_3dup(&mut stack),
                        OpCodes::OP_2OVER => op_2over(&mut stack),
                        OpCodes::OP_2ROT => op_2rot(&mut stack),
                        OpCodes::OP_2SWAP => op_2swap(&mut stack),
                        OpCodes::OP_IFDUP => op_ifdup(&mut stack),
                        OpCodes::OP_DEPTH => op_depth(&mut stack),
                        OpCodes::OP_DROP => op_drop(&mut stack),
                        OpCodes::OP_DUP => op_dup(&mut stack),
                        OpCodes::OP_NIP => op_nip(&mut stack),
                        OpCodes::OP_OVER => op_over(&mut stack),
                        OpCodes::OP_PICK => op_pick(&mut stack),
                        OpCodes::OP_ROLL => op_roll(&mut stack),
                        OpCodes::OP_ROT => op_rot(&mut stack),
                        OpCodes::OP_SWAP => op_swap(&mut stack),
                        OpCodes::OP_TUCK => op_tuck(&mut stack),
                        // splice
                        OpCodes::OP_CAT => op_cat(&mut stack),
                        OpCodes::OP_SUBSTR => op_substr(&mut stack),
                        OpCodes::OP_LEFT => op_left(&mut stack),
                        OpCodes::OP_RIGHT => op_right(&mut stack),
                        OpCodes::OP_SIZE => op_size(&mut stack),
                        // bitwise logic
                        OpCodes::OP_INVERT => op_invert(&mut stack),
                        OpCodes::OP_AND => op_and(&mut stack),
                        OpCodes::OP_OR => op_or(&mut stack),
                        OpCodes::OP_XOR => op_xor(&mut stack),
                        OpCodes::OP_EQUAL => op_equal(&mut stack),
                        OpCodes::OP_EQUALVERIFY => op_equalverify(&mut stack),
                        // arithmetic
                        OpCodes::OP_1ADD => op_1add(&mut stack),
                        OpCodes::OP_1SUB => op_1sub(&mut stack),
                        OpCodes::OP_2MUL => op_2mul(&mut stack),
                        OpCodes::OP_2DIV => op_2div(&mut stack),
                        OpCodes::OP_NOT => op_not(&mut stack),
                        OpCodes::OP_0NOTEQUAL => op_0notequal(&mut stack),
                        OpCodes::OP_ADD => op_add(&mut stack),
                        OpCodes::OP_SUB => op_sub(&mut stack),
                        OpCodes::OP_MUL => op_mul(&mut stack),
                        OpCodes::OP_DIV => op_div(&mut stack),
                        OpCodes::OP_MOD => op_mod(&mut stack),
                        OpCodes::OP_LSHIFT => op_lshift(&mut stack),
                        OpCodes::OP_RSHIFT => op_rshift(&mut stack),
                        OpCodes::OP_BOOLAND => op_booland(&mut stack),
                        OpCodes::OP_BOOLOR => op_boolor(&mut stack),
                        OpCodes::OP_NUMEQUAL => op_numequal(&mut stack),
                        OpCodes::OP_NUMEQUALVERIFY => op_numequalverify(&mut stack),
                        OpCodes::OP_NUMNOTEQUAL => op_numnotequal(&mut stack),
                        OpCodes::OP_LESSTHAN => op_lessthan(&mut stack),
                        OpCodes::OP_GREATERTHAN => op_greaterthan(&mut stack),
                        OpCodes::OP_LESSTHANOREQUAL => op_lessthanorequal(&mut stack),
                        OpCodes::OP_GREATERTHANOREQUAL => op_greaterthanorequal(&mut stack),
                        OpCodes::OP_MIN => op_min(&mut stack),
                        OpCodes::OP_MAX => op_max(&mut stack),
                        OpCodes::OP_WITHIN => op_within(&mut stack),
                        // crypto
                        OpCodes::OP_SHA3 => op_sha3(&mut stack),
                        OpCodes::OP_HASH256 => op_hash256(&mut stack),
                        OpCodes::OP_CHECKSIG => op_checksig(&mut stack),
                        OpCodes::OP_CHECKSIGVERIFY => op_checksigverify(&mut stack),
                        OpCodes::OP_CHECKMULTISIG => op_checkmultisig(&mut stack),
                        OpCodes::OP_CHECKMULTISIGVERIFY => op_checkmultisigverify(&mut stack),
                        // smart data
                        OpCodes::OP_CREATE => Ok(()),
                        // reserved
                        op => Err(ScriptError::ReservedOpcode(op)),
                    }
                }
                /*---- SIGNATURE | PUBKEY | NUM | BYTES ----*/
                StackEntry::Signature(_)
                | StackEntry::PubKey(_)
                | StackEntry::Num(_)
                | StackEntry::Bytes(_) => {
                    if cond_stack.all_true() {
                        stack.push(stack_entry.clone())
                    } else {
                        Ok(())
                    }
                }
            }?;

            stack.check_preconditions()?;
        }

        if !cond_stack.is_empty() {
            Err(ScriptError::NotEmptyCondition)
        } else {
            stack.check_end_state()
        }
    }

    /// Constructs a new script for coinbase
    ///
    /// ### Arguments
    ///
    /// * `block_number`  - The block time to push
    pub fn new_for_coinbase(block_number: u64) -> Self {
        let stack = vec![StackEntry::Num(block_number as usize)];
        Self { stack }
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
        let stack = vec![
            StackEntry::Op(OpCodes::OP_CREATE),
            StackEntry::Num(block_number as usize),
            StackEntry::Op(OpCodes::OP_DROP),
            StackEntry::Bytes(hex::decode(asset_hash).expect("asset_hash contains non-hex characters")),
            StackEntry::Signature(signature),
            StackEntry::PubKey(pub_key),
            StackEntry::Op(OpCodes::OP_CHECKSIG),
        ];
        Self { stack }
    }

    /// Constructs a pay to public key hash script
    ///
    /// ### Arguments
    ///
    /// * `check_data`  - Check data to provide signature
    /// * `signature`   - Signature of check data
    /// * `pub_key`     - Public key of the payer
    pub fn pay2pkh(
        check_data: Vec<u8>,
        signature: Signature,
        pub_key: PublicKey,
    ) -> Self {
        let stack = vec![
            StackEntry::Bytes(check_data),
            StackEntry::Signature(signature),
            StackEntry::PubKey(pub_key),
            StackEntry::Op(OpCodes::OP_DUP),
            StackEntry::Op(OpCodes::OP_HASH256),
            StackEntry::Bytes(hex::decode(construct_address(&pub_key))
                .expect("address contains non-hex characters?")),
            StackEntry::Op(OpCodes::OP_EQUALVERIFY),
            StackEntry::Op(OpCodes::OP_CHECKSIG),
        ];
        Self { stack }
    }

    /// Constructs one part of a multiparty transaction script
    ///
    /// ### Arguments
    ///
    /// * `check_data`  - Data to be signed for verification
    /// * `pub_key`     - Public key of this party
    /// * `signature`   - Signature of this party
    pub fn member_multisig(check_data: Vec<u8>, pub_key: PublicKey, signature: Signature) -> Self {
        let stack = vec![
            StackEntry::Bytes(check_data),
            StackEntry::Signature(signature),
            StackEntry::PubKey(pub_key),
            StackEntry::Op(OpCodes::OP_CHECKSIG),
        ];
        Self { stack }
    }

    /// Constructs a multisig locking script
    ///
    /// ### Arguments
    ///
    /// * `m`           - Number of signatures required to unlock
    /// * `n`           - Number of valid signatures total
    /// * `check_data`  - Data to have checked against signatures
    /// * `pub_keys`    - The constituent public keys
    pub fn multisig_lock(m: usize, n: usize, check_data: Vec<u8>, pub_keys: Vec<PublicKey>) -> Self {
        let mut stack = vec![StackEntry::Bytes(check_data), StackEntry::Num(m)];
        stack.append(&mut pub_keys.iter().map(|e| StackEntry::PubKey(*e)).collect());
        stack.push(StackEntry::Num(n));
        stack.push(StackEntry::Op(OpCodes::OP_CHECKMULTISIG));
        Self { stack }
    }

    /// Constructs a multisig unlocking script
    ///
    /// ### Arguments
    ///
    /// * `check_data`  - Data to have signed
    /// * `signatures`  - Signatures to unlock with
    pub fn multisig_unlock(check_data: Vec<u8>, signatures: Vec<Signature>) -> Self {
        let mut stack = vec![StackEntry::Bytes(check_data)];
        stack.append(
            &mut signatures
                .iter()
                .map(|e| StackEntry::Signature(*e))
                .collect(),
        );
        Self { stack }
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
        check_data: Vec<u8>,
        signatures: Vec<Signature>,
        pub_keys: Vec<PublicKey>,
    ) -> Self {
        let mut stack = vec![StackEntry::Bytes(check_data)];
        stack.append(
            &mut signatures
                .iter()
                .map(|e| StackEntry::Signature(*e))
                .collect(),
        );
        stack.push(StackEntry::Num(m));
        stack.append(&mut pub_keys.iter().map(|e| StackEntry::PubKey(*e)).collect());
        stack.push(StackEntry::Num(n));
        stack.push(StackEntry::Op(OpCodes::OP_CHECKMULTISIG));
        Self { stack }
    }
}

impl From<Vec<StackEntry>> for Script {
    /// Creates a new script with a pre-filled stack
    fn from(s: Vec<StackEntry>) -> Self {
        Script { stack: s }
    }
}
