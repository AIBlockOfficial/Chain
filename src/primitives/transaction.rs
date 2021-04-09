#![allow(unused)]
use bincode::serialize;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::sign::ed25519::{PublicKey, Signature};

use crate::primitives::asset::{Asset, TokenAmount};
use crate::script::lang::Script;
use crate::script::{OpCodes, StackEntry};
use crate::utils::is_valid_amount;

/// A user-friendly construction struct for a TxIn
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TxConstructor {
    pub t_hash: String,
    pub prev_n: i32,
    pub signatures: Vec<Signature>,
    pub pub_keys: Vec<PublicKey>,
}

/// An outpoint - a combination of a transaction hash and an index n into its vout
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct OutPoint {
    pub t_hash: String,
    pub n: i32,
}

impl OutPoint {
    /// Creates a new outpoint instance
    pub fn new(t_hash: String, n: i32) -> OutPoint {
        OutPoint { t_hash, n }
    }
}

/// An input of a transaction. It contains the location of the previous
/// transaction's output that it claims and a signature that matches the
/// output's public key.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TxIn {
    pub previous_out: Option<OutPoint>,
    pub script_signature: Script,
}

impl Default for TxIn {
    fn default() -> Self {
        Self::new()
    }
}

impl TxIn {
    /// Creates a new TxIn instance
    pub fn new() -> TxIn {
        let mut script_sig = Script::new();
        script_sig.stack.push(StackEntry::Op(OpCodes::OP_0));

        TxIn {
            previous_out: None,
            script_signature: script_sig,
        }
    }

    /// Creates a new TxIn instance from provided inputs
    ///
    /// ### Arguments
    ///
    /// * `previous_out`    - Outpoint of the previous transaction
    /// * `script_sig`      - Script signature of the previous outpoint
    pub fn new_from_input(previous_out: OutPoint, script_sig: Script) -> TxIn {
        TxIn {
            previous_out: Some(previous_out),
            script_signature: script_sig,
        }
    }
}

/// An output of a transaction. It contains the public key that the next input
/// must be able to sign with to claim it. It also contains the block hash for the
/// potential DRS if this is a data asset transaction
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TxOut {
    pub value: Option<Asset>,
    pub amount: TokenAmount,
    pub locktime: u64,
    pub drs_block_hash: Option<String>,
    pub drs_tx_hash: Option<String>,
    pub script_public_key: Option<String>,
}

impl Default for TxOut {
    fn default() -> Self {
        Self::new()
    }
}

impl TxOut {
    /// Creates a new TxOut instance
    pub fn new() -> TxOut {
        TxOut {
            value: None,
            amount: TokenAmount(0),
            drs_tx_hash: None,
            locktime: 0,
            drs_block_hash: None,
            script_public_key: None,
        }
    }

    pub fn new_amount(to_address: String, amount: TokenAmount) -> TxOut {
        TxOut {
            value: Some(Asset::Token(amount)),
            amount,
            locktime: 0,
            script_public_key: Some(to_address),
            drs_block_hash: None,
            drs_tx_hash: None,
        }
    }
}

/// The basic transaction that is broadcasted on the network and contained in
/// blocks. A transaction can contain multiple inputs and outputs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Transaction {
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub version: usize,
    pub druid: Option<String>,
    pub druid_participants: Option<usize>,
    pub expect_value: Option<Asset>,
    pub expect_value_amount: Option<TokenAmount>,
    pub expect_address: Option<String>,
}

impl Default for Transaction {
    fn default() -> Self {
        Self::new()
    }
}

impl Transaction {
    /// Creates a new Transaction instance
    pub fn new() -> Transaction {
        Transaction {
            inputs: Vec::new(),
            outputs: Vec::new(),
            version: 0,
            druid: None,
            druid_participants: None,
            expect_value: None,
            expect_value_amount: None,
            expect_address: None,
        }
    }

    /// Creates a new Transaction instance from inputs
    ///
    /// ### Arguments
    ///
    /// * `inputs`              - Transaction inputs
    /// * `outputs`             - Transaction outputs
    /// * `version`             - Network version
    /// * `druid`               - DRUID value for a dual double entry
    /// * `expect_value`        - Value expected in return for this payment (only in dual double)
    /// * `expect_value_amount` - Amount of value expected in return for this payment (only in dual double)
    pub fn new_from_input(
        inputs: Vec<TxIn>,
        outputs: Vec<TxOut>,
        version: usize,
        druid: Option<String>,
        druid_participants: Option<usize>,
        expect_value: Option<Asset>,
        expect_value_amount: Option<TokenAmount>,
        expect_address: Option<String>,
    ) -> Transaction {
        Transaction {
            inputs,
            outputs,
            version,
            druid,
            druid_participants,
            expect_value,
            expect_value_amount,
            expect_address,
        }
    }

    /// Gets the total value of all outputs and checks that it is within the
    /// possible amounts set by chain system
    pub fn get_output_value(&mut self) -> TokenAmount {
        let mut total_value = TokenAmount(0);

        for txout in &mut self.outputs {
            if txout.value.is_some() {
                // we're safe to unwrap here
                let this_value = txout.value.clone().unwrap();

                if let Asset::Token(token_val) = this_value {
                    if !is_valid_amount(&token_val) {
                        panic!("TxOut value {value} out of range", value = token_val);
                    }

                    total_value.0 += token_val.0;

                    if !is_valid_amount(&total_value) {
                        panic!(
                            "Total TxOut value of {value} out of range",
                            value = total_value
                        );
                    }
                }
            }
        }

        total_value
    }

    /// Get the total transaction size in bytes
    pub fn get_total_size(&self) -> usize {
        let data = Bytes::from(serialize(&self).unwrap());
        data.len()
    }

    /// Returns whether current transaction is a coinbase tx
    pub fn is_coinbase(&self) -> bool {
        self.inputs.len() == 1 && self.inputs[0].previous_out == None
    }
}
