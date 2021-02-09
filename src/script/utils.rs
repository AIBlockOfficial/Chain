#![allow(unused)]
use crate::constants::TOTAL_TOKENS;
use crate::primitives::asset::{Asset, TokenAmount};
use crate::primitives::transaction::*;
use crate::primitives::transaction_utils::construct_address;
use crate::script::interface_ops;
use crate::script::lang::Script;
use crate::script::{OpCodes, StackEntry};
use crate::sha3::Digest;

use bincode::serialize;
use bytes::Bytes;
use hex::encode;
use sha3::Sha3_256;
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::sign::ed25519::{PublicKey, Signature};
use std::collections::BTreeMap;
use tracing::{debug, error, info, trace};

/// Verifies that a member of a multisig tx script is valid
///
/// ### Arguments
///
/// * `script`  - Script to verify
pub fn member_multisig_is_valid(script: Script) -> bool {
    let mut current_stack: Vec<StackEntry> = Vec::with_capacity(script.stack.len());

    for stack_entry in script.stack {
        match stack_entry {
            StackEntry::Op(OpCodes::OP_CHECKSIG) => {
                return interface_ops::op_checkmultisigmem(&mut current_stack);
            }
            _ => {
                println!("Adding constant to stack: {:?}", stack_entry);
                current_stack.push(stack_entry);
            }
        }
    }

    true
}

/// Verifies that all incoming transactions are allowed to be spent. Returns false if a single
/// transaction doesn't verify
///
/// TODO: Currently assumes p2pkh, abstract to all tx types
///
/// ### Arguments
///
/// * `tx_ins`  - Tx_ins to verify
pub fn tx_is_valid<'a>(
    tx: &Transaction,
    is_in_utxo: impl Fn(&OutPoint) -> Option<&'a TxOut> + 'a,
) -> bool {
    let mut tx_in_amount = TokenAmount(0);

    for tx_in in &tx.inputs {
        let tx_out_point = tx_in.previous_out.as_ref().unwrap().clone();
        let tx_out = is_in_utxo(&tx_out_point);

        let tx_out = if let Some(tx_out) = is_in_utxo(&tx_out_point) {
            tx_out
        } else {
            error!("UTXO DOESN'T CONTAIN THIS TX");
            return false;
        };

        // At this point TxOut will be valid
        let tx_out_pk = tx_out.script_public_key.as_ref();
        let tx_out_hash = hex::encode(serialize(&tx_out_point).unwrap());

        if let Some(pk) = tx_out_pk {
            // Check will need to include other signature types here
            if !tx_has_valid_p2pkh_sig(&tx_in.script_signature, &tx_out_hash, &pk) {
                return false;
            }
        } else {
            return false;
        }

        tx_in_amount += tx_out.amount;
    }

    tx_outs_are_valid(&tx.outputs, tx_in_amount)
}

/// Verifies that the outgoing TxOuts are valid. Returns false if a single
/// transaction doesn't verify
///
/// ### Arguments
///
/// * `tx_outs` - TxOuts to verify
/// * `amount_spent` - Total amount spendable from TxIns
pub fn tx_outs_are_valid(tx_outs: &[TxOut], amount_spent: TokenAmount) -> bool {
    let tx_out_amount = tx_outs.iter().fold(TokenAmount(0), |acc, i| acc + i.amount);

    tx_out_amount <= TokenAmount(TOTAL_TOKENS) && tx_out_amount == amount_spent
}

/// Checks whether a complete validation multisig transaction is in fact valid
///
/// ### Arguments
///
/// * `script`  - Script to validate
fn tx_has_valid_multsig_validation(script: &Script) -> bool {
    let mut current_stack: Vec<StackEntry> = Vec::with_capacity(script.stack.len());

    for stack_entry in &script.stack {
        match stack_entry {
            StackEntry::Op(OpCodes::OP_CHECKMULTISIG) => {
                return interface_ops::op_multisig(&mut current_stack);
            }
            _ => {
                return interface_ops::op_else(&stack_entry, &mut current_stack);
            }
        }
    }

    true
}

/// Checks whether a transaction to spend tokens in P2PKH has a valid signature
///
/// ### Arguments
///
/// * `script`          - Script to validate
/// * `outpoint_hash`   - Hash of the corresponding outpoint
/// * `tx_out_pub_key`  - Public key of the previous tx_out
fn tx_has_valid_p2pkh_sig(script: &Script, outpoint_hash: &str, tx_out_pub_key: &str) -> bool {
    let mut it = script.stack.iter();

    if let (
        Some(StackEntry::Bytes(b)),
        Some(StackEntry::Signature(_)),
        Some(StackEntry::PubKey(_)),
        Some(StackEntry::Op(OpCodes::OP_DUP)),
        Some(StackEntry::Op(OpCodes::OP_HASH256)),
        Some(StackEntry::PubKeyHash(h)),
        Some(StackEntry::Op(OpCodes::OP_EQUALVERIFY)),
        Some(StackEntry::Op(OpCodes::OP_CHECKSIG)),
        None,
    ) = (
        it.next(),
        it.next(),
        it.next(),
        it.next(),
        it.next(),
        it.next(),
        it.next(),
        it.next(),
        it.next(),
    ) {
        if h == tx_out_pub_key && b == outpoint_hash && interpret_script(script) {
            return true;
        }
    }

    trace!(
        "Invalid script: {:?} tx_out_pub_key: {}",
        script.stack,
        tx_out_pub_key
    );

    false
}

/// Handles the byte code unwrap and execution for transaction scripts
///
/// ### Arguments
///
/// * `script`  - Script to unwrap and execute
fn interpret_script(script: &Script) -> bool {
    let mut current_stack: Vec<StackEntry> = Vec::with_capacity(script.stack.len());

    for stack_entry in &script.stack {
        match stack_entry {
            StackEntry::Op(OpCodes::OP_DUP) => {
                return interface_ops::op_dup(&mut current_stack);
            }
            StackEntry::Op(OpCodes::OP_HASH256) => {
                return interface_ops::op_hash256(&mut current_stack);
            }
            StackEntry::Op(OpCodes::OP_EQUALVERIFY) => {
                return interface_ops::op_equalverify(&mut current_stack);
            }
            StackEntry::Op(OpCodes::OP_CHECKSIG) => {
                return interface_ops::op_checksig(&mut current_stack);
            }
            _ => {
                println!("Adding constant to stack: {:?}", stack_entry);
                current_stack.push(stack_entry.clone());
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::transaction_utils::{construct_address, construct_payment_tx_ins};

    /// Util function to create p2pkh TxIns
    fn create_multisig_tx_ins(tx_values: Vec<TxConstructor>, m: usize) -> Vec<TxIn> {
        let mut tx_ins = Vec::new();

        for entry in tx_values {
            let mut new_tx_in = TxIn::new();
            new_tx_in.script_signature = Script::multisig_validation(
                m,
                entry.pub_keys.len(),
                entry.t_hash.clone(),
                entry.signatures,
                entry.pub_keys,
            );
            new_tx_in.previous_out = Some(OutPoint::new(entry.t_hash, entry.prev_n));

            tx_ins.push(new_tx_in);
        }

        tx_ins
    }

    /// Util function to create multisig member TxIns
    fn create_multisig_member_tx_ins(tx_values: Vec<TxConstructor>) -> Vec<TxIn> {
        let mut tx_ins = Vec::new();

        for entry in tx_values {
            let mut new_tx_in = TxIn::new();
            new_tx_in.script_signature = Script::member_multisig(
                entry.t_hash.clone(),
                entry.pub_keys[0],
                entry.signatures[0],
            );
            new_tx_in.previous_out = Some(OutPoint::new(entry.t_hash, entry.prev_n));

            tx_ins.push(new_tx_in);
        }

        tx_ins
    }

    #[test]
    /// Checks that correct member multisig scripts are validated as such
    fn should_pass_member_multisig_valid() {
        let (pk, sk) = sign::gen_keypair();
        let t_hash = hex::encode(vec![0, 0, 0]);
        let signature = sign::sign_detached(t_hash.as_bytes(), &sk);

        let tx_const = TxConstructor {
            t_hash,
            prev_n: 0,
            signatures: vec![signature],
            pub_keys: vec![pk],
        };

        let tx_ins = create_multisig_member_tx_ins(vec![tx_const]);

        assert!(member_multisig_is_valid(tx_ins[0].clone().script_signature));
    }

    #[test]
    /// Checks that incorrect member multisig scripts are validated as such
    fn should_fail_member_multisig_invalid() {
        let (_pk, sk) = sign::gen_keypair();
        let (pk, _sk) = sign::gen_keypair();
        let t_hash = hex::encode(vec![0, 0, 0]);
        let signature = sign::sign_detached(t_hash.as_bytes(), &sk);

        let tx_const = TxConstructor {
            t_hash,
            prev_n: 0,
            signatures: vec![signature],
            pub_keys: vec![pk],
        };

        let tx_ins = create_multisig_member_tx_ins(vec![tx_const]);

        assert_eq!(
            member_multisig_is_valid(tx_ins[0].clone().script_signature),
            false
        );
    }

    #[test]
    /// Checks that correct p2pkh transaction signatures are validated as such
    fn should_pass_p2pkh_sig_valid() {
        let (pk, sk) = sign::gen_keypair();
        let t_hash = hex::encode(vec![0, 0, 0]);
        let outpoint = OutPoint {
            t_hash: t_hash.clone(),
            n: 0,
        };

        let hash_to_sign = hex::encode(serialize(&outpoint).unwrap());
        let signature = sign::sign_detached(&hash_to_sign.as_bytes(), &sk);

        let tx_const = TxConstructor {
            t_hash,
            prev_n: 0,
            signatures: vec![signature],
            pub_keys: vec![pk],
        };

        let tx_ins = construct_payment_tx_ins(vec![tx_const]);
        let tx_out_pk = construct_address(pk);

        assert!(tx_has_valid_p2pkh_sig(
            &tx_ins[0].script_signature,
            &hash_to_sign,
            &tx_out_pk
        ));
    }

    #[test]
    /// Checks that invalid p2pkh transaction signatures are validated as such
    fn should_fail_p2pkh_sig_invalid() {
        let (pk, sk) = sign::gen_keypair();
        let (second_pk, _s) = sign::gen_keypair();
        let t_hash = hex::encode(vec![0, 0, 0]);
        let outpoint = OutPoint {
            t_hash: t_hash.clone(),
            n: 0,
        };

        let hash_to_sign = hex::encode(serialize(&outpoint).unwrap());
        let signature = sign::sign_detached(&hash_to_sign.as_bytes(), &sk);

        let tx_const = TxConstructor {
            t_hash,
            prev_n: 0,
            signatures: vec![signature],
            pub_keys: vec![second_pk],
        };

        let tx_ins = construct_payment_tx_ins(vec![tx_const]);
        let tx_out_pk = construct_address(pk);

        assert_eq!(
            tx_has_valid_p2pkh_sig(&tx_ins[0].script_signature, &hash_to_sign, &tx_out_pk),
            false
        );
    }

    #[test]
    /// Checks that invalid p2pkh transaction signatures are validated as such
    fn should_fail_p2pkh_sig_script_empty() {
        let (pk, sk) = sign::gen_keypair();
        let t_hash = hex::encode(vec![0, 0, 0]);
        let outpoint = OutPoint {
            t_hash: t_hash.clone(),
            n: 0,
        };

        let hash_to_sign = hex::encode(serialize(&outpoint).unwrap());
        let signature = sign::sign_detached(&hash_to_sign.as_bytes(), &sk);

        let tx_const = TxConstructor {
            t_hash,
            prev_n: 0,
            signatures: vec![signature],
            pub_keys: vec![pk],
        };

        let mut tx_ins = Vec::new();

        for entry in vec![tx_const] {
            let mut new_tx_in = TxIn::new();
            new_tx_in.script_signature = Script::new();
            new_tx_in.previous_out = Some(OutPoint::new(entry.t_hash, entry.prev_n));

            tx_ins.push(new_tx_in);
        }

        let tx_out_pk = construct_address(pk);

        assert_eq!(
            tx_has_valid_p2pkh_sig(&tx_ins[0].script_signature, &hash_to_sign, &tx_out_pk),
            false
        );
    }

    #[test]
    /// Checks that invalid p2pkh transaction signatures are validated as such
    fn should_fail_p2pkh_sig_script_invalid_struct() {
        let (pk, sk) = sign::gen_keypair();
        let t_hash = hex::encode(vec![0, 0, 0]);
        let outpoint = OutPoint {
            t_hash: t_hash.clone(),
            n: 0,
        };

        let hash_to_sign = hex::encode(serialize(&outpoint).unwrap());
        let signature = sign::sign_detached(&hash_to_sign.as_bytes(), &sk);

        let tx_const = TxConstructor {
            t_hash,
            prev_n: 0,
            signatures: vec![signature],
            pub_keys: vec![pk],
        };

        let mut tx_ins = Vec::new();

        for entry in vec![tx_const] {
            let mut new_tx_in = TxIn::new();
            new_tx_in.script_signature = Script::new();
            new_tx_in
                .script_signature
                .stack
                .push(StackEntry::Bytes("".to_string()));
            new_tx_in.previous_out = Some(OutPoint::new(entry.t_hash, entry.prev_n));

            tx_ins.push(new_tx_in);
        }

        let tx_out_pk = construct_address(pk);

        assert_eq!(
            tx_has_valid_p2pkh_sig(&tx_ins[0].script_signature, &hash_to_sign, &tx_out_pk),
            false
        );
    }

    #[test]
    /// Checks that correct multisig validation signatures are validated as such
    fn should_pass_multisig_validation_valid() {
        let (first_pk, first_sk) = sign::gen_keypair();
        let (second_pk, second_sk) = sign::gen_keypair();
        let (third_pk, third_sk) = sign::gen_keypair();
        let check_data = hex::encode(vec![0, 0, 0]);

        let m = 2;
        let first_sig = sign::sign_detached(check_data.as_bytes(), &first_sk);
        let second_sig = sign::sign_detached(check_data.as_bytes(), &second_sk);
        let third_sig = sign::sign_detached(check_data.as_bytes(), &third_sk);

        let tx_const = TxConstructor {
            t_hash: hex::encode(vec![0, 0, 0]),
            prev_n: 0,
            signatures: vec![first_sig, second_sig, third_sig],
            pub_keys: vec![first_pk, second_pk, third_pk],
        };

        let tx_ins = create_multisig_tx_ins(vec![tx_const], m);

        assert!(tx_has_valid_multsig_validation(&tx_ins[0].script_signature));
    }

    #[test]
    /// Ensures that enough pubkey-sigs are provided to complete the multisig
    fn should_pass_sig_pub_keypairs_for_multisig_valid() {
        let (first_pk, first_sk) = sign::gen_keypair();
        let (second_pk, second_sk) = sign::gen_keypair();
        let (third_pk, third_sk) = sign::gen_keypair();
        let check_data = hex::encode(vec![0, 0, 0]);

        let m = 2;
        let first_sig = sign::sign_detached(check_data.as_bytes(), &first_sk);
        let second_sig = sign::sign_detached(check_data.as_bytes(), &second_sk);
        let third_sig = sign::sign_detached(check_data.as_bytes(), &third_sk);

        assert!(match_on_multisig_to_pubkey(
            check_data,
            vec![first_sig, second_sig, third_sig],
            vec![first_pk, second_pk, third_pk],
            m
        ));
    }

    #[test]
    /// Validate tx_is_valid for multiple TxIn configurations
    fn test_tx_is_valid() {
        //
        // Arrange
        //
        let (pk, sk) = sign::gen_keypair();
        let tx_hash = hex::encode(vec![0, 0, 0]);
        let tx_outpoint = OutPoint::new(tx_hash, 0);
        let script_public_key = construct_address(pk);
        let tx_out = TxOut {
            script_public_key: Some(script_public_key.clone()),
            ..TxOut::default()
        };

        let valid_bytes = hex::encode(serialize(&tx_outpoint).unwrap());
        let valid_sig = sign::sign_detached(&valid_bytes.as_bytes(), &sk);

        // Test cases:
        let inputs = vec![
            // 0. Happy case: valid test
            (
                vec![
                    StackEntry::Bytes(valid_bytes),
                    StackEntry::Signature(valid_sig),
                    StackEntry::PubKey(pk),
                    StackEntry::Op(OpCodes::OP_DUP),
                    StackEntry::Op(OpCodes::OP_HASH256),
                    StackEntry::PubKeyHash(script_public_key),
                    StackEntry::Op(OpCodes::OP_EQUALVERIFY),
                    StackEntry::Op(OpCodes::OP_CHECKSIG),
                ],
                true,
            ),
            // 2. Empty script
            (vec![StackEntry::Bytes("".to_string())], false),
        ];

        //
        // Act
        //
        let mut actual_result = Vec::new();
        for (script, _) in &inputs {
            let tx_ins = vec![TxIn {
                script_signature: Script {
                    stack: script.clone(),
                },
                previous_out: Some(tx_outpoint.clone()),
            }];
            let ongoing_tx_outs = vec![TxOut::new()];
            let tx =
                Transaction::new_from_input(tx_ins, ongoing_tx_outs, 0, None, None, None, None);

            let result = tx_is_valid(&tx, |v| Some(&tx_out).filter(|_| v == &tx_outpoint));
            actual_result.push(result);
        }

        //
        // Assert
        //
        assert_eq!(
            actual_result,
            inputs.iter().map(|(_, e)| *e).collect::<Vec<bool>>(),
        );
    }

    #[test]
    /// Checks that incorrect member multisig scripts are validated as such
    fn should_fail_interpret_valid() {
        let (_pk, sk) = sign::gen_keypair();
        let (pk, _sk) = sign::gen_keypair();
        let t_hash = hex::encode(vec![0, 0, 0]);
        let signature = sign::sign_detached(t_hash.as_bytes(), &sk);

        let tx_const = TxConstructor {
            t_hash,
            prev_n: 0,
            signatures: vec![signature],
            pub_keys: vec![pk],
        };

        let tx_ins = create_multisig_member_tx_ins(vec![tx_const]);

        assert_eq!(
            interpret_script(&(tx_ins[0].clone().script_signature)),
            false
        );
    }

    #[test]
    /// Checks that correct member multisig scripts are validated as such
    fn should_pass_interpret_valid() {
        let (pk, sk) = sign::gen_keypair();
        let t_hash = hex::encode(vec![0, 0, 0]);
        let signature = sign::sign_detached(t_hash.as_bytes(), &sk);

        let tx_const = TxConstructor {
            t_hash,
            prev_n: 0,
            signatures: vec![signature],
            pub_keys: vec![pk],
        };

        let tx_ins = create_multisig_member_tx_ins(vec![tx_const]);

        assert!(interpret_script(&(tx_ins[0].clone().script_signature)));
    }
}
