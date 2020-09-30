use crate::primitives::asset::{Asset, AssetInTransit};
use crate::primitives::transaction::*;
use crate::script::lang::Script;
use crate::sha3::Digest;

use bincode::serialize;
use bytes::Bytes;
use rayon::prelude::*;
use sha3::Sha3_256;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// Constructs the UTXO set for the current state of the blockchain. The set passed
/// needs to consist of all transactions which the system does not currently know the state of.
///
/// ### Arguments
///
/// * `current_utxo` - The current UTXO set to be updated.
pub fn construct_utxo_set(current_utxo: &mut Arc<Mutex<BTreeMap<String, Transaction>>>) {
    let value_set: Vec<Transaction> = current_utxo
        .lock()
        .unwrap()
        .clone()
        .into_iter()
        .map(|(_, val)| val.clone())
        .collect();

    value_set.par_iter().for_each(|x| {
        for input in x.inputs.clone() {
            current_utxo
                .lock()
                .unwrap()
                .remove(&input.previous_out.unwrap().t_hash);
        }
    });
}

/// Constructs a search-valid hash for a transaction to be added to the blockchain
///
/// ### Arguments
///
/// * `tx`  - Transaction to hash
pub fn construct_tx_hash(tx: &Transaction) -> String {
    let tx_bytes = Bytes::from(serialize(tx).unwrap());
    let tx_raw_h = Sha3_256::digest(&tx_bytes).to_vec();
    let mut hash = hex::encode(tx_raw_h);

    hash.insert(0, 'g');
    hash.truncate(32);

    hash
}

/// Constructs a transaction for the creation of a new smart data asset
///
/// ### Arguments
///
/// * `drs`                 - Digital rights signature for the new asset
/// * `receiver_address`    - Address to receive the newly created asset
/// * `amount`              - Amount of the asset to generate
pub fn construct_create_tx(drs: Vec<u8>, receiver_address: String, amount: u64) -> Transaction {
    let mut tx = Transaction::new();
    let mut tx_out = TxOut::new();

    tx_out.value = Some(Asset::Data(drs));
    tx_out.amount = amount;
    tx_out.script_public_key = Some(receiver_address);

    // Provide an empty TxIn
    tx.inputs.push(TxIn::new());

    tx.outputs = vec![tx_out];
    tx.version = 0;

    tx
}

/// Constructs a transaction to pay a receiver
///
/// TODO: Check whether the `amount` is valid in the TxIns
/// TODO: Call this a charity tx or something, as a payment is an exchange of goods
///
/// ### Arguments
///
/// * `tx_ins`              - Address/es to pay from
/// * `receiver_address`    - Address to send to
/// * `drs_block_hash`      - Hash of the block containing the original DRS. Only for data trades
/// * `amount`              - Number of tokens to send
pub fn construct_payment_tx(
    tx_ins: Vec<TxIn>,
    receiver_address: String,
    drs_block_hash: Option<String>,
    drs_tx_hash: Option<String>,
    asset: Asset,
    amount: u64,
) -> Transaction {
    let mut tx = Transaction::new();
    let mut tx_out = TxOut::new();

    tx_out.value = Some(asset);
    tx_out.amount = amount;
    tx_out.script_public_key = Some(receiver_address);
    tx_out.drs_block_hash = drs_block_hash;
    tx_out.drs_tx_hash = drs_tx_hash;

    tx.outputs = vec![tx_out];
    tx.inputs = tx_ins;
    tx.version = 0;

    tx
}

/// Constructs a set of TxIns for a payment
///
/// ### Arguments
///
/// * `tx_values`   - Series of values required for TxIn construction
pub fn construct_payment_tx_ins(tx_values: Vec<TxConstructor>) -> Vec<TxIn> {
    let mut tx_ins = Vec::new();

    for entry in tx_values {
        let mut new_tx_in = TxIn::new();
        new_tx_in.script_signature =
            Script::pay2pkh(entry.t_hash.clone(), entry.signatures[0], entry.pub_keys[0]);
        new_tx_in.previous_out = Some(OutPoint::new(entry.t_hash, entry.prev_n));

        tx_ins.push(new_tx_in);
    }

    tx_ins
}

/// Constructs a dual double entry tx
///
/// ### Arguments
///
/// * `tx_ins`              - Addresses to pay from
/// * `address`             - Address to send the asset to
/// * `send_asset`          - Asset to be sent as payment
/// * `receive_asset`       - Asset to receive
/// * `send_asset_drs_hash` - Hash of the block containing the DRS for the sent asset. Only applicable to data trades
/// * `druid`               - DRUID value to match with the other party
/// * `druid_participants`  - Number of DRUID values to match with
pub fn construct_dde_tx(
    tx_ins: Vec<TxIn>,
    address: String,
    send_asset: AssetInTransit,
    receive_asset: AssetInTransit,
    send_asset_drs_hash: Option<String>,
    druid: String,
    druid_participants: usize,
) -> Transaction {
    let mut tx = Transaction::new();
    let mut tx_out = TxOut::new();

    tx_out.value = Some(send_asset.asset);
    tx_out.amount = send_asset.amount;
    tx_out.script_public_key = Some(address);
    tx_out.drs_block_hash = send_asset_drs_hash;

    tx.outputs = vec![tx_out];
    tx.inputs = tx_ins;
    tx.version = 0;
    tx.druid = Some(druid);
    tx.druid_participants = Some(druid_participants);
    tx.expect_value = Some(receive_asset.asset);
    tx.expect_value_amount = Some(receive_asset.amount);

    tx
}

/*---- TESTS ----*/

#[cfg(test)]
mod tests {
    use super::*;
    use sodiumoxide::crypto::sign;

    #[test]
    // Creates a valid creation transaction
    fn should_construct_a_valid_create_tx() {
        let receiver_address = hex::encode(vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let amount = 1;
        let drs = vec![0, 8, 30, 20, 1];

        let tx = construct_create_tx(drs.clone(), receiver_address.clone(), amount);

        assert_eq!(tx.druid, None);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0].amount, amount);
        assert_eq!(tx.outputs[0].drs_block_hash, None);
        assert_eq!(tx.outputs[0].script_public_key, Some(receiver_address));
        assert_eq!(tx.outputs[0].value, Some(Asset::Data(drs)));
    }

    #[test]
    // Creates a valid payment transaction
    fn should_construct_a_valid_payment_tx() {
        let (_pk, sk) = sign::gen_keypair();
        let (pk, _sk) = sign::gen_keypair();
        let t_hash = vec![0, 0, 0];
        let signature = sign::sign_detached(&t_hash.clone(), &sk);
        let drs_block_hash = hex::encode(vec![1, 2, 3, 4, 5, 6]);
        let drs_tx_hash = hex::encode(vec![1, 2, 3, 4, 5, 6]);

        let tx_const = TxConstructor {
            t_hash: hex::encode(t_hash),
            prev_n: 0,
            b_hash: hex::encode(vec![0]),
            signatures: vec![signature],
            pub_keys: vec![pk],
        };

        let tx_ins = construct_payment_tx_ins(vec![tx_const]);
        let payment_tx = construct_payment_tx(
            tx_ins,
            hex::encode(vec![0, 0, 0, 0]),
            Some(drs_block_hash),
            Some(drs_tx_hash),
            Asset::Token(4),
            4,
        );

        assert_eq!(
            Asset::Token(4),
            payment_tx.outputs[0].clone().value.unwrap()
        );
        assert_eq!(
            payment_tx.outputs[0].clone().script_public_key,
            Some(hex::encode(vec![0, 0, 0, 0]))
        );
    }

    #[test]
    // Creates a valid UTXO set
    fn should_construct_valid_utxo_set() {
        let (pk, sk) = sign::gen_keypair();
        
        let t_hash_1 = hex::encode(vec![0,0,0]);
        let signed = sign::sign_detached(t_hash_1.as_bytes(), &sk);

        let tx_1 = TxConstructor {
            t_hash: "".to_string(),
            prev_n: 0,
            b_hash: hex::encode(vec![0]),
            signatures: vec![signed],
            pub_keys: vec![pk]
        };
        
        let tx_ins_1 = construct_payment_tx_ins(vec![tx_1]);
        let payment_tx_1 = construct_payment_tx(
            tx_ins_1,
            hex::encode(vec![0, 0, 0, 0]),
            None,
            None,
            Asset::Token(4),
            4,
        );
        let tx_1_hash = construct_tx_hash(&payment_tx_1);

        // Second tx referencing first
        let tx_2 = TxConstructor {
            t_hash: tx_1_hash.clone(),
            prev_n: 0,
            b_hash: hex::encode(vec![0]),
            signatures: vec![signed],
            pub_keys: vec![pk]
        };
        let tx_ins_2 = construct_payment_tx_ins(vec![tx_2]);
        let payment_tx_2 = construct_payment_tx(
            tx_ins_2,
            hex::encode(vec![0, 0, 0, 0]),
            None,
            None,
            Asset::Token(4),
            4,
        );
        let tx_2_hash = construct_tx_hash(&payment_tx_2);

        // BTreemap
        let mut btree = BTreeMap::new();
        btree.insert(tx_1_hash, payment_tx_1);
        btree.insert(tx_2_hash.clone(), payment_tx_2);

        let mut barc = Arc::new(Mutex::new(btree));
        construct_utxo_set(&mut barc);

        // Check that only one entry remains
        assert_eq!(barc.lock().unwrap().len(), 1);
        assert_ne!(barc.lock().unwrap().get(&tx_2_hash), None);
    }

    #[test]
    // Creates a valid DDE transaction
    fn should_construct_a_valid_dde_tx() {
        let (_pk, sk) = sign::gen_keypair();
        let (pk, _sk) = sign::gen_keypair();
        let t_hash = hex::encode(vec![0, 0, 0]);
        let drs_block_hash = hex::encode(vec![1, 2, 3, 4, 5, 6]);
        let signature = sign::sign_detached(t_hash.as_bytes(), &sk);

        let tx_const = TxConstructor {
            t_hash: hex::encode(t_hash),
            prev_n: 0,
            b_hash: hex::encode(vec![0]),
            signatures: vec![signature],
            pub_keys: vec![pk],
        };

        let tx_ins = construct_payment_tx_ins(vec![tx_const]);

        // DDE params
        let druid = hex::encode(vec![1, 2, 3, 4, 5]);
        let druid_participants = 2;

        let first_asset = Asset::Token(10);
        let first_amount = 10;
        let second_asset = Asset::Token(0);
        let second_amount = 0;

        let first_asset_t = AssetInTransit {
            asset: first_asset,
            amount: first_amount,
        };
        let second_asset_t = AssetInTransit {
            asset: second_asset,
            amount: second_amount,
        };

        // Actual DDE
        let dde = construct_dde_tx(
            tx_ins,
            hex::encode(vec![0, 0, 0, 0]),
            first_asset_t.clone(),
            second_asset_t,
            Some(drs_block_hash),
            druid.clone(),
            druid_participants.clone(),
        );

        assert_eq!(dde.druid, Some(druid.clone()));
        assert_eq!(
            dde.outputs[0].clone().value,
            Some(first_asset_t.clone().asset)
        );
        assert_eq!(dde.outputs[0].clone().amount, first_asset_t.clone().amount);
        assert_eq!(dde.druid_participants, Some(druid_participants.clone()));
    }
}
