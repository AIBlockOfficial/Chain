use crate::constants::TX_PREPEND;
use crate::primitives::asset::{Asset, AssetInTransit, TokenAmount};
use crate::primitives::transaction::*;
use crate::script::lang::Script;
use crate::sha3::Digest;

use bincode::serialize;
use bytes::Bytes;
use sha3::Sha3_256;
use std::collections::BTreeMap;

/// Get all the hash to remove from UTXO set for the utxo_entries
///
/// ### Arguments
///
/// * `utxo_entries` - The entries to to provide an update for.
pub fn get_inputs_previous_out_point<'a>(
    utxo_entries: impl Iterator<Item = &'a Transaction>,
) -> impl Iterator<Item = &'a OutPoint> {
    utxo_entries
        .flat_map(|val| val.inputs.iter())
        .map(|input| input.previous_out.as_ref().unwrap())
}

/// Get all the OutPoint and Transaction from the (hash,transactions)
///
/// ### Arguments
///
/// * `txs` - The entries to to provide an update for.
pub fn get_tx_with_out_point<'a>(
    txs: impl Iterator<Item = (&'a String, &'a Transaction)>,
) -> impl Iterator<Item = (OutPoint, &'a Transaction)> {
    txs.map(|(hash, tx)| (hash, tx, &tx.outputs))
        .flat_map(|(hash, tx, outs)| outs.iter().enumerate().map(move |(idx, _)| (hash, idx, tx)))
        .map(|(hash, idx, tx)| (OutPoint::new(hash.clone(), idx as i32), tx))
}

/// Get all the OutPoint and Transaction from the (hash,transactions)
///
/// ### Arguments
///
/// * `txs` - The entries to to provide an update for.
pub fn get_tx_with_out_point_cloned<'a>(
    txs: impl Iterator<Item = (&'a String, &'a Transaction)> + 'a,
) -> impl Iterator<Item = (OutPoint, Transaction)> + 'a {
    get_tx_with_out_point(txs).map(|(h, tx)| (h, tx.clone()))
}

/// Constructs the UTXO set for the current state of the blockchain
///
/// ### Arguments
///
/// * `current_utxo` - The current UTXO set to be updated.
pub fn update_utxo_set(current_utxo: &mut BTreeMap<OutPoint, Transaction>) {
    let value_set: Vec<OutPoint> = get_inputs_previous_out_point(current_utxo.values())
        .cloned()
        .collect();

    value_set.iter().for_each(move |t_hash| {
        current_utxo.remove(t_hash);
    });
}

/// Constructs a coinbase transaction
///
/// ### Arguments
///
/// * `amount`      - Amount of tokens allowed in coinbase
/// * `block_time`  - Block time to assign to script
/// * `address`     - Address to send the coinbase amount to
pub fn construct_coinbase_tx(amount: TokenAmount, block_time: u32, address: String) -> Transaction {
    let mut tx = Transaction::new();
    let mut tx_in = TxIn::new();
    tx_in.script_signature = Script::new_for_coinbase(block_time);

    let mut tx_out = TxOut::new();
    tx_out.amount = amount;
    tx_out.value = Some(Asset::Token(amount));
    tx_out.script_public_key = Some(address);

    tx.inputs.push(tx_in);
    tx.outputs.push(tx_out);

    tx
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

    hash.insert(0, TX_PREPEND);
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
pub fn construct_create_tx(
    drs: Vec<u8>,
    receiver_address: String,
    amount: TokenAmount,
) -> Transaction {
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
    amount: TokenAmount,
) -> Transaction {
    let tx_out = TxOut {
        value: Some(asset),
        amount,
        script_public_key: Some(receiver_address),
        drs_block_hash,
        drs_tx_hash,
    };

    construct_payments_tx(tx_ins, vec![tx_out])
}

/// Constructs a transaction to pay a receivers
/// If TxIn collection does not add up to the exact amount to pay,
/// payer will always need to provide a return payment in tx_outs,
/// otherwise the excess will be burnt and unusable.
///
/// TODO: Check whether the `amount` is valid in the TxIns
/// TODO: Call this a charity tx or something, as a payment is an exchange of goods
///
/// ### Arguments
///
/// * `tx_ins`     - Address/es to pay from
/// * `tx_outs`    - Address/es to send to
pub fn construct_payments_tx(tx_ins: Vec<TxIn>, tx_outs: Vec<TxOut>) -> Transaction {
    Transaction {
        outputs: tx_outs,
        inputs: tx_ins,
        version: 0,
        ..Default::default()
    }
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
        let amount = TokenAmount(1);
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
        let signature = sign::sign_detached(&t_hash, &sk);
        let drs_block_hash = hex::encode(vec![1, 2, 3, 4, 5, 6]);
        let drs_tx_hash = hex::encode(vec![1, 2, 3, 4, 5, 6]);

        let tx_const = TxConstructor {
            t_hash: hex::encode(t_hash),
            prev_n: 0,
            signatures: vec![signature],
            pub_keys: vec![pk],
        };

        let token_amount = TokenAmount(400000);
        let tx_ins = construct_payment_tx_ins(vec![tx_const]);
        let payment_tx = construct_payment_tx(
            tx_ins,
            hex::encode(vec![0, 0, 0, 0]),
            Some(drs_block_hash),
            Some(drs_tx_hash),
            Asset::Token(token_amount),
            token_amount,
        );

        assert_eq!(
            Asset::Token(token_amount),
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

        let t_hash_1 = hex::encode(vec![0, 0, 0]);
        let signed = sign::sign_detached(t_hash_1.as_bytes(), &sk);

        let tx_1 = TxConstructor {
            t_hash: "".to_string(),
            prev_n: 0,
            signatures: vec![signed],
            pub_keys: vec![pk],
        };

        let token_amount = TokenAmount(400000);
        let tx_ins_1 = construct_payment_tx_ins(vec![tx_1]);
        let payment_tx_1 = construct_payment_tx(
            tx_ins_1,
            hex::encode(vec![0, 0, 0, 0]),
            None,
            None,
            Asset::Token(token_amount),
            token_amount,
        );
        let tx_1_hash = construct_tx_hash(&payment_tx_1);
        let tx_1_out_p = OutPoint::new(tx_1_hash.clone(), 0);

        // Second tx referencing first
        let tx_2 = TxConstructor {
            t_hash: tx_1_hash,
            prev_n: 0,
            signatures: vec![signed],
            pub_keys: vec![pk],
        };
        let tx_ins_2 = construct_payment_tx_ins(vec![tx_2]);
        let payment_tx_2 = construct_payment_tx(
            tx_ins_2,
            hex::encode(vec![0, 0, 0, 0]),
            None,
            None,
            Asset::Token(token_amount),
            token_amount,
        );
        let tx_2_hash = construct_tx_hash(&payment_tx_2);
        let tx_2_out_p = OutPoint::new(tx_2_hash, 0);

        // BTreemap
        let mut btree = BTreeMap::new();
        btree.insert(tx_1_out_p, payment_tx_1);
        btree.insert(tx_2_out_p.clone(), payment_tx_2);

        update_utxo_set(&mut btree);

        // Check that only one entry remains
        assert_eq!(btree.len(), 1);
        assert_ne!(btree.get(&tx_2_out_p), None);
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
            signatures: vec![signature],
            pub_keys: vec![pk],
        };

        let tx_ins = construct_payment_tx_ins(vec![tx_const]);

        // DDE params
        let druid = hex::encode(vec![1, 2, 3, 4, 5]);
        let druid_participants = 2;

        let first_token_amount = TokenAmount(1000000);
        let second_token_amount = TokenAmount(0);

        let first_asset = Asset::Token(first_token_amount);
        let second_asset = Asset::Token(second_token_amount);

        let first_asset_t = AssetInTransit {
            asset: first_asset,
            amount: first_token_amount,
        };
        let second_asset_t = AssetInTransit {
            asset: second_asset,
            amount: second_token_amount,
        };

        // Actual DDE
        let dde = construct_dde_tx(
            tx_ins,
            hex::encode(vec![0, 0, 0, 0]),
            first_asset_t.clone(),
            second_asset_t,
            Some(drs_block_hash),
            druid.clone(),
            druid_participants,
        );

        assert_eq!(dde.druid, Some(druid));
        assert_eq!(
            dde.outputs[0].clone().value,
            Some(first_asset_t.clone().asset)
        );
        assert_eq!(dde.outputs[0].clone().amount, first_asset_t.amount);
        assert_eq!(dde.druid_participants, Some(druid_participants));
    }
}
