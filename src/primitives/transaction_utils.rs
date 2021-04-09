use crate::constants::{RECEIPT_ACCEPT_VAL, TX_PREPEND};
use crate::primitives::asset::{Asset, AssetInTransit, TokenAmount};
use crate::primitives::transaction::*;
use crate::script::lang::Script;
use crate::sha3::Digest;

use bincode::serialize;
use bytes::Bytes;
use sha3::Sha3_256;
use sodiumoxide::crypto::sign;
use sodiumoxide::crypto::sign::{PublicKey, SecretKey, Signature};
use std::collections::BTreeMap;

/// Builds an address from a public key
///
/// ### Arguments
///
/// * `pub_key` - A public key to build an address from
pub fn construct_address(pub_key: PublicKey) -> String {
    let first_pubkey_bytes = serialize(&pub_key).unwrap();
    let mut first_hash = Sha3_256::digest(&first_pubkey_bytes).to_vec();

    // TODO: Add RIPEMD

    first_hash.truncate(16);

    hex::encode(first_hash)
}

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

/// Get all the OutPoint and TxOut from the (hash,transactions)
///
/// ### Arguments
///
/// * `txs` - The entries to to provide an update for.
pub fn get_tx_out_with_out_point<'a>(
    txs: impl Iterator<Item = (&'a String, &'a Transaction)>,
) -> impl Iterator<Item = (OutPoint, &'a TxOut)> {
    txs.map(|(hash, tx)| (hash, tx.outputs.iter()))
        .flat_map(|(hash, outs)| outs.enumerate().map(move |(idx, txo)| (hash, idx, txo)))
        .map(|(hash, idx, txo)| (OutPoint::new(hash.clone(), idx as i32), txo))
}

/// Get all the OutPoint and TxOut from the (hash,transactions)
///
/// ### Arguments
///
/// * `txs` - The entries to to provide an update for.
pub fn get_tx_out_with_out_point_cloned<'a>(
    txs: impl Iterator<Item = (&'a String, &'a Transaction)> + 'a,
) -> impl Iterator<Item = (OutPoint, TxOut)> + 'a {
    get_tx_out_with_out_point(txs).map(|(o, txo)| (o, txo.clone()))
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

/// Reconstructs a signature type from an input vector
///
/// ### Arguments
///
/// * `input`   - Input vector
pub fn reconstruct_signature(input: Vec<u8>) -> Signature {
    Signature::from_slice(&input).unwrap()
}

/// Constructs a coinbase transaction
/// TODO: Adding block number to coinbase construction non-ideal. Consider moving to Compute
/// construction or mining later
///
/// ### Arguments
///
/// * `b_num`       - Block number for the current coinbase block
/// * `amount`      - Amount of tokens allowed in coinbase
/// * `address`     - Address to send the coinbase amount to
pub fn construct_coinbase_tx(b_num: u64, amount: TokenAmount, address: String) -> Transaction {
    let mut tx = Transaction::new();
    let mut tx_in = TxIn::new();
    tx_in.script_signature = Script::new_for_coinbase(b_num);

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
/// * `drs_tx_hash`         - Hash of the transaction containing the original DRS. Only for data trades
/// * `asset`               - Asset to send
/// * `locktime`            - Block height below which the payment is restricted. "0" means no locktime
/// * `amount`              - Number of tokens to send
pub fn construct_payment_tx(
    tx_ins: Vec<TxIn>,
    receiver_address: String,
    drs_block_hash: Option<String>,
    drs_tx_hash: Option<String>,
    asset: Asset,
    locktime: u64,
    amount: TokenAmount,
) -> Transaction {
    let tx_out = TxOut {
        value: Some(asset),
        amount,
        locktime,
        script_public_key: Some(receiver_address),
        drs_block_hash,
        drs_tx_hash,
    };

    Transaction {
        outputs: vec![tx_out],
        inputs: tx_ins,
        version: 0,
        ..Default::default()
    }
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

/// Constructs the "send" half of a receipt-based payment
/// transaction
///
/// ### Arguments
///
/// * `tx_ins`              - Address/es to pay from
/// * `receiver_address`    - Address to send to
/// * `asset`               - Asset to send
/// * `locktime`            - Block height below which the payment is restricted. "0" means no locktime
/// * `druid`               - The matching DRUID value
/// * `amount`              - Number of tokens to send
pub fn construct_rb_payments_send_tx(
    tx_ins: Vec<TxIn>,
    tx_outs: Vec<TxOut>,
    druid: String,
) -> Transaction {
    let mut tx = construct_payments_tx(tx_ins, tx_outs);
    tx.druid = Some(druid);
    tx.druid_participants = Some(2);
    tx
}

/// Constructs the "receive" half of a receipt-based payment
/// transaction
///
/// ### Arguments
///
/// * `sender_address`      - Address of sender
/// * `asset`               - Asset expected
/// * `amount`              - Number of tokens expected
/// * `druid`               - The matching DRUID value
/// * `locktime`            - Block height below which the payment receipt is restricted. "0" means no locktime
/// * `sk`                  - Secret key to sign the receipt-value with
pub fn construct_rb_receive_payment_tx(
    sender_address: String,
    asset: Asset,
    amount: TokenAmount,
    druid: String,
    locktime: u64,
    sk: SecretKey,
) -> Transaction {
    let signed_receipt = sign::sign_detached(RECEIPT_ACCEPT_VAL.as_bytes(), &sk);
    let tx_in = TxIn::new();
    let signed_receipt_asset = Asset::Data(signed_receipt.0.to_vec());

    let mut tx = construct_payment_tx(
        vec![tx_in],
        sender_address,
        None,
        None,
        signed_receipt_asset,
        locktime,
        TokenAmount(0),
    );

    tx.druid = Some(druid);
    tx.druid_participants = Some(2);
    tx.expect_value = Some(asset);
    tx.expect_value_amount = Some(amount);

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
        let outpoint = OutPoint::new(entry.t_hash, entry.prev_n);

        new_tx_in.previous_out = Some(outpoint.clone());
        let signable_hash = hex::encode(serialize(&outpoint).unwrap());

        new_tx_in.script_signature =
            Script::pay2pkh(signable_hash, entry.signatures[0], entry.pub_keys[0]);

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
            0,
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
            0,
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
            0,
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
    // Creates a valid receipt signature
    fn should_construct_a_valid_receipt_signature() {
        let (_, sk) = sign::gen_keypair();
        let signed_receipt = sign::sign_detached(RECEIPT_ACCEPT_VAL.as_bytes(), &sk);
        let sig_vec = signed_receipt.0.to_vec();

        let recon = reconstruct_signature(sig_vec);
        assert_eq!(recon, signed_receipt);
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

    #[test]
    // Creates a valid receipt based tx pair
    fn should_construct_a_valid_receipt_tx_pair() {
        // Arrange
        //
        let amount = TokenAmount(33);
        let druid = "VALUE".to_owned();
        let receiver_addr = "00000".to_owned();
        let sender_address_excess = "11112".to_owned();
        let sender_address = "11111".to_owned();
        let asset_transfered = Asset::Data(RECEIPT_ACCEPT_VAL.as_bytes().to_vec());
        let (_sender_pk, sender_sk) = sign::gen_keypair();

        // Act
        //
        let send_tx = {
            let tx_ins = {
                // constructors with enough money for amount and excess, caller responsibility.
                let tx_ins_constructor = vec![];
                construct_payment_tx_ins(tx_ins_constructor)
            };
            let tx_outs = {
                // Tx outs with the one at relevant address with the relevant amount
                let excess_tx_out =
                    TxOut::new_amount(sender_address_excess, TokenAmount(22));
                let druid_tx_out = TxOut::new_amount(receiver_addr, amount);
                vec![druid_tx_out, excess_tx_out]
            };

            construct_rb_payments_send_tx(tx_ins, tx_outs, druid.clone())
        };

        let recv_tx = {
            // create the sender that match the receiver.
            construct_rb_receive_payment_tx(
                sender_address,
                asset_transfered,
                TokenAmount(33),
                druid,
                0,
                sender_sk,
            )
        };

        // Assert
        assert_eq!(send_tx.druid, recv_tx.druid);
        assert_eq!(send_tx.druid_participants, recv_tx.druid_participants);
        assert_eq!(send_tx.druid_participants, Some(2));
        assert_eq!(Some(send_tx.outputs[0].amount), recv_tx.expect_value_amount);
    }
}
