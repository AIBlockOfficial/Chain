use crate::constants::{RECEIPT_ACCEPT_VAL, TX_PREPEND};
use crate::primitives::asset::{Asset, DataAsset, TokenAmount};
use crate::primitives::druid::{DdeValues, DruidExpectation};
use crate::primitives::transaction::*;
use crate::script::lang::Script;
use crate::sha3::Digest;

use bincode::serialize;
use bytes::Bytes;
use sha3::Sha3_256;
use sodiumoxide::crypto::sign::{PublicKey, Signature};
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

    let tx_out = TxOut {
        value: Asset::Token(amount),
        script_public_key: Some(address),
        ..Default::default()
    };

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
pub fn construct_create_tx(drs: Vec<u8>, receiver_address: String, amount: usize) -> Transaction {
    let mut tx = Transaction::new();
    let tx_out = TxOut {
        value: Asset::Data(DataAsset { data: drs, amount }),
        script_public_key: Some(receiver_address),
        ..Default::default()
    };

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
        value: asset,
        locktime,
        script_public_key: Some(receiver_address),
        drs_block_hash,
        drs_tx_hash,
    };

    construct_tx_core(tx_ins, vec![tx_out])
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
pub fn construct_tx_core(tx_ins: Vec<TxIn>, tx_outs: Vec<TxOut>) -> Transaction {
    Transaction {
        outputs: tx_outs,
        inputs: tx_ins,
        ..Default::default()
    }
}

/// Constructs the expectations for a receipt-based payment
///
/// ### Arguments
///
/// * `from_address`    - Address tokens are being sent from
/// * `to_address`      - Address receiving tokens
/// * `amount`          - Number of tokens to send
pub fn construct_rb_payment_expects(
    from_address: String,
    to_address: String,
    amount: TokenAmount,
) -> Vec<DruidExpectation> {
    let send_expect = DruidExpectation {
        from: from_address,
        to: to_address,
        asset: Asset::Token(amount),
    };

    let receive_expect = DruidExpectation {
        from: to_address,
        to: from_address,
        asset: Asset::Receipt(RECEIPT_ACCEPT_VAL.to_string()),
    };

    vec![send_expect, receive_expect]
}

/// Constructs the expectations for a simple, 2 participant DDE trade
///
/// ### Arguments
///
/// * `from`    - The address and asset of the "from" party
/// * `to`      - The address and asset of the "to" party
pub fn construct_dde_single_trade_expects(
    from: (String, Asset),
    to: (String, Asset),
) -> Vec<DruidExpectation> {
    let send_expect = DruidExpectation {
        from: from.0,
        to: to.0,
        asset: from.1,
    };

    let receive_expect = DruidExpectation {
        from: to.0,
        to: from.0,
        asset: to.1,
    };

    vec![send_expect, receive_expect]
}

/// Constructs a core receipt-based payment transaction
fn construct_rb_tx_core(
    from_address: String,
    to_address: String,
    amount: TokenAmount,
    tx_ins: Vec<TxIn>,
    out: TxOut,
    druid: String,
) -> Transaction {
    let expectations = construct_rb_payment_expects(from_address, to_address, amount);

    let mut tx = construct_tx_core(tx_ins, vec![out]);
    tx.druid_info = Some(DdeValues {
        druid,
        participants: 2,
        expectations,
    });

    tx
}

/// Constructs the "send" half of a receipt-based payment
/// transaction
///
/// ### Arguments
///
/// * `tx_ins`              - Inputs to the payment
/// * `own_address`         - Own address to receive receipt to
/// * `receiver_address`    - Own address to receive receipt to
/// * `amount`              - Amount of token to send
/// * `druid`               - DRUID of the transaction
/// * `locktime`            - Block height to lock the current transaction to
pub fn construct_rb_payments_send_tx(
    tx_ins: Vec<TxIn>,
    own_address: String,
    receiver_address: String,
    amount: TokenAmount,
    druid: String,
    locktime: u64,
) -> Transaction {
    let out = TxOut {
        value: Asset::Token(amount),
        locktime,
        script_public_key: Some(receiver_address),
        drs_block_hash: None,
        drs_tx_hash: None,
    };

    construct_rb_tx_core(own_address, receiver_address, amount, tx_ins, out, druid)
}

/// Constructs the "receive" half of a receipt-based payment
/// transaction
///
/// ### Arguments
///
/// * `tx_ins`              - Inputs to receipt data asset
/// * `sender_address`      - Address of sender
/// * `own_address`         - Address of this receiver
/// * `amount`              - Number of tokens expected
/// * `druid`               - The matching DRUID value
/// * `locktime`            - Block height below which the payment receipt is restricted. "0" means no locktime
pub fn construct_rb_receive_payment_tx(
    tx_ins: Vec<TxIn>,
    sender_address: String,
    own_address: String,
    amount: TokenAmount,
    druid: String,
    locktime: u64,
) -> Transaction {
    let out = TxOut {
        value: Asset::Receipt(RECEIPT_ACCEPT_VAL.to_string()),
        locktime,
        script_public_key: Some(sender_address),
        drs_block_hash: None,
        drs_tx_hash: None,
    };

    construct_rb_tx_core(sender_address, own_address, amount, tx_ins, out, druid)
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
/// * `druid`                           - DRUID value to match with the other party
/// * `tx_ins`                          - Addresses to pay from
/// * `send_asset_drs_hash`             - Hash of the block containing the DRS for the sent asset. Only applicable to data trades
/// * `participants`                    - Participants in trade
/// * `(send_address, receive_address)` - Send and receive addresses as a tuple
/// * `(send_asset, receive_asset)`     - Send and receive assets as a tuple
pub fn construct_dde_tx(
    druid: String,
    tx_ins: Vec<TxIn>,
    tx_outs: Vec<TxOut>,
    participants: usize,
    send_asset_drs_hash: Option<String>,
    expectations: Vec<DruidExpectation>,
) -> Transaction {
    let mut tx = construct_tx_core(tx_ins, tx_outs);
    tx.druid_info = Some(DdeValues {
        druid,
        participants,
        expectations,
    });

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

        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.druid_info, None);
        assert_eq!(tx.outputs[0].drs_block_hash, None);
        assert_eq!(tx.outputs[0].script_public_key, Some(receiver_address));
        assert_eq!(
            tx.outputs[0].value,
            Asset::Data(DataAsset { data: drs, amount })
        );
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
            payment_tx.outputs[0].clone().value
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

        let from = "0000".to_owned();
        let to = "1111".to_owned();
        let data = Asset::Data(DataAsset {
            data: vec![0, 12, 3, 5, 6],
            amount: 1,
        });
        let cost = TokenAmount(20);

        let tx_const = TxConstructor {
            t_hash: hex::encode(t_hash),
            prev_n: 0,
            signatures: vec![signature],
            pub_keys: vec![pk],
        };

        let tx_ins = construct_payment_tx_ins(vec![tx_const]);
        let tx_outs = vec![TxOut {
            value: data.clone(),
            drs_block_hash: Some(drs_block_hash),
            drs_tx_hash: Some(t_hash),
            script_public_key: Some(to),
            ..Default::default()
        }];

        // DDE params
        let druid = hex::encode(vec![1, 2, 3, 4, 5]);
        let participants = 2;
        let expects = construct_dde_single_trade_expects((from, data), (to, Asset::Token(cost)));

        // Actual DDE
        let dde = construct_dde_tx(
            druid.clone(),
            tx_ins,
            tx_outs,
            participants,
            Some(drs_block_hash),
            expects,
        );

        assert_eq!(dde.druid_info.unwrap().druid, druid);
        assert_eq!(dde.outputs[0].clone().value, data);
        assert_eq!(dde.druid_info.unwrap().participants, participants);
    }

    #[test]
    // Creates a valid receipt based tx pair
    fn should_construct_a_valid_receipt_tx_pair() {
        // Arrange
        //
        let amount = TokenAmount(33);
        let payment = TokenAmount(11);
        let druid = "VALUE".to_owned();
        let receiver_addr = "00000".to_owned();
        let sender_address_excess = "11112".to_owned();
        let sender_address = "11111".to_owned();
        let (sender_pk, sender_sk) = sign::gen_keypair();

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
                let excess_tx_out = TxOut::new_amount(sender_address_excess, amount - payment);
                let druid_tx_out = TxOut::new_amount(receiver_addr, payment);
                vec![druid_tx_out, excess_tx_out]
            };

            construct_tx_core(tx_ins, tx_outs)
        };

        let recv_tx = {
            let tx_ins = {
                // constructors with enough money for amount and excess, caller responsibility.
                let tx_ins_constructor = vec![];
                construct_payment_tx_ins(tx_ins_constructor)
            };
            // create the sender that match the receiver.
            construct_rb_receive_payment_tx(
                tx_ins,
                sender_address,
                receiver_addr,
                payment,
                druid,
                0,
            )
        };

        // Assert
        assert_eq!(
            send_tx.druid_info.clone().unwrap().druid,
            recv_tx.druid_info.clone().unwrap().druid
        );
        assert_eq!(
            send_tx.druid_info.clone().unwrap().participants,
            recv_tx.druid_info.clone().unwrap().participants
        );
        assert_eq!(send_tx.druid_info.unwrap().participants, 2);
    }
}
