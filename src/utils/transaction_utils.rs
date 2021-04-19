use crate::constants::TX_PREPEND;
use crate::primitives::asset::{Asset, DataAsset, TokenAmount};
use crate::primitives::druid::{DdeValues, DruidExpectation};
use crate::primitives::transaction::*;
use crate::script::lang::Script;
use crate::sha3::Digest;

use bincode::serialize;
use bytes::Bytes;
use sha3::Sha3_256;
use sodiumoxide::crypto::sign::PublicKey;
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
pub fn construct_create_tx(drs: Vec<u8>, receiver_address: String, amount: u64) -> Transaction {
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

/// Constructs a receipt data asset for use in accepting payments
/// TODO: On compute, figure out a way to ease flow of receipts without issue for users
///
/// ### Arguments
///
/// * `receiver_address`    - Address to receive the receipt assets
/// * `amount`              - Amount of receipt assets to create
pub fn construct_receipt_create_tx(receiver_address: String, amount: u64) -> Transaction {
    let mut tx = Transaction::new();
    let tx_out = TxOut {
        value: Asset::Receipt(amount),
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
pub fn construct_payment_tx(
    tx_ins: Vec<TxIn>,
    receiver_address: String,
    drs_block_hash: Option<String>,
    drs_tx_hash: Option<String>,
    asset: Asset,
    locktime: u64,
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

/// Constructs a core receipt-based payment transaction
///
/// ### Arguments
///
/// * `from_address`    - Address receiving asset from
/// * `to_address`      - Address sending asset to
/// * `asset`           - Asset to send
/// * `tx_ins`          - TxIns for outgoing transaction
/// * `out`             - The TxOut for this send
/// * `druid`           - DRUID to match on
pub fn construct_rb_tx_core(
    tx_ins: Vec<TxIn>,
    tx_outs: Vec<TxOut>,
    druid: String,
    druid_expectation: Vec<DruidExpectation>,
) -> Transaction {
    let mut tx = construct_tx_core(tx_ins, tx_outs);
    tx.druid_info = Some(DdeValues {
        druid,
        participants: 2,
        expectations: druid_expectation,
    });

    tx
}

/// Constructs the "send" half of a receipt-based payment
/// transaction
///
/// ### Arguments
///
/// * `receiver_address`    - Own address to receive receipt to
/// * `amount`              - Amount of token to send
/// * `locktime`            - Block height to lock the current transaction to
pub fn construct_rb_payments_send_tx(
    tx_ins: Vec<TxIn>,
    receiver_address: String,
    amount: TokenAmount,
    locktime: u64,
    druid: String,
    expectation: Vec<DruidExpectation>,
) -> Transaction {
    let out = TxOut {
        value: Asset::Token(amount),
        locktime,
        script_public_key: Some(receiver_address),
        drs_block_hash: None,
        drs_tx_hash: None,
    };

    construct_rb_tx_core(tx_ins, vec![out], druid, expectation)
}

/// Constructs the "receive" half of a receipt-based payment
/// transaction
///
/// ### Arguments
///
/// * `tx_ins`              - Inputs to receipt data asset
/// * `sender_address`      - Address of sender
/// * `sender_send_addr`    - Input hash used by sender to send tokens
/// * `own_address`         - Own address to receive tokens to
/// * `amount`              - Number of tokens expected
/// * `locktime`            - Block height below which the payment receipt is restricted. "0" means no locktime
/// * `druid`               - The matching DRUID value
pub fn construct_rb_receive_payment_tx(
    tx_ins: Vec<TxIn>,
    sender_address: String,
    locktime: u64,
    druid: String,
    expectation: Vec<DruidExpectation>,
) -> Transaction {
    let out = TxOut {
        value: Asset::Receipt(1),
        locktime,
        script_public_key: Some(sender_address),
        drs_block_hash: None, // this will need to change
        drs_tx_hash: None,    // this will need to change
    };

    construct_rb_tx_core(tx_ins, vec![out], druid, expectation)
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
        );

        assert_eq!(Asset::Token(token_amount), payment_tx.outputs[0].value);
        assert_eq!(
            payment_tx.outputs[0].script_public_key,
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
        let tx_outs = vec![TxOut::new_amount(
            hex::encode(vec![0, 0, 0, 0]),
            token_amount,
        )];
        let payment_tx_2 = construct_tx_core(tx_ins_2, tx_outs);

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
        let signature = sign::sign_detached(t_hash.as_bytes(), &sk);

        let to_asset = "2222".to_owned();
        let data = Asset::Data(DataAsset {
            data: vec![0, 12, 3, 5, 6],
            amount: 1,
        });

        let tx_const = TxConstructor {
            t_hash: hex::encode(&t_hash),
            prev_n: 0,
            signatures: vec![signature],
            pub_keys: vec![pk],
        };

        let tx_ins = construct_payment_tx_ins(vec![tx_const]);
        let tx_outs = vec![TxOut {
            value: data.clone(),
            drs_tx_hash: Some(t_hash),
            script_public_key: Some(to_asset.clone()),
            ..Default::default()
        }];

        let from_addr = hex::encode(serialize(&tx_ins).unwrap());

        // DDE params
        let druid = hex::encode(vec![1, 2, 3, 4, 5]);
        let participants = 2;
        let expects = vec![DruidExpectation {
            from: from_addr.clone(),
            to: to_asset,
            asset: data.clone(),
        }];

        // Actual DDE
        let dde = construct_dde_tx(druid.clone(), tx_ins, tx_outs, participants, expects);

        assert_eq!(dde.druid_info.clone().unwrap().druid, druid);
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

        let tx_input = construct_payment_tx_ins(vec![]);
        let from_addr = hex::encode(Sha3_256::digest(&serialize(&tx_input).unwrap()).to_vec());

        let alice_addr = "1111".to_owned();
        let bob_addr = "00000".to_owned();

        let sender_address_excess = "11112".to_owned();

        // Act
        //
        let send_tx = {
            let tx_ins = {
                // constructors with enough money for amount and excess, caller responsibility.
                construct_payment_tx_ins(vec![])
            };
            let excess_tx_out = TxOut::new_amount(sender_address_excess, amount - payment);

            let expectation = DruidExpectation {
                from: from_addr.clone(),
                to: alice_addr.clone(),
                asset: Asset::Receipt(1),
            };

            let mut tx = construct_rb_payments_send_tx(
                tx_ins,
                bob_addr.clone(),
                payment.clone(),
                0,
                druid.clone(),
                vec![expectation],
            );

            tx.outputs.push(excess_tx_out);

            tx
        };

        let recv_tx = {
            let tx_ins = {
                // constructors with enough money for amount and excess, caller responsibility.
                let tx_ins_constructor = vec![];
                construct_payment_tx_ins(tx_ins_constructor)
            };
            let expectation = DruidExpectation {
                from: from_addr,
                to: bob_addr.clone(),
                asset: Asset::Token(payment),
            };

            // create the sender that match the receiver.
            construct_rb_receive_payment_tx(tx_ins, alice_addr, 0, druid.clone(), vec![expectation])
        };

        // Assert
        assert_eq!(
            send_tx
                .druid_info
                .as_ref()
                .map(|v| (&v.druid, v.participants)),
            Some((&druid, 2))
        );
        assert_eq!(
            recv_tx
                .druid_info
                .as_ref()
                .map(|v| (&v.druid, v.participants)),
            Some((&druid, 2))
        );
    }
}
