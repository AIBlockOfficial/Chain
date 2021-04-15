use crate::constants::XXHASH_SEED;
use crate::primitives::asset::Asset;
use crate::primitives::transaction::Transaction;
use bincode::serialize;
use std::collections::BTreeSet;
use xxhash_rust::xxh64::xxh64;

/// Verifies that all DDE transaction expectations are met for DRUID-matching transactions
///
/// ### Arguments
///
/// * `transactions`    - Transactions to verify
pub fn druid_expectations_are_met(druid: String, transactions: &[Transaction]) -> bool {
    let mut expects = BTreeSet::new();
    let mut in_outs = BTreeSet::new();

    // Fill expectations
    for tx in transactions {
        if let Some(druid_info) = &tx.druid_info {
            // Ensure match with passed DRUID
            if druid_info.druid == druid {
                for expect in druid_info.expectations.clone() {
                    let expect_hash =
                        construct_expectation_hash(expect.from, expect.to, expect.asset);

                    expects.insert(expect_hash);
                }

                // Input-output set
                update_set_on_in_out(&mut in_outs, tx);
            } else {
                return false;
            }
        }
    }

    // Check expectations
    for exp in &expects.clone() {
        if in_outs.contains(exp) {
            expects.remove(exp);
        }
    }

    expects.is_empty()
}

/// Constructs a hash from an expectation to match
///
/// ### Arguments
///
/// * `from`    - From address hash
/// * `to`      - To address
/// * `asset`   - Asset to send
fn construct_expectation_hash(from: String, to: String, asset: Asset) -> String {
    let out_value = vec![to, hex::encode(&serialize(&asset).unwrap())];
    let out_hash = hex::encode(serialize(&out_value).unwrap());

    format!(
        "{:x}",
        xxh64(&serialize(&vec![from, out_hash]).unwrap(), XXHASH_SEED)
    )
}

/// Updates the input-output set for DRUID expectations
///
/// ### Arguments
///
/// * `in_out`  - Input-output set to update
/// * `tx`      - Current transaction
fn update_set_on_in_out(in_outs: &mut BTreeSet<String>, tx: &Transaction) {
    let input_hash = hex::encode(serialize(&tx.inputs).unwrap());

    for out in &tx.outputs {
        if let Some(to_addr) = out.script_public_key.clone() {
            let final_hash =
                construct_expectation_hash(input_hash.clone(), to_addr, out.value.clone());

            in_outs.insert(final_hash);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::asset::{Asset, DataAsset, TokenAmount};
    use crate::primitives::druid::{DdeValues, DruidExpectation};
    use crate::primitives::transaction::*;
    use crate::primitives::transaction_utils::*;

    /// Util function to create valid DDE asset tx's
    fn create_dde_txs() -> Vec<Transaction> {
        let druid = "VALUE".to_owned();
        let from_addr = hex::encode(serialize(&vec![TxIn::new()]).unwrap());

        // Alice
        let amount = TokenAmount(10);
        let alice_addr = "3333".to_owned();
        let alice_asset = Asset::Token(amount);

        // Bob
        let bob_asset = Asset::Data(DataAsset {
            data: "453094573049875".as_bytes().to_vec(),
            amount: 1,
        });
        let bob_addr = "22222".to_owned();

        // TxOuts
        let token_tx_out = TxOut {
            value: alice_asset.clone(),
            script_public_key: Some(bob_addr.clone()),
            ..Default::default()
        };

        let data_tx_out = TxOut {
            value: bob_asset.clone(),
            script_public_key: Some(alice_addr.clone()),
            ..Default::default()
        };

        // Expectations (from addresses the same due to empty TxIn)
        let expects = vec![
            DruidExpectation {
                from: from_addr.clone(),
                to: bob_addr,
                asset: alice_asset,
            },
            DruidExpectation {
                from: from_addr,
                to: alice_addr,
                asset: bob_asset,
            },
        ];

        // Txs
        let alice_tx = construct_dde_tx(
            druid.clone(),
            vec![TxIn::new()],
            vec![token_tx_out],
            2,
            None,
            expects.clone(),
        );

        let bob_tx = construct_dde_tx(
            druid,
            vec![TxIn::new()],
            vec![data_tx_out],
            2,
            Some("".to_string()),
            expects,
        );

        vec![alice_tx, bob_tx]
    }

    /// Util function to create valid receipt-based payment tx's
    fn create_rb_payment_txs() -> (Transaction, Transaction) {
        // Arrange
        //
        let amount = TokenAmount(33);
        let payment = TokenAmount(11);
        let druid = "VALUE".to_owned();

        let tx_input = construct_payment_tx_ins(vec![]);
        let from_addr = hex::encode(serialize(&tx_input).unwrap());

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

            let mut tx = construct_rb_payments_send_tx(
                tx_ins,
                bob_addr.clone(),
                from_addr.clone(),
                alice_addr.clone(),
                payment.clone(),
                0,
                druid.clone(),
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
            // create the sender that match the receiver.
            construct_rb_receive_payment_tx(
                tx_ins, alice_addr, from_addr, bob_addr, payment, 0, druid,
            )
        };

        (send_tx, recv_tx)
    }

    #[test]
    /// Checks that matching DDE transactions are verified as such by DDE verifier
    fn should_pass_matching_dde_tx_valid() {
        let txs = create_dde_txs();
        assert!(druid_expectations_are_met("VALUE".to_owned(), &txs));
    }

    #[test]
    /// Checks that DDE transactions with non-matching expects fail
    fn should_fail_dde_tx_value_expect_mismatch() {
        let mut txs = create_dde_txs();
        let mut change_tx = txs.pop().unwrap();
        let orig_tx = txs[0].clone();

        let druid_info = change_tx.druid_info.clone();
        let mut expects = druid_info.unwrap().expectations;
        expects[0].to = "60764505679457".to_string();

        // New druid info
        let nm_druid_info = DdeValues {
            druid: "VALUE".to_owned(),
            participants: 2,
            expectations: expects,
        };
        change_tx.druid_info = Some(nm_druid_info);

        assert_eq!(
            druid_expectations_are_met("VALUE".to_owned(), &vec![orig_tx, change_tx]),
            false
        );
    }

    #[test]
    /// Checks that matching receipt-based payments are verified as such by the DDE verifier
    fn should_pass_matching_rb_payment_valid() {
        let (send_tx, recv_tx) = create_rb_payment_txs();
        assert!(druid_expectations_are_met(
            "VALUE".to_owned(),
            &vec![send_tx, recv_tx]
        ));
    }

    #[test]
    /// Checks that receipt-based payments with non-matching DRUIDs fail
    fn should_fail_rb_payment_druid_mismatch() {
        let (send_tx, mut recv_tx) = create_rb_payment_txs();

        let mut druid_info = recv_tx.druid_info.unwrap();
        druid_info.druid = "Not_VAlue".to_owned();
        recv_tx.druid_info = Some(druid_info);

        // Non-matching druid
        assert_eq!(
            druid_expectations_are_met("VALUE".to_owned(), &vec![send_tx, recv_tx]),
            false
        );
    }

    #[test]
    /// Checks that receipt-based payments with non-matching addresses fail
    fn should_fail_rb_payment_addr_mismatch() {
        let (send_tx, mut recv_tx) = create_rb_payment_txs();
        recv_tx.outputs[0].script_public_key = Some("11145".to_string());

        // Non-matching address expectation
        assert_eq!(
            druid_expectations_are_met("VALUE".to_owned(), &vec![send_tx, recv_tx]),
            false
        );
    }

    #[test]
    /// Checks that receipt-based payments with non-matching value expectations fail
    fn should_fail_rb_payment_value_expect_mismatch() {
        let (mut send_tx, recv_tx) = create_rb_payment_txs();
        send_tx.outputs[0].value = Asset::Token(TokenAmount(10));

        // Non-matching address expectation
        assert_eq!(
            druid_expectations_are_met("VALUE".to_owned(), &vec![send_tx, recv_tx]),
            false
        );
    }
}
