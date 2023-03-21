use crate::constants::*;
use tracing::{error, trace};

/*------- TRACE MESSAGES -------*/

pub fn trace(op: &str, desc: &str) {
    trace!("{}: {}", op, desc)
}

/*------- ERROR MESSAGES -------*/

// opcodes

pub fn error_verify(op: &str) {
    error!("{}: {}", op, ERROR_VERIFY)
}

pub fn error_return(op: &str) {
    error!("{}: {}", op, ERROR_RETURN)
}

pub fn error_num_items(op: &str) {
    error!("{}: {}", op, ERROR_NUM_ITEMS)
}

pub fn error_item_type(op: &str) {
    error!("{}: {}", op, ERROR_ITEM_TYPE)
}

pub fn error_item_index(op: &str) {
    error!("{}: {}", op, ERROR_ITEM_INDEX)
}

pub fn error_item_size(op: &str) {
    error!("{}: {}", op, ERROR_ITEM_SIZE)
}

pub fn error_not_equal_items(op: &str) {
    error!("{}: {}", op, ERROR_NOT_EQUAL_ITEMS)
}

pub fn error_overflow(op: &str) {
    error!("{}: {}", op, ERROR_OVERFLOW)
}

pub fn error_div_zero(op: &str) {
    error!("{}: {}", op, ERROR_DIV_ZERO)
}

pub fn error_invalid_signature(op: &str) {
    error!("{}: {}", op, ERROR_INVALID_SIGNATURE)
}

pub fn error_invalid_multisignature(op: &str) {
    error!("{}: {}", op, ERROR_INVALID_MULTISIGNATURE)
}

pub fn error_num_pubkeys(op: &str) {
    error!("{}: {}", op, ERROR_NUM_PUBKEYS)
}

pub fn error_num_signatures(op: &str) {
    error!("{}: {}", op, ERROR_NUM_SIGNATURES)
}

// script

pub fn error_max_script_size() {
    error!("{}", ERROR_MAX_SCRIPT_SIZE)
}

pub fn error_max_stack_size() {
    error!("{}", ERROR_MAX_STACK_SIZE)
}

pub fn error_max_ops_script() {
    error!("{}", ERROR_MAX_OPS_SCRIPT)
}

pub fn error_invalid_opcode() {
    error!("{}", ERROR_INVALID_OPCODE)
}
