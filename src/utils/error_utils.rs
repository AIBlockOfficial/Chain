use crate::constants::*;
use tracing::{error, trace};

/*------- TRACE MESSAGES -------*/

pub fn trace(op: &str, desc: &str) {
    trace!("{}: {}", op, desc)
}

/*------- ERROR MESSAGES -------*/

pub fn error_num_items(opcode: &str) {
    error!("{}: {}", opcode, ERROR_NUM_ITEMS)
}

pub fn error_item_type(opcode: &str) {
    error!("{}: {}", opcode, ERROR_ITEM_TYPE)
}

pub fn error_item_index(opcode: &str) {
    error!("{}: {}", opcode, ERROR_ITEM_INDEX)
}

pub fn error_item_size(opcode: &str) {
    error!("{}: {}", opcode, ERROR_ITEM_SIZE)
}

pub fn error_not_equal_items(opcode: &str) {
    error!("{}: {}", opcode, ERROR_NOT_EQUAL_ITEMS)
}

pub fn error_overflow(opcode: &str) {
    error!("{}: {}", opcode, ERROR_OVERFLOW)
}

pub fn error_div_zero(opcode: &str) {
    error!("{}: {}", opcode, ERROR_DIV_ZERO)
}

pub fn error_max_script_size() {
    error!("{}", ERROR_MAX_SCRIPT_SIZE)
}

pub fn error_max_stack_size() {
    error!("{}", ERROR_MAX_STACK_SIZE)
}

pub fn error_max_ops_script() {
    error!("{}", ERROR_MAX_OPS_SCRIPT)
}

pub fn error_unknown_operation() {
    error!("{}", ERROR_UNKWON_OPERATION)
}
