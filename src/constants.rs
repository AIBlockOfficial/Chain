use crate::script::OpCodes;
use tracing::{error, trace};

/*------- TRANSACTION CONSTANTS -------*/

pub const RECEIPT_DEFAULT_DRS_TX_HASH: &str = "default_drs_tx_hash";
pub const MAX_METADATA_BYTES: usize = 800;

/*------- NETWORK CONSTANTS --------*/

/// Current network version: Always bump immediately after a version is deployed.
pub const NETWORK_VERSION: u32 = 4;
pub const NETWORK_VERSION_SERIALIZED: &[u8] = b"4";

/*------- VALUE HANDLING CONSTANTS --------*/

// Number of decimal places to divide to in display
pub const D_DISPLAY_PLACES_U64: u64 = 25200;
pub const D_DISPLAY_PLACES: f64 = 25200.0;

// Number of possible tokens in existence (10 billion)
pub const TOTAL_TOKENS: u64 = D_DISPLAY_PLACES_U64 * 10000000000;

/*------- ASSET CONSTANTS -------*/

// The value to sign/verify for receipt-based payments
pub const RECEIPT_ACCEPT_VAL: &str = "PAYMENT_ACCEPT";

/*------- BLOCK CONSTANTS --------*/

// Maximum number of bytes that a block can contain
pub const MAX_BLOCK_SIZE: usize = 1000;

/*------- SCRIPT CONSTANTS -------*/

// Maximum number of bytes pushable to the stack
pub const MAX_SCRIPT_ELEMENT_SIZE: u16 = 520;

// Maximum number of non-push operations per script
pub const MAX_OPS_PER_SCRIPT: u8 = 201;

// Maximum number of public keys per multisig
pub const MAX_PUB_KEYS_PER_MULTISIG: u8 = 20;

// Maximum script length in bytes
pub const MAX_SCRIPT_SIZE: u16 = 10000;

// Maximum number of values on script interpreter stack
pub const MAX_STACK_SIZE: u16 = 1000;

// Threshold for lock_time: below this value it is interpreted as block number,
// otherwise as UNIX timestamp.
pub const LOCKTIME_THRESHOLD: u32 = 500000000; // Tue Nov 5 00:53:20 1985 UTC

// Maximum value that an opcode can be
pub const MAX_OPCODE: u8 = OpCodes::MAX_OPCODE as u8;

/*------- STORAGE CONSTANTS -------*/

/// The constant prepending character for a transaction
pub const TX_PREPEND: u8 = b'g';

/*------- PREVIOUS NETWORK VERSIONS -------*/

// Network version 0
pub const NETWORK_VERSION_V0: u64 = 0;

// Network version to support temporary address structure on wallet
// TODO: Depreciate after addresses retire
pub const NETWORK_VERSION_TEMP: u64 = 99999;

/*------- NUMBERS -------*/
pub const ZERO: usize = 0;
pub const ONE: usize = 1;
pub const TWO: usize = 2;
pub const THREE: usize = 3;
pub const FOUR: usize = 4;
pub const FIVE: usize = 5;
pub const SIX: usize = 6;
pub const SEVEN: usize = 7;
pub const EIGHT: usize = 8;
pub const NINE: usize = 9;
pub const TEN: usize = 10;
pub const ELEVEN: usize = 11;
pub const TWELVE: usize = 12;
pub const THIRTEEN: usize = 13;
pub const FOURTEEN: usize = 14;
pub const FIFTEEN: usize = 15;
pub const SIXTEEN: usize = 16;

/*------- STRINGS -------*/

// constants
pub const OP0: &str = "OP_0";
pub const OP1: &str = "OP_1";
pub const OP2: &str = "OP_2";
pub const OP3: &str = "OP_3";
pub const OP4: &str = "OP_4";
pub const OP5: &str = "OP_5";
pub const OP6: &str = "OP_6";
pub const OP7: &str = "OP_7";
pub const OP8: &str = "OP_8";
pub const OP9: &str = "OP_9";
pub const OP10: &str = "OP_10";
pub const OP11: &str = "OP_11";
pub const OP12: &str = "OP_12";
pub const OP13: &str = "OP_13";
pub const OP14: &str = "OP_14";
pub const OP15: &str = "OP_15";
pub const OP16: &str = "OP_16";

pub const OP0_DESC: &str = "Pushes the number ZERO onto the stack";
pub const OP1_DESC: &str = "Pushes the number ONE onto the stack";
pub const OP2_DESC: &str = "Pushes the number TWO onto the stack";
pub const OP3_DESC: &str = "Pushes the number THREE onto the stack";
pub const OP4_DESC: &str = "Pushes the number FOUR onto the stack";
pub const OP5_DESC: &str = "Pushes the number FIVE onto the stack";
pub const OP6_DESC: &str = "Pushes the number SIX onto the stack";
pub const OP7_DESC: &str = "Pushes the number SEVEN onto the stack";
pub const OP8_DESC: &str = "Pushes the number EIGHT onto the stack";
pub const OP9_DESC: &str = "Pushes the number NINE onto the stack";
pub const OP10_DESC: &str = "Pushes the number TEN onto the stack";
pub const OP11_DESC: &str = "Pushes the number ELEVEN onto the stack";
pub const OP12_DESC: &str = "Pushes the number TWELVE onto the stack";
pub const OP13_DESC: &str = "Pushes the number THIRTEEN onto the stack";
pub const OP14_DESC: &str = "Pushes the number FOURTEEN onto the stack";
pub const OP15_DESC: &str = "Pushes the number FIFTEEN onto the stack";
pub const OP16_DESC: &str = "Pushes the number SIXTEEN onto the stack";

// stack
pub const OPTOALTSTACK: &str = "OP_TOALTSTACK";
pub const OPFROMALTSTACK: &str = "OP_FROMALTSTACK";
pub const OP2DROP: &str = "OP_2DROP";
pub const OP2DUP: &str = "OP_2DUP";
pub const OP3DUP: &str = "OP_3DUP";
pub const OP2OVER: &str = "OP_2OVER";
pub const OP2ROT: &str = "OP_2ROT";
pub const OP2SWAP: &str = "OP_2SWAP";
pub const OPIFDUP: &str = "OP_IFDUP";
pub const OPDEPTH: &str = "OP_DEPTH";
pub const OPDROP: &str = "OP_DROP";
pub const OPDUP: &str = "OP_DUP";
pub const OPNIP: &str = "OP_NIP";
pub const OPOVER: &str = "OP_OVER";
pub const OPPICK: &str = "OP_PICK";
pub const OPROLL: &str = "OP_ROLL";
pub const OPROT: &str = "OP_ROT";
pub const OPSWAP: &str = "OP_SWAP";
pub const OPTUCK: &str = "OP_TUCK";

pub const OPTOALTSTACK_DESC: &str =
    "Moves the top item from the main stack to the top of the alt stack";
pub const OPFROMALTSTACK_DESC: &str =
    "Moves the top item from the alt stack to the top of the main stack";
pub const OP2DROP_DESC: &str = "Removes the top two items from the stack";
pub const OP2DUP_DESC: &str = "Duplicates the top two items on the stack";
pub const OP3DUP_DESC: &str = "Duplicates the top three items on the stack";
pub const OP2OVER_DESC: &str = "Copies the second-to-top pair of items to the top of the stack";
pub const OP2ROT_DESC: &str = "Moves the third-to-top pair of items to the top of the stack";
pub const OP2SWAP_DESC: &str = "Swaps the top two pairs of items on the stack";
pub const OPIFDUP_DESC: &str = "Duplicates the top item on the stack if it is not ZERO";
pub const OPDEPTH_DESC: &str = "Pushes the stack size onto the stack";
pub const OPDROP_DESC: &str = "Removes the top item from the stack";
pub const OPDUP_DESC: &str = "Duplicates the top item on the stack";
pub const OPNIP_DESC: &str = "Removes the second-to-top item from the stack";
pub const OPOVER_DESC: &str = "Copies the second-to-top item to the top of the stack";
pub const OPPICK_DESC: &str =
    "Copies the nth-to-top item to the top of the stack, where n is the top item on the stack";
pub const OPROLL_DESC: &str =
    "Moves the nth-to-top item to the top of the stack, where n is the top item on the stack";
pub const OPROT_DESC: &str = "Moves the third-to-top item to the top of the stack";
pub const OPSWAP_DESC: &str = "Swaps the top two items on the stack";
pub const OPTUCK_DESC: &str = "Copies the top item before the second-to-top item on the stack";

// error messages
pub const ERROR_NUM_ITEMS: &str = "Not enough items on the stack";
pub const ERROR_TYPE: &str = "Item type is not correct";
pub const ERROR_INDEX: &str = "Index is out of bound";


// util functions
pub fn trace(opcode: &str, desc: &str) {
    trace!("{}: {}", opcode, desc)
}

pub fn error_num_items(opcode: &str) {
    error!("{}: {}", opcode, ERROR_NUM_ITEMS)
}

pub fn error_type(opcode: &str) {
    error!("{}: {}", opcode, ERROR_TYPE)
}

pub fn error_index(opcode: &str) {
    error!("{}: {}", opcode, ERROR_INDEX)
}
