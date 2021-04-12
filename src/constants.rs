use crate::script::OpCodes;

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
pub const MAX_OPCODE: u8 = OpCodes::OP_NOP10 as u8;

/*------- STORAGE CONSTANTS -------*/

/// The constant prepending character for a transaction
pub const TX_PREPEND: char = 'g';

/// Path to chain DB
pub const DB_PATH: &str = "/Users/byron/code/zenotta/naom/src/db/db";

/// Path to test net DB
pub const DB_PATH_TEST: &str = "test";

/// Path to live net DB
pub const DB_PATH_LIVE: &str = "live";

/// Path to wallet DB
pub const WALLET_PATH: &str = "/Users/byron/code/zenotta/naom/src/wallet/wallet";
