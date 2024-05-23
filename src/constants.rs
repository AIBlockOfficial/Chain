/*------- TRANSACTION CONSTANTS -------*/
pub const TX_PREPEND: u8 = b'g';
pub const ITEM_DEFAULT_DRS_TX_HASH: &str = "default_genesis_hash";
pub const MAX_METADATA_BYTES: usize = 800;
pub const TX_HASH_LENGTH: usize = 32;

/*------- ADDRESS CONSTANTS -------*/
pub const STANDARD_ADDRESS_LENGTH: usize = 64;
// Prepending character for a P2SH address
pub const P2SH_PREPEND: u8 = b'H';

/*------- NETWORK CONSTANTS --------*/
// Current network version: Always bump immediately after a version is deployed.
pub const NETWORK_VERSION: u32 = 6;
pub const NETWORK_VERSION_SERIALIZED: &[u8] = b"6";

/*------- VALUE HANDLING CONSTANTS --------*/
// Number of decimal places to divide to in display
pub const D_DISPLAY_PLACES_U64: u64 = 72072000;
pub const D_DISPLAY_PLACES: f64 = 72072000.0;
// Number of possible tokens in existence (5 billion)
pub const TOTAL_TOKENS: u64 = D_DISPLAY_PLACES_U64 * 5000000000;

/*------- ASSET CONSTANTS -------*/
// The value to sign/verify for item-based payments
pub const ITEM_ACCEPT_VAL: &str = "PAYMENT_ACCEPT";

/*------- BLOCK CONSTANTS --------*/
// Maximum number of bytes that a block can contain
pub const MAX_BLOCK_SIZE: usize = 1000;

/*------- SCRIPT CONSTANTS -------*/
// Maximum number of bytes pushable to the stack
pub const MAX_SCRIPT_ITEM_SIZE: u16 = 520;
// Maximum number of non-push operations per script
pub const MAX_OPS_PER_SCRIPT: u8 = 201;
// Maximum number of public keys per multisig
pub const MAX_PUB_KEYS_PER_MULTISIG: u8 = 20;
// Maximum script length in bytes
pub const MAX_SCRIPT_SIZE: u16 = 10000;
// Maximum number of values on script interpreter stack
pub const MAX_STACK_SIZE: u16 = 1000;

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
