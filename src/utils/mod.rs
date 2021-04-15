use crate::constants::D_DISPLAY_PLACES;
use crate::primitives::asset::TokenAmount;

// ------- MODS ------- //

pub mod druid_utils;
pub mod script_utils;
pub mod transaction_utils;

// ------- FUNCTIONS ------- //

/// Determines whether the passed value is within bounds of
/// available tokens in the supply.
///
/// TODO: Currently placeholder, needs to be filled in once requirements known
pub fn is_valid_amount(_value: &TokenAmount) -> bool {
    true
}

/// Formats an incoming value to be displayed
///
/// ### Arguments
///
/// * `value`   - Value to format for display
pub fn format_for_display(value: &u64) -> String {
    let value_f64 = *value as f64;
    (value_f64 / D_DISPLAY_PLACES).to_string()
}
