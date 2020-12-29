use crate::constants::D_DISPLAY_PLACES;
use crate::primitives::asset::TokenAmount;

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
pub fn format_for_display(value: &u64) -> f64 {
    *value as f64 / D_DISPLAY_PLACES
}
