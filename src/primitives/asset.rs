use crate::utils::format_for_display;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A structure representing the amount of tokens in an instance
#[derive(Deserialize, Serialize, Default, Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub struct TokenAmount(pub u64);

impl fmt::Display for TokenAmount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let format_result = format_for_display(&self.0);
        write!(f, "{:.3}", format_result)
    }
}

/// A placeholder Asset struct
#[derive(Deserialize, Serialize, Debug, Clone, Eq, PartialEq)]
pub enum Asset {
    Token(TokenAmount),
    Data(Vec<u8>),
}

/// A structure for an asset to send, along with its quantity
#[derive(Debug, Clone)]
pub struct AssetInTransit {
    pub asset: Asset,
    pub amount: TokenAmount,
}
