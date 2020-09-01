use serde::{Deserialize, Serialize};

/// A placeholder Asset struct
#[derive(Deserialize, Serialize, Debug, Clone, Eq, PartialEq)]
pub enum Asset {
    Token(u64),
    Data(Vec<u8>),
}

/// A structure for an asset to send, along with its quantity
#[derive(Debug, Clone)]
pub struct AssetInTransit {
    pub asset: Asset,
    pub amount: u64,
}