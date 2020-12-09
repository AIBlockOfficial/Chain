use serde::{Deserialize, Serialize};

/// A placeholder Asset struct
#[derive(Deserialize, Serialize, Debug, Clone, PartialOrd, PartialEq)]
pub enum Asset {
    Token(f64),
    Data(Vec<u8>),
}

/// A structure for an asset to send, along with its quantity
#[derive(Debug, Clone)]
pub struct AssetInTransit {
    pub asset: Asset,
    pub amount: f64,
}
