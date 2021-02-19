use crate::utils::format_for_display;
use serde::{Deserialize, Serialize};
use std::{fmt, iter, ops};

/// A structure representing the amount of tokens in an instance
#[derive(Deserialize, Serialize, Default, Debug, Copy, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub struct TokenAmount(pub u64);

impl fmt::Display for TokenAmount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let format_result = format_for_display(&self.0);
        write!(f, "{}", format_result)
    }
}

impl ops::Add for TokenAmount {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self(self.0 + other.0)
    }
}

impl ops::AddAssign for TokenAmount {
    fn add_assign(&mut self, other: Self) {
        self.0 += other.0;
    }
}

impl ops::Sub for TokenAmount {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        Self(self.0 - other.0)
    }
}

impl ops::SubAssign for TokenAmount {
    fn sub_assign(&mut self, other: Self) {
        self.0 -= other.0;
    }
}

impl iter::Sum for TokenAmount {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::default(), |r, l| r + l)
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
