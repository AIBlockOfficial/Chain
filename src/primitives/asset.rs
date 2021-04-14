use crate::utils::format_for_display;
use serde::{Deserialize, Serialize};
use std::{fmt, iter, mem::size_of, ops};

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

impl ops::Div<u64> for TokenAmount {
    type Output = Self;

    fn div(self, rhs: u64) -> Self {
        Self(self.0 / rhs)
    }
}

impl ops::DivAssign<u64> for TokenAmount {
    fn div_assign(&mut self, rhs: u64) {
        self.0 /= rhs;
    }
}

impl ops::Mul<u64> for TokenAmount {
    type Output = Self;

    fn mul(self, rhs: u64) -> Self {
        Self(self.0 * rhs)
    }
}

impl ops::MulAssign<u64> for TokenAmount {
    fn mul_assign(&mut self, rhs: u64) {
        self.0 *= rhs;
    }
}

impl iter::Sum for TokenAmount {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::default(), |r, l| r + l)
    }
}

/// Data asset struct
#[derive(Deserialize, Serialize, Debug, Clone, Eq, PartialEq)]
pub struct DataAsset {
    pub data: Vec<u8>,
    pub amount: usize,
}

/// Asset struct
#[derive(Deserialize, Serialize, Debug, Clone, Eq, PartialEq)]
pub enum Asset {
    Token(TokenAmount),
    Data(DataAsset),
    Receipt(String),
}

impl Default for Asset {
    fn default() -> Self {
        Self::new()
    }
}

impl Asset {
    pub fn new() -> Asset {
        Asset::Token(TokenAmount(0))
    }

    pub fn len(&self) -> usize {
        match self {
            Asset::Token(_) => size_of::<u64>(),
            Asset::Data(d) => d.data.len(),
            Asset::Receipt(s) => s.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Asset::Token(_) => false,
            Asset::Data(d) => d.data.is_empty(),
            Asset::Receipt(s) => s.is_empty(),
        }
    }
}
