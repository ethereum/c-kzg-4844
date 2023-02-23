#![allow(dead_code)]

use crate::Bytes32;
use crate::Bytes48;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input<'a> {
    commitment: &'a str,
    input_point: &'a str,
    claimed_value: &'a str,
    proof: &'a str,
}

impl Input<'_> {
    pub fn get_commitment(&self) -> Bytes48 {
        Bytes48::from_bytes(&hex::decode(self.commitment).unwrap()).unwrap()
    }

    pub fn get_input_point(&self) -> Bytes32 {
        Bytes32::from_bytes(&hex::decode(self.input_point).unwrap()).unwrap()
    }

    pub fn get_claimed_value(&self) -> Bytes32 {
        Bytes32::from_bytes(&hex::decode(self.claimed_value).unwrap()).unwrap()
    }

    pub fn get_proof(&self) -> Bytes48 {
        Bytes48::from_bytes(&hex::decode(self.proof).unwrap()).unwrap()
    }
}

#[derive(Deserialize)]
pub struct Output {
    valid: Option<bool>,
}

impl Output {
    pub fn get_valid(&self) -> Option<bool> {
        self.valid
    }
}

#[derive(Deserialize)]
pub struct Test<'a> {
    #[serde(borrow)]
    pub input: Input<'a>,
    pub output: Output,
}
