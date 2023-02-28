#![allow(dead_code)]

use crate::Bytes32;
use crate::Bytes48;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input<'a> {
    commitment: &'a str,
    #[serde(rename(deserialize = "z"))]
    input_point: &'a str,
    #[serde(rename(deserialize = "y"))]
    claimed_value: &'a str,
    proof: &'a str,
}

impl Input<'_> {
    pub fn get_commitment(&self) -> Bytes48 {
        Bytes48::from_bytes(&hex::decode(self.commitment.replace("0x", "")).unwrap()).unwrap()
    }

    pub fn get_input_point(&self) -> Bytes32 {
        Bytes32::from_bytes(&hex::decode(self.input_point.replace("0x", "")).unwrap()).unwrap()
    }

    pub fn get_claimed_value(&self) -> Bytes32 {
        Bytes32::from_bytes(&hex::decode(self.claimed_value.replace("0x", "")).unwrap()).unwrap()
    }

    pub fn get_proof(&self) -> Bytes48 {
        Bytes48::from_bytes(&hex::decode(self.proof.replace("0x", "")).unwrap()).unwrap()
    }
}

#[derive(Deserialize)]
pub struct Test<'a> {
    #[serde(borrow)]
    pub input: Input<'a>,
    output: Option<bool>,
}

impl Test<'_> {
    pub fn get_output(&self) -> Option<bool> {
        self.output
    }
}
