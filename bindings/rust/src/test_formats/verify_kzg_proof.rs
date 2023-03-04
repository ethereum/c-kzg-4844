#![allow(dead_code)]

use crate::Bytes48;
use crate::{Bytes32, Error};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input<'a> {
    commitment: &'a str,
    z: &'a str,
    y: &'a str,
    proof: &'a str,
}

impl Input<'_> {
    pub fn get_commitment(&self) -> Result<Bytes48, Error> {
        let hex_str = self.commitment.replace("0x", "");
        let bytes = hex::decode(hex_str).unwrap();
        Bytes48::from_bytes(&bytes)
    }

    pub fn get_z(&self) -> Result<Bytes32, Error> {
        let hex_str = self.z.replace("0x", "");
        let bytes = hex::decode(hex_str).unwrap();
        Bytes32::from_bytes(&bytes)
    }

    pub fn get_y(&self) -> Result<Bytes32, Error> {
        let hex_str = self.y.replace("0x", "");
        let bytes = hex::decode(hex_str).unwrap();
        Bytes32::from_bytes(&bytes)
    }

    pub fn get_proof(&self) -> Result<Bytes48, Error> {
        let hex_str = self.proof.replace("0x", "");
        let bytes = hex::decode(hex_str).unwrap();
        Bytes48::from_bytes(&bytes)
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
