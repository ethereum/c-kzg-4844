#![allow(dead_code)]

use crate::Blob;
use crate::Bytes32;
use crate::Bytes48;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input<'a> {
    blob: &'a str,
    input_point: &'a str,
}

impl Input<'_> {
    pub fn get_blob(&self) -> Blob {
        Blob::from_bytes(&hex::decode(self.blob).unwrap()).unwrap()
    }

    pub fn get_input_point(&self) -> Bytes32 {
        Bytes32::from_bytes(&hex::decode(self.input_point).unwrap()).unwrap()
    }
}

#[derive(Deserialize)]
pub struct Output<'a> {
    proof: Option<&'a str>,
}

impl Output<'_> {
    pub fn get_proof(&self) -> Option<Bytes48> {
        if self.proof.is_some() {
            Some(Bytes48::from_bytes(&hex::decode(self.proof.unwrap()).unwrap()).unwrap())
        } else {
            None
        }
    }
}

#[derive(Deserialize)]
pub struct Test<'a> {
    #[serde(borrow)]
    pub input: Input<'a>,
    #[serde(borrow)]
    pub output: Output<'a>,
}
