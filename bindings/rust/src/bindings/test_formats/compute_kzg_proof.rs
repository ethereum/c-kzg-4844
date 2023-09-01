#![allow(dead_code)]

use crate::{Blob, Bytes32, Error, KzgProof};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input<'a> {
    blob: &'a str,
    z: &'a str,
}

impl Input<'_> {
    pub fn get_blob(&self) -> Result<Blob, Error> {
        Blob::from_hex(self.blob)
    }

    pub fn get_z(&self) -> Result<Bytes32, Error> {
        Bytes32::from_hex(self.z)
    }
}

#[derive(Deserialize)]
pub struct Test<'a> {
    #[serde(borrow)]
    pub input: Input<'a>,
    #[serde(borrow)]
    output: Option<(&'a str, &'a str)>,
}

impl Test<'_> {
    pub fn get_output(&self) -> Option<(KzgProof, Bytes32)> {
        self.output.map(|(proof, y)| {
            (
                KzgProof::from_hex(proof).unwrap(),
                Bytes32::from_hex(y).unwrap(),
            )
        })
    }
}
