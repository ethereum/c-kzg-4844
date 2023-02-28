#![allow(dead_code)]

use crate::Blob;
use crate::Bytes32;
use crate::Bytes48;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input<'a> {
    blob: &'a str,
    #[serde(rename(deserialize = "z"))]
    input_point: &'a str,
}

impl Input<'_> {
    pub fn get_blob(&self) -> Blob {
        Blob::from_bytes(&hex::decode(self.blob.replace("0x", "")).unwrap()).unwrap()
    }

    pub fn get_input_point(&self) -> Bytes32 {
        Bytes32::from_bytes(&hex::decode(self.input_point.replace("0x", "")).unwrap()).unwrap()
    }
}

#[derive(Deserialize)]
pub struct Test<'a> {
    #[serde(borrow)]
    pub input: Input<'a>,
    #[serde(borrow)]
    output: Option<&'a str>,
}

impl Test<'_> {
    pub fn get_output(&self) -> Option<Bytes48> {
        if self.output.is_some() {
            Some(
                Bytes48::from_bytes(&hex::decode(self.output.unwrap().replace("0x", "")).unwrap())
                    .unwrap(),
            )
        } else {
            None
        }
    }
}
