#![allow(dead_code)]

use crate::{Blob, Bytes48, Error};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input<'a> {
    blob: &'a str,
}

impl Input<'_> {
    pub fn get_blob(&self) -> Result<Box<Blob>, Error> {
        let hex_str = self.blob.replace("0x", "");
        let bytes = hex::decode(hex_str).unwrap();
        Blob::from_bytes(&bytes)
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
            let hex_str = self.output.unwrap().replace("0x", "");
            let bytes = hex::decode(hex_str).unwrap();
            Some(Bytes48::from_bytes(&bytes).unwrap())
        } else {
            None
        }
    }
}
