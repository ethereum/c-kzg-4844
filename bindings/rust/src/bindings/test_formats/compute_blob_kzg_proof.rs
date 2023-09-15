#![allow(dead_code)]

use crate::{Blob, Bytes48, Error, KzgSettings};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input<'a> {
    blob: &'a str,
    commitment: &'a str,
}

impl Input<'_> {
    pub fn get_blob(&self, s: &KzgSettings) -> Result<Blob, Error> {
        Blob::from_hex(self.blob, s)
    }

    pub fn get_commitment(&self) -> Result<Bytes48, Error> {
        Bytes48::from_hex(self.commitment)
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
        self.output.map(|s| Bytes48::from_hex(s).unwrap())
    }
}
