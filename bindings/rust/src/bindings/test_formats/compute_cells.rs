#![allow(dead_code)]

use crate::{Blob, Bytes32, Bytes48, Cell, Error};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input<'a> {
    blob: &'a str,
}

impl Input<'_> {
    pub fn get_blob(&self) -> Result<Blob, Error> {
        Blob::from_hex(self.blob)
    }
}

#[derive(Deserialize)]
pub struct Test<'a> {
    #[serde(borrow)]
    pub input: Input<'a>,
    output: Option<Vec<String>>,
}

impl Test<'_> {
    pub fn get_output(&self) -> Option<Vec<Cell>> {
        self.output.clone().map(|strs| {
            strs.iter()
                .map(|s| Cell::from_hex(s).unwrap())
                .collect::<Vec<Cell>>()
        })
    }
}
