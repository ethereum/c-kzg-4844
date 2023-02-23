#![allow(dead_code)]

use crate::Blob;
use crate::Bytes48;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input<'a> {
    blob: &'a str,
}

impl Input<'_> {
    pub fn get_blob(&self) -> Blob {
        Blob::from_bytes(&hex::decode(self.blob).unwrap()).unwrap()
    }
}

#[derive(Deserialize)]
pub struct Output<'a> {
    commitment: Option<&'a str>,
}

impl Output<'_> {
    pub fn get_commitment(&self) -> Option<Bytes48> {
        if self.commitment.is_some() {
            Some(Bytes48::from_bytes(&hex::decode(self.commitment.unwrap()).unwrap()).unwrap())
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
