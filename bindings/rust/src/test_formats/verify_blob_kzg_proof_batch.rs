#![allow(dead_code)]

use crate::Bytes48;
use crate::{Blob, Error};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input {
    blobs: Vec<String>,
    commitments: Vec<String>,
    proofs: Vec<String>,
}

impl Input {
    pub fn get_blobs(&self) -> Result<Vec<Box<Blob>>, Error> {
        let mut ret: Vec<Result<Box<Blob>, Error>>  = Vec::new();
        for blob in &self.blobs {
            let hex_str = &blob.replace("0x", "");
            let bytes = &hex::decode(hex_str).unwrap();
            ret.push(Blob::from_bytes_boxed(&bytes));
        }

        //let new: Result<Vec<T>, E> = v.into_iter().collect()
        ret.into_iter().collect::<Result<Vec<Box<Blob>>, Error>>()
        //ret.iter().transpose()
    }

    pub fn get_commitments(&self) -> Result<Vec<Bytes48>, Error> {
        self.commitments
            .iter()
            .map(|s| s.replace("0x", ""))
            .map(|hex_str| hex::decode(hex_str).unwrap())
            .map(|bytes| Bytes48::from_bytes(bytes.as_slice()))
            .collect::<Result<Vec<Bytes48>, Error>>()
    }

    pub fn get_proofs(&self) -> Result<Vec<Bytes48>, Error> {
        self.proofs
            .iter()
            .map(|s| s.replace("0x", ""))
            .map(|hex_str| hex::decode(hex_str).unwrap())
            .map(|bytes| Bytes48::from_bytes(bytes.as_slice()))
            .collect::<Result<Vec<Bytes48>, Error>>()
    }
}

#[derive(Deserialize)]
pub struct Test {
    pub input: Input,
    output: Option<bool>,
}

impl Test {
    pub fn get_output(&self) -> Option<bool> {
        self.output
    }
}
