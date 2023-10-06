#![allow(dead_code)]

use super::deserialize_blob;
use crate::{Bytes48, Error};
use bytes::Bytes;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input {
    blobs: Vec<String>,
    commitments: Vec<String>,
    proofs: Vec<String>,
}

impl Input {
    pub fn get_blobs(&self) -> Result<Vec<Bytes>, Error> {
        let mut v: Vec<Bytes> = Vec::new();
        for blob in &self.blobs {
            v.push(deserialize_blob(blob)?);
        }
        Ok(v)
    }

    pub fn get_commitments(&self) -> Result<Vec<Bytes48>, Error> {
        self.commitments
            .iter()
            .map(|s| Bytes48::from_hex(s))
            .collect::<Result<Vec<Bytes48>, Error>>()
    }

    pub fn get_proofs(&self) -> Result<Vec<Bytes48>, Error> {
        self.proofs
            .iter()
            .map(|s| Bytes48::from_hex(s))
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
