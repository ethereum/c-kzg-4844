#![allow(dead_code)]

use crate::Blob;
use crate::Bytes48;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input {
    blobs: Vec<String>,
    commitments: Vec<String>,
    proofs: Vec<String>,
}

impl Input {
    pub fn get_blobs(&self) -> Vec<Blob> {
        self.blobs.iter()
            .map(|f| hex::decode(f).unwrap())
            .map(|bytes| Blob::from_bytes(bytes.as_slice()).unwrap())
            .collect::<Vec<Blob>>()
    }

    pub fn get_commitments(&self) -> Vec<Bytes48> {
        self.commitments.iter()
            .map(|f| hex::decode(f).unwrap())
            .map(|bytes| Bytes48::from_bytes(bytes.as_slice()).unwrap())
            .collect::<Vec<Bytes48>>()
    }

    pub fn get_proofs(&self) -> Vec<Bytes48> {
        self.proofs.iter()
            .map(|f| hex::decode(f).unwrap())
            .map(|bytes| Bytes48::from_bytes(bytes.as_slice()).unwrap())
            .collect::<Vec<Bytes48>>()
    }
}

#[derive(Deserialize)]
pub struct Output {
    valid: Option<bool>,
}

impl Output {
    pub fn get_valid(&self) -> Option<bool> {
        self.valid
    }
}

#[derive(Deserialize)]
pub struct Test {
    pub input: Input,
    pub output: Output,
}
