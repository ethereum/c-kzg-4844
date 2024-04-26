#![allow(dead_code)]

use crate::{Bytes48, Cell, Error};
use alloc::string::String;
use alloc::vec::Vec;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input {
    row_commitments: Vec<String>,
    row_indices: Vec<u64>,
    column_indices: Vec<u64>,
    cells: Vec<String>,
    proofs: Vec<String>,
}

impl Input {
    pub fn get_row_commitments(&self) -> Result<Vec<Bytes48>, Error> {
        self.row_commitments
            .iter()
            .map(|s| Bytes48::from_hex(s))
            .collect::<Result<Vec<Bytes48>, Error>>()
    }

    pub fn get_row_indices(&self) -> Result<Vec<u64>, Error> {
        Ok(self.row_indices.clone())
    }

    pub fn get_column_indices(&self) -> Result<Vec<u64>, Error> {
        Ok(self.column_indices.clone())
    }

    pub fn get_cells(&self) -> Result<Vec<Cell>, Error> {
        self.cells
            .iter()
            .map(|s| Cell::from_hex(s))
            .collect::<Result<Vec<Cell>, Error>>()
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
