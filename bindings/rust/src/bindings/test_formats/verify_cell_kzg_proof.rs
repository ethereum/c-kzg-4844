#![allow(dead_code)]

use crate::{Bytes48, Cell, Error};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input<'a> {
    commitment: &'a str,
    cell_id: u64,
    cell: &'a str,
    proof: &'a str,
}

impl Input<'_> {
    pub fn get_commitment(&self) -> Result<Bytes48, Error> {
        Bytes48::from_hex(self.commitment)
    }

    pub fn get_cell_id(&self) -> Result<u64, Error> {
        Ok(self.cell_id)
    }

    pub fn get_cell(&self) -> Result<Cell, Error> {
        Cell::from_hex(self.cell)
    }

    pub fn get_proof(&self) -> Result<Bytes48, Error> {
        Bytes48::from_hex(self.proof)
    }
}

#[derive(Deserialize)]
pub struct Test<'a> {
    #[serde(borrow)]
    pub input: Input<'a>,
    output: Option<bool>,
}

impl Test<'_> {
    pub fn get_output(&self) -> Option<bool> {
        self.output
    }
}
