#![allow(dead_code)]

use crate::{Cell, Error};
use alloc::string::String;
use alloc::vec::Vec;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Input {
    cell_ids: Vec<u64>,
    cells: Vec<String>,
}

impl Input {
    pub fn get_cell_ids(&self) -> Result<Vec<u64>, Error> {
        Ok(self.cell_ids.clone())
    }

    pub fn get_cells(&self) -> Result<Vec<Cell>, Error> {
        self.cells
            .iter()
            .map(|s| Cell::from_hex(s))
            .collect::<Result<Vec<Cell>, Error>>()
    }
}

#[derive(Deserialize)]
pub struct Test {
    pub input: Input,
    output: Option<Vec<String>>,
}

impl Test {
    pub fn get_output(&self) -> Option<Vec<Cell>> {
        self.output.clone().map(|strs| {
            strs.iter()
                .map(|s| Cell::from_hex(s).unwrap())
                .collect::<Vec<Cell>>()
        })
    }
}
