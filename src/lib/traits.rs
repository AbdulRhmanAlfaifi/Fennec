use std::{
    io::{Error, ErrorKind, Read},
    process::{ChildStderr, ChildStdout},
};

pub trait ReadUntil {
    fn read_until(&mut self, byte: u8) -> Result<String, Error>;
}

impl ReadUntil for ChildStdout {
    fn read_until(&mut self, byte: u8) -> Result<String, Error> {
        let mut results: Vec<u8> = vec![];
        loop {
            let mut single_byte: [u8; 1] = [0; 1];
            match self.read(&mut single_byte) {
                Ok(size) => {
                    if size == 0 {
                        return Err(Error::new(ErrorKind::UnexpectedEof, "EoF reached"));
                    }
                }
                Err(e) => return Err(e),
            }

            if single_byte[0] == byte {
                return Ok(String::from_utf8_lossy(&results).to_string());
            } else {
                results.push(single_byte[0]);
            }
        }
    }
}
impl ReadUntil for ChildStderr {
    fn read_until(&mut self, byte: u8) -> Result<String, Error> {
        let mut results: Vec<u8> = vec![];
        loop {
            let mut single_byte: [u8; 1] = [0; 1];
            match self.read(&mut single_byte) {
                Ok(size) => {
                    if size == 0 {
                        return Err(Error::new(ErrorKind::UnexpectedEof, "EoF reached"));
                    }
                }
                Err(e) => return Err(e),
            }

            if single_byte[0] == byte {
                return Ok(String::from_utf8_lossy(&results).to_string());
            } else {
                results.push(single_byte[0]);
            }
        }
    }
}
