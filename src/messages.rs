use std::io::{self, Write};

trait NomError<'a>: nom::error::ContextError<&'a [u8]> + nom::error::ParseError<&'a [u8]> {}

impl<'a, E> NomError<'a> for E where
    E: nom::error::ParseError<&'a [u8]> + nom::error::ContextError<&'a [u8]>
{
}

trait Wire<'a>: Sized {
    fn serialize_into<W>(&self, writer: &mut W) -> io::Result<usize>
    where
        W: Write;
    fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        self.serialize_into(&mut data)
            .expect("Writing to a Vec should never failed");
        data
    }

    fn header_size() -> usize;

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>;
}

const SIGNATURE: &'static [u8; 8] = b"NTLMSSP\0";

mod authenticate;
mod challenge;
mod negociate;
mod utils;
