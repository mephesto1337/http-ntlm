use std::io;
use std::mem::size_of_val;
use std::ops::{Deref, DerefMut};

use super::{NomError, Wire};

use nom::bytes::complete::take;
use nom::error::context;

#[derive(Default, Debug, PartialEq, Eq)]
pub struct Version([u8; 8]);

impl<'a> Wire<'a> for Version {
    fn serialize_into<W>(&self, writer: &mut W) -> io::Result<usize>
    where
        W: io::Write,
    {
        writer.write_all(&self.0[..])?;
        Ok(self.0.len())
    }

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        let mut version = [0u8; 8];

        let (rest, data) = context("Version", take(size_of_val(&version)))(input)?;

        version.copy_from_slice(data);
        Ok((rest, Self(version)))
    }
}

impl From<[u8; 8]> for Version {
    fn from(d: [u8; 8]) -> Self {
        Self(d)
    }
}

impl Deref for Version {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Version {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
