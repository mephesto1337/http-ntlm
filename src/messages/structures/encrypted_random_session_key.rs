use std::fmt;
use std::io;
use std::ops::{Deref, DerefMut};

use crate::messages::{NomError, Wire};

#[derive(Default, PartialEq, Eq)]
pub struct EncryptedRandomSessionKey(Vec<u8>);

impl<'a> Wire<'a> for EncryptedRandomSessionKey {
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
        Ok((&b""[..], input.into()))
    }
}

impl From<&[u8]> for EncryptedRandomSessionKey {
    fn from(d: &[u8]) -> Self {
        Self(d.to_owned())
    }
}

impl From<Vec<u8>> for EncryptedRandomSessionKey {
    fn from(d: Vec<u8>) -> Self {
        Self(d)
    }
}

impl Deref for EncryptedRandomSessionKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for EncryptedRandomSessionKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl fmt::Debug for EncryptedRandomSessionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0[..] {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}
