use std::io;

use crate::messages::{
    utils::{write_u16, write_u8},
    NomError, Wire,
};

use nom::combinator::verify;
use nom::error::context;
use nom::number::complete::{le_u16, le_u24, le_u8};
use nom::sequence::tuple;

#[derive(Default, Debug, PartialEq, Eq, Clone)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
    pub build: u16,
    pub revision_count: u8,
}

pub const NTLMSSP_REVISION_W2K3: u8 = 0x0f;

impl<'a> Wire<'a> for Version {
    fn serialize_into<W>(&self, writer: &mut W) -> io::Result<usize>
    where
        W: io::Write,
    {
        let mut size = 0;
        size += write_u8(writer, self.major)?;
        size += write_u8(writer, self.minor)?;
        size += write_u16(writer, self.build)?;
        size += write_u8(writer, 0)?;
        size += write_u16(writer, 0)?;
        size += write_u8(writer, self.revision_count)?;
        Ok(size)
    }

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        let (rest, (major, minor, build, _reserved, revision_count)) = context(
            "Version",
            tuple((
                context("major", le_u8),
                context("minor", le_u8),
                context("build", le_u16),
                context("reserved", verify(le_u24, |r| *r == 0)),
                context(
                    "revision_count",
                    verify(le_u8, |rc| *rc == NTLMSSP_REVISION_W2K3),
                ),
            )),
        )(input)?;

        Ok((
            rest,
            Self {
                major,
                minor,
                build,
                revision_count,
            },
        ))
    }
}

impl TryFrom<[u8; 8]> for Version {
    type Error = ();

    fn try_from(value: [u8; 8]) -> Result<Self, Self::Error> {
        match Self::deserialize::<()>(&value[..]) {
            Ok((_, v)) => Ok(v),
            Err(_) => Err(()),
        }
    }
}
