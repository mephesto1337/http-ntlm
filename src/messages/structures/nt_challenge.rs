use std::io;

use nom::branch::alt;
use nom::combinator::{map, verify};
use nom::error::context;
use nom::number::complete::{le_u16, le_u32, le_u8};
use nom::sequence::{preceded, tuple};

use crate::messages::{
    structures::{AvPair, ClientChallenge, FileTime, Response24},
    utils::{write_u16, write_u32, write_u8},
    NomError, Wire,
};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Ntv1Challenge {
    pub response: Response24,
}

impl<'a> Wire<'a> for Ntv1Challenge {
    fn serialize_into<W>(&self, writer: &mut W) -> io::Result<usize>
    where
        W: io::Write,
    {
        self.response.serialize_into(writer)
    }

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        let (rest, response) = context("Ntv1Challenge", Response24::deserialize)(input)?;
        Ok((rest, Self { response }))
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Ntv2Challenge {
    pub timestamp: FileTime,
    pub challenge_from_client: ClientChallenge,
    pub target_infos: Vec<AvPair>,
}

impl<'a> Wire<'a> for Ntv2Challenge {
    fn serialize_into<W>(&self, writer: &mut W) -> io::Result<usize>
    where
        W: io::Write,
    {
        let mut size = 0;
        // RespType
        size += write_u8(writer, 1)?;
        // HiRespType
        size += write_u8(writer, 1)?;
        // Reserved1
        size += write_u16(writer, 0)?;
        // Reserved2
        size += write_u32(writer, 0)?;
        size += self.timestamp.serialize_into(writer)?;
        size += self.challenge_from_client.serialize_into(writer)?;
        // Reserved3
        size += write_u32(writer, 0)?;
        size += self.challenge_from_client.len();
        debug_assert_eq!(size, 28);
        size += self.target_infos.serialize_into(writer)?;

        Ok(size)
    }

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        let (rest, (timestamp, challenge_from_client, _reserved3, target_infos)) = context(
            "Ntv2Challenge",
            preceded(
                tuple((
                    context("RespType", verify(le_u8, |b| *b == 1)),
                    context("HiRespType", verify(le_u8, |b| *b == 1)),
                    context("Reserved1", verify(le_u16, |b| *b == 0)),
                    context("Reserved2", verify(le_u32, |b| *b == 0)),
                )),
                tuple((
                    FileTime::deserialize,
                    ClientChallenge::deserialize,
                    verify(le_u32, |b| *b == 0),
                    Vec::<AvPair>::deserialize,
                )),
            ),
        )(input)?;

        Ok((
            rest,
            Self {
                timestamp,
                challenge_from_client,
                target_infos,
            },
        ))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum NtChallenge {
    V1(Ntv1Challenge),
    V2(Ntv2Challenge),
}

impl Default for NtChallenge {
    fn default() -> Self {
        Self::V2(Default::default())
    }
}

impl From<Ntv1Challenge> for NtChallenge {
    fn from(c: Ntv1Challenge) -> Self {
        Self::V1(c)
    }
}

impl From<Ntv2Challenge> for NtChallenge {
    fn from(c: Ntv2Challenge) -> Self {
        Self::V2(c)
    }
}

impl<'a> Wire<'a> for NtChallenge {
    fn serialize_into<W>(&self, writer: &mut W) -> std::io::Result<usize>
    where
        W: std::io::Write,
    {
        match self {
            Self::V1(ref v1) => v1.serialize_into(writer),
            Self::V2(ref v2) => v2.serialize_into(writer),
        }
    }

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        alt((
            map(Ntv2Challenge::deserialize, |c| Self::V2(c)),
            map(Ntv1Challenge::deserialize, |c| Self::V1(c)),
        ))(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    #[test]
    fn size() {
        assert_eq!(size_of::<Ntv1Challenge>(), 24);
        assert!(size_of::<Ntv2Challenge>() >= 28);
    }
}
