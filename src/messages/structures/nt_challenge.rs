use std::io;
use std::mem::size_of_val;

use nom::bytes::complete::take;
use nom::combinator::{map, verify};
use nom::error::context;
use nom::number::complete::{le_u16, le_u32, le_u8};
use nom::sequence::{preceded, tuple};

use crate::messages::{
    structures::{AvPair, FileTime},
    utils::write_u32,
    NomError, Wire,
};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Ntv1Challenge {
    pub response: [u8; 24],
}

impl<'a> Wire<'a> for Ntv1Challenge {
    fn serialize_into<W>(&self, writer: &mut W) -> io::Result<usize>
    where
        W: io::Write,
    {
        writer.write_all(&self.response[..])?;
        Ok(self.response.len())
    }

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        let mut response = [0u8; 24];
        let (rest, data) = context("Ntv1Challenge", take(size_of_val(&response)))(input)?;
        response.copy_from_slice(data);
        Ok((rest, Self { response }))
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Ntv2Challenge {
    pub timestamp: FileTime,
    pub challenge_from_client: [u8; 8],
    pub av_pairs: Vec<AvPair>,
}

impl<'a> Wire<'a> for Ntv2Challenge {
    fn serialize_into<W>(&self, writer: &mut W) -> io::Result<usize>
    where
        W: io::Write,
    {
        // [RespType, HiRespType, Reserved1]
        writer.write_all(&[1, 1, 0, 0][..])?;
        // Reserved2
        write_u32(writer, 0)?;
        self.timestamp.serialize_into(writer)?;
        writer.write_all(&self.challenge_from_client[..])?;
        let mut size = 28;
        size += self.av_pairs.serialize_into(writer)?;

        Ok(size)
    }

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        let mut challenge_from_client = [0u8; 8];

        let (rest, (timestamp, challenge_from_client_data, _reserved3, av_pairs)) =
            context(
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
                        take(size_of_val(&challenge_from_client)),
                        verify(le_u32, |b| *b == 0),
                        Vec::<AvPair>::deserialize,
                    )),
                ),
            )(input)?;

        challenge_from_client.copy_from_slice(challenge_from_client_data);

        Ok((
            rest,
            Self {
                timestamp,
                challenge_from_client,
                av_pairs,
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
        Self::V1(Default::default())
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
        map(Ntv1Challenge::deserialize, |c| Self::V1(c))(input)
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
