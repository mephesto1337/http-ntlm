use std::io;
use std::mem::size_of_val;

use nom::branch::alt;
use nom::bytes::complete::take;
use nom::combinator::map;
use nom::error::context;
use nom::sequence::tuple;

use crate::messages::{NomError, Wire};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Lmv1Challenge {
    pub response: [u8; 24],
}

impl<'a> Wire<'a> for Lmv1Challenge {
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
        let (rest, data) = context("Lmv1Challenge", take(size_of_val(&response)))(input)?;
        response.copy_from_slice(data);
        Ok((rest, Self { response }))
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Lmv2Challenge {
    pub response: [u8; 16],
    pub challenge_from_client: [u8; 8],
}

impl<'a> Wire<'a> for Lmv2Challenge {
    fn serialize_into<W>(&self, writer: &mut W) -> io::Result<usize>
    where
        W: io::Write,
    {
        writer.write_all(&self.response[..])?;
        writer.write_all(&self.challenge_from_client[..])?;
        Ok(self.response.len() + self.challenge_from_client.len())
    }

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        let mut response = [0u8; 16];
        let mut challenge_from_client = [0u8; 8];

        let (rest, (response_data, challenge_from_client_data)) = context(
            "Lmv2Challenge",
            tuple((
                take(size_of_val(&response)),
                take(size_of_val(&challenge_from_client)),
            )),
        )(input)?;

        response.copy_from_slice(response_data);
        challenge_from_client.copy_from_slice(challenge_from_client_data);

        Ok((
            rest,
            Self {
                response,
                challenge_from_client,
            },
        ))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum LmChallenge {
    V1(Lmv1Challenge),
    V2(Lmv2Challenge),
}

impl Default for LmChallenge {
    fn default() -> Self {
        Self::V2(Default::default())
    }
}

impl From<Lmv1Challenge> for LmChallenge {
    fn from(c: Lmv1Challenge) -> Self {
        Self::V1(c)
    }
}

impl From<Lmv2Challenge> for LmChallenge {
    fn from(c: Lmv2Challenge) -> Self {
        Self::V2(c)
    }
}

impl<'a> Wire<'a> for LmChallenge {
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
            map(Lmv1Challenge::deserialize, |c| Self::V1(c)),
            map(Lmv2Challenge::deserialize, |c| Self::V2(c)),
        ))(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    #[test]
    fn size() {
        assert_eq!(size_of::<Lmv1Challenge>(), 24);
        assert_eq!(size_of::<Lmv2Challenge>(), 24);
    }
}
