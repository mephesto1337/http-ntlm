use std::io;

use nom::branch::alt;
use nom::combinator::map;
use nom::error::context;
use nom::sequence::tuple;

use crate::{
    crypto::hmac_md5,
    messages::{
        structures::{ClientChallenge, Response16, Response24, ServerChallenge},
        NomError, Wire,
    },
};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Lmv1Challenge {
    pub response: Response24,
}

impl<'a> Wire<'a> for Lmv1Challenge {
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
        let (rest, response) = context("Lmv1Challenge", Response24::deserialize)(input)?;
        Ok((rest, Self { response }))
    }
}

impl Lmv1Challenge {
    pub fn from_client_challenge(client_challenge: &ClientChallenge) -> Self {
        let mut me = Self::default();
        (&mut me.response[..client_challenge.len()]).copy_from_slice(client_challenge);
        me
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Lmv2Challenge {
    pub response: Response16,
    pub challenge_from_client: ClientChallenge,
}

impl Lmv2Challenge {
    pub fn from_server_challenge(
        server_challenge: &ServerChallenge,
        nt_hash: &[u8],
        client_challenge: &ClientChallenge,
    ) -> Self {
        let mut challenge = [0u8; 16];
        let mut response = [0u8; 16];

        (&mut challenge[..8]).copy_from_slice(server_challenge);
        (&mut challenge[8..]).copy_from_slice(client_challenge);
        hmac_md5(nt_hash, &challenge[..], &mut response[..]);

        Self {
            response: response.into(),
            challenge_from_client: client_challenge.clone(),
        }
    }
}

impl<'a> Wire<'a> for Lmv2Challenge {
    fn serialize_into<W>(&self, writer: &mut W) -> io::Result<usize>
    where
        W: io::Write,
    {
        let mut size = self.response.serialize_into(writer)?;
        size += self.challenge_from_client.serialize_into(writer)?;
        Ok(size)
    }

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        let (rest, (response, challenge_from_client)) = context(
            "Lmv2Challenge",
            tuple((Response16::deserialize, ClientChallenge::deserialize)),
        )(input)?;

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
            map(Lmv2Challenge::deserialize, |c| Self::V2(c)),
            map(Lmv1Challenge::deserialize, |c| Self::V1(c)),
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
