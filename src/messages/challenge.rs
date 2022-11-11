use nom::bytes::complete::{tag, take};
use nom::combinator::verify;
use nom::error::context;
use nom::number::complete::{be_u32, be_u64};
use nom::sequence::{preceded, tuple};

use super::{
    utils::{write_u32, write_u64, Fields},
    Wire, SIGNATURE,
};

const MESSAGE_TYPE: u32 = 0x00000002;

#[derive(Default, Debug, PartialEq, Eq)]
pub struct Challenge<'a> {
    pub target_name: Fields,
    pub negociate_flags: u32,
    pub server_challenge: u64,
    pub target_info: Fields,
    pub version: [u8; 8],
    pub payload: &'a [u8],
}

impl<'a> Wire<'a> for Challenge<'a> {
    fn serialize_into<W>(&self, writer: &mut W) -> std::io::Result<usize>
    where
        W: std::io::Write,
    {
        let mut written = 0;
        writer.write_all(&SIGNATURE[..])?;
        written += &SIGNATURE[..].len();
        written += write_u32(writer, MESSAGE_TYPE)?;
        written += self.target_name.serialize_into(writer)?;
        written += write_u32(writer, self.negociate_flags)?;
        written += write_u64(writer, self.server_challenge)?;
        written += write_u64(writer, 0)?;
        written += self.target_info.serialize_into(writer)?;
        writer.write_all(self.payload)?;
        written += self.payload.len();

        Ok(written)
    }

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: super::NomError<'a>,
    {
        let mut version = [0u8; 8];

        let (
            payload,
            (
                target_name,
                negociate_flags,
                server_challenge,
                _reserved,
                target_info,
                version_content,
            ),
        ) = context(
            "Challenge",
            preceded(
                tuple((tag(SIGNATURE), verify(be_u32, |mt| *mt == MESSAGE_TYPE))),
                tuple((
                    Fields::deserialize,
                    be_u32,
                    be_u64,
                    verify(be_u64, |reserved| *reserved == 0),
                    Fields::deserialize,
                    take(std::mem::size_of_val(&version)),
                )),
            ),
        )(input)?;

        version.copy_from_slice(version_content);
        Ok((
            &b""[..],
            Self {
                target_name,
                negociate_flags,
                server_challenge,
                target_info,
                version,
                payload,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_message() {
        let m = "yNY3lb6a0L6vVQEZNqwQn0s8UNew33KdKZvG+Onv";
        let message = base64::decode_config(m, base64::STANDARD).unwrap();
        let (_, decoded_message) =
            Challenge::deserialize::<nom::error::VerboseError<&[u8]>>(&message[..]).unwrap();
        assert_eq!(decoded_message, Challenge::default());
    }
}
