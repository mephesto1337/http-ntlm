use nom::bytes::complete::{tag, take};
use nom::combinator::verify;
use nom::error::context;
use nom::number::complete::{le_u32, le_u64};
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
        written += self.version.len();
        writer.write_all(&self.version[..])?;
        written += self.target_info.serialize_into(writer)?;
        writer.write_all(self.payload)?;
        debug_assert_eq!(written, Self::header_size());
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
                tuple((tag(SIGNATURE), verify(le_u32, |mt| *mt == MESSAGE_TYPE))),
                tuple((
                    Fields::deserialize,
                    le_u32,
                    le_u64,
                    verify(le_u64, |reserved| *reserved == 0),
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

    fn header_size() -> usize {
        56
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode() {
        let m = "TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAFASgKAAAADw==";
        let challenge_message = Challenge::default();
        let message = base64::decode(m).unwrap();
        let maybe_decoded_message =
            Challenge::deserialize::<nom::error::VerboseError<&[u8]>>(&message[..]);
        let (_, decoded_message) = maybe_decoded_message.unwrap();
        pretty_assertions::assert_eq!(decoded_message, challenge_message);
    }

    #[test]
    fn encode() {
        let m = "TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAFASgKAAAADw==";
        let challenge_message = Challenge::default();
        pretty_assertions::assert_eq!(base64::encode(challenge_message.serialize()), m);
    }

    #[test]
    fn encode_decode() {
        let m1 = Challenge::default();
        eprintln!("m1 = {:#x?}", m1);
        let ser = m1.serialize();
        let (rest, m2) = Challenge::deserialize::<nom::error::VerboseError<_>>(&ser[..]).unwrap();
        eprintln!("m2 = {:#x?}", m2);
        pretty_assertions::assert_eq!(rest.len(), 0);
        pretty_assertions::assert_eq!(m1, m2);
    }
}
