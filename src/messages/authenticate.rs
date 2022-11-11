use nom::bytes::complete::{tag, take};
use nom::combinator::verify;
use nom::error::context;
use nom::number::complete::le_u32;
use nom::sequence::{preceded, tuple};

use super::{
    utils::{write_u32, Fields},
    Wire, SIGNATURE,
};

const MESSAGE_TYPE: u32 = 0x00000003;

#[derive(Default, Debug, PartialEq, Eq)]
pub struct Authenticate<'a> {
    pub lm_challenge_response: Fields,
    pub nt_challenge_response: Fields,
    pub domain: Fields,
    pub user: Fields,
    pub workstation: Fields,
    pub encrypted_random_session_key: Fields,
    pub negociate_flags: u32,
    pub version: [u8; 8],
    pub mic: [u8; 16],
    pub payload: &'a [u8],
}

impl<'a> Wire<'a> for Authenticate<'a> {
    fn serialize_into<W>(&self, writer: &mut W) -> std::io::Result<usize>
    where
        W: std::io::Write,
    {
        let mut written = 0;
        writer.write_all(&SIGNATURE[..])?;
        written += &SIGNATURE[..].len();
        written += write_u32(writer, MESSAGE_TYPE)?;
        written += self.lm_challenge_response.serialize_into(writer)?;
        written += self.nt_challenge_response.serialize_into(writer)?;
        written += self.domain.serialize_into(writer)?;
        written += self.user.serialize_into(writer)?;
        written += self.workstation.serialize_into(writer)?;
        written += self.encrypted_random_session_key.serialize_into(writer)?;
        written += write_u32(writer, self.negociate_flags)?;
        writer.write_all(&self.version[..])?;
        written += self.version.len();
        writer.write_all(&self.mic[..])?;
        written += self.mic.len();
        debug_assert_eq!(written, Self::header_size());
        writer.write_all(self.payload)?;
        written += self.payload.len();

        Ok(written)
    }

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: super::NomError<'a>,
    {
        let mut version = [0u8; 8];
        let mut mic = [0u8; 16];

        let (
            payload,
            (
                lm_challenge_response,
                nt_challenge_response,
                domain,
                user,
                workstation,
                encrypted_random_session_key,
                negociate_flags,
                version_data,
                mic_data,
            ),
        ) = context(
            "Authenticate",
            preceded(
                tuple((tag(SIGNATURE), verify(le_u32, |mt| *mt == MESSAGE_TYPE))),
                tuple((
                    Fields::deserialize,
                    Fields::deserialize,
                    Fields::deserialize,
                    Fields::deserialize,
                    Fields::deserialize,
                    Fields::deserialize,
                    le_u32,
                    take(std::mem::size_of_val(&version)),
                    take(std::mem::size_of_val(&mic)),
                )),
            ),
        )(input)?;

        version.copy_from_slice(&version_data[..]);
        mic.copy_from_slice(&mic_data[..]);
        Ok((
            &b""[..],
            Self {
                lm_challenge_response,
                nt_challenge_response,
                domain,
                user,
                workstation,
                encrypted_random_session_key,
                negociate_flags,
                version,
                mic,
                payload,
            },
        ))
    }

    fn header_size() -> usize {
        88
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode() {
        let authenticate_message = Authenticate {
            lm_challenge_response: Fields {
                len: 0x18,
                max_len: 0x18,
                offset: 0x88,
            },
            nt_challenge_response: Fields {
                len: 0x18,
                max_len: 0x18,
                offset: 0xa0,
            },
            domain: Fields {
                len: 0xe,
                max_len: 0xe,
                offset: 0x48,
            },
            user: Fields {
                len: 0x1a,
                max_len: 0x1a,
                offset: 0x56,
            },
            workstation: Fields {
                len: 0x18,
                max_len: 0x18,
                offset: 0x70,
            },
            encrypted_random_session_key: Fields {
                len: 0x0,
                max_len: 0x0,
                offset: 0xb8,
            },
            negociate_flags: 0xa2888205,
            version: [0x5, 0x1, 0x28, 0xa, 0x0, 0x0, 0x0, 0xf],
            mic: [
                0x65, 0x0, 0x78, 0x0, 0x61, 0x0, 0x6d, 0x0, 0x70, 0x0, 0x6c, 0x0, 0x65, 0x0, 0x61,
                0x0,
            ],
            payload: &[
                0x64, 0x0, 0x6d, 0x0, 0x69, 0x0, 0x6e, 0x0, 0x69, 0x0, 0x73, 0x0, 0x74, 0x0, 0x72,
                0x0, 0x61, 0x0, 0x74, 0x0, 0x6f, 0x0, 0x72, 0x0, 0x57, 0x0, 0x41, 0x0, 0x4e, 0x0,
                0x47, 0x0, 0x5f, 0x0, 0x57, 0x0, 0x45, 0x0, 0x4e, 0x0, 0x43, 0x0, 0x48, 0x0, 0x41,
                0x0, 0x4f, 0x0, 0x65, 0xaa, 0x7b, 0x6e, 0x67, 0xf8, 0x4a, 0xa3, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xaa, 0x58, 0xdd, 0x5b,
                0x9b, 0x65, 0x5c, 0x20, 0x7f, 0xac, 0x3d, 0x27, 0xe6, 0x85, 0xc9, 0x9d, 0x7a, 0x16,
                0x3a, 0x54, 0xb4, 0xb6, 0xf8, 0xcc,
            ][..],
        };

        let m = "TlRMTVNTUAADAAAAGAAYAIgAAAAYABgAoAAAAA4ADgBIAAAAGgAaAFYAAAAYABgAcAAAAAAAAAC4AAAABYKIogUBKAoAAAAPZQB4AGEAbQBwAGwAZQBhAGQAbQBpAG4AaQBzAHQAcgBhAHQAbwByAFcAQQBOAEcAXwBXAEUATgBDAEgAQQBPAGWqe25n+EqjAAAAAAAAAAAAAAAAAAAAAKpY3VubZVwgf6w9J+aFyZ16FjpUtLb4zA==";
        let message = base64::decode_config(m, base64::STANDARD).unwrap();
        let maybe_decoded_message =
            Authenticate::deserialize::<nom::error::VerboseError<&[u8]>>(&message[..]);
        eprintln!("maybe_decoded_message = {:#x?}", maybe_decoded_message);
        let (_, decoded_message) = maybe_decoded_message.unwrap();
        pretty_assertions::assert_eq!(decoded_message, authenticate_message);
    }

    #[test]
    fn encode() {
        let authenticate_message = Authenticate {
            lm_challenge_response: Fields {
                len: 0x18,
                max_len: 0x18,
                offset: 0x88,
            },
            nt_challenge_response: Fields {
                len: 0x18,
                max_len: 0x18,
                offset: 0xa0,
            },
            domain: Fields {
                len: 0xe,
                max_len: 0xe,
                offset: 0x48,
            },
            user: Fields {
                len: 0x1a,
                max_len: 0x1a,
                offset: 0x56,
            },
            workstation: Fields {
                len: 0x18,
                max_len: 0x18,
                offset: 0x70,
            },
            encrypted_random_session_key: Fields {
                len: 0x0,
                max_len: 0x0,
                offset: 0xb8,
            },
            negociate_flags: 0xa2888205,
            version: [0x5, 0x1, 0x28, 0xa, 0x0, 0x0, 0x0, 0xf],
            mic: [
                0x65, 0x0, 0x78, 0x0, 0x61, 0x0, 0x6d, 0x0, 0x70, 0x0, 0x6c, 0x0, 0x65, 0x0, 0x61,
                0x0,
            ],
            payload: &[
                0x64, 0x0, 0x6d, 0x0, 0x69, 0x0, 0x6e, 0x0, 0x69, 0x0, 0x73, 0x0, 0x74, 0x0, 0x72,
                0x0, 0x61, 0x0, 0x74, 0x0, 0x6f, 0x0, 0x72, 0x0, 0x57, 0x0, 0x41, 0x0, 0x4e, 0x0,
                0x47, 0x0, 0x5f, 0x0, 0x57, 0x0, 0x45, 0x0, 0x4e, 0x0, 0x43, 0x0, 0x48, 0x0, 0x41,
                0x0, 0x4f, 0x0, 0x65, 0xaa, 0x7b, 0x6e, 0x67, 0xf8, 0x4a, 0xa3, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xaa, 0x58, 0xdd, 0x5b,
                0x9b, 0x65, 0x5c, 0x20, 0x7f, 0xac, 0x3d, 0x27, 0xe6, 0x85, 0xc9, 0x9d, 0x7a, 0x16,
                0x3a, 0x54, 0xb4, 0xb6, 0xf8, 0xcc,
            ][..],
        };
        let message_base64 = "TlRMTVNTUAADAAAAGAAYAIgAAAAYABgAoAAAAA4ADgBIAAAAGgAaAFYAAAAYABgAcAAAAAAAAAC4AAAABYKIogUBKAoAAAAPZQB4AGEAbQBwAGwAZQBhAGQAbQBpAG4AaQBzAHQAcgBhAHQAbwByAFcAQQBOAEcAXwBXAEUATgBDAEgAQQBPAGWqe25n+EqjAAAAAAAAAAAAAAAAAAAAAKpY3VubZVwgf6w9J+aFyZ16FjpUtLb4zA==";
        pretty_assertions::assert_eq!(
            base64::encode(authenticate_message.serialize()),
            message_base64
        );
    }

    #[test]
    fn encode_decode() {
        let m1 = Authenticate::default();
        let ser = m1.serialize();
        let (rest, m2) =
            Authenticate::deserialize::<nom::error::VerboseError<_>>(&ser[..]).unwrap();
        pretty_assertions::assert_eq!(rest.len(), 0);
        pretty_assertions::assert_eq!(m1, m2);
    }
}
