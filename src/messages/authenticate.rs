use std::fmt;

use nom::bytes::complete::tag;
use nom::combinator::verify;
use nom::error::context;
use nom::number::complete::le_u32;
use nom::sequence::{preceded, tuple};

use crate::messages::{
    flags::{self, Flags},
    structures::{
        LmChallenge, Lmv1Challenge, Lmv2Challenge, NtChallenge, Ntv1Challenge, Ntv2Challenge,
    },
    utils::{write_u32, Fields},
    NomError, Wire, SIGNATURE,
};

const MESSAGE_TYPE: u32 = 0x00000003;

#[derive(Default, PartialEq, Eq)]
pub struct Authenticate<'a> {
    pub lm_challenge_response_field: Fields,
    pub lm_challenge_response: Option<LmChallenge>,
    pub nt_challenge_response_field: Fields,
    pub nt_challenge_response: Option<NtChallenge>,
    pub domain_field: Fields,
    pub domain: Option<String>,
    pub user_field: Fields,
    pub user: Option<String>,
    pub workstation_field: Fields,
    pub workstation: Option<String>,
    pub encrypted_random_session_key_field: Fields,
    pub encrypted_random_session_key: Option<&'a [u8]>,
    pub negociate_flags: Flags,
    pub payload: &'a [u8],
}

impl fmt::Debug for Authenticate<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authenticate")
            .field("lm_challenge_response", &self.lm_challenge_response)
            .field("nt_challenge_response", &self.nt_challenge_response)
            .field("domain", &self.domain)
            .field("user", &self.user)
            .field("workstation", &self.workstation)
            .field(
                "encrypted_random_session_key",
                &self.encrypted_random_session_key,
            )
            .field("negociate_flags", &self.negociate_flags)
            .finish()
    }
}

impl<'a> Authenticate<'a> {
    pub fn version(&'a self) -> &'a [u8] {
        &self.payload[..8]
    }

    pub fn mic(&'a self) -> &'a [u8] {
        &self.payload[8..][..16]
    }
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
        written += self.lm_challenge_response_field.serialize_into(writer)?;
        written += self.nt_challenge_response_field.serialize_into(writer)?;
        written += self.domain_field.serialize_into(writer)?;
        written += self.user_field.serialize_into(writer)?;
        written += self.workstation_field.serialize_into(writer)?;
        written += self
            .encrypted_random_session_key_field
            .serialize_into(writer)?;
        written += self.negociate_flags.serialize_into(writer)?;

        debug_assert_eq!(written, 64);
        writer.write_all(self.payload)?;
        written += self.payload.len();

        Ok(written)
    }

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        let (
            payload,
            (
                lm_challenge_response_field,
                nt_challenge_response_field,
                domain_field,
                user_field,
                workstation_field,
                encrypted_random_session_key_field,
                negociate_flags,
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
                    Flags::deserialize,
                )),
            ),
        )(input)?;

        let (lm_challenge_response, nt_challenge_response): (
            Option<LmChallenge>,
            Option<NtChallenge>,
        ) = if negociate_flags.has_flag(flags::NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) {
            let (_rest, lm_challenge) = context("Lmv2Challenge", |i| {
                lm_challenge_response_field.get_data::<Lmv2Challenge, E>(i)
            })(input)?;
            let (_rest, nt_challenge) = context("Ntv2Challenge", |i| {
                nt_challenge_response_field.get_data::<Ntv2Challenge, E>(i)
            })(input)?;
            (
                lm_challenge.map(|c| c.into()),
                nt_challenge.map(|c| c.into()),
            )
        } else if negociate_flags.has_flag(flags::NTLMSSP_NEGOTIATE_NTLM) {
            let (_rest, lm_challenge) = context("Lmv1Challenge", |i| {
                lm_challenge_response_field.get_data::<Lmv1Challenge, E>(i)
            })(input)?;
            let (_rest, nt_challenge) = context("Ntv1Challenge", |i| {
                nt_challenge_response_field.get_data::<Ntv1Challenge, E>(i)
            })(input)?;
            (
                lm_challenge.map(|c| c.into()),
                nt_challenge.map(|c| c.into()),
            )
        } else {
            let (_rest, lm_challenge) = context("Lmv2Challenge", |i| {
                lm_challenge_response_field.get_data::<Lmv2Challenge, E>(i)
            })(input)?;
            let (_rest, nt_challenge) = context("Ntv2Challenge", |i| {
                nt_challenge_response_field.get_data::<Ntv2Challenge, E>(i)
            })(input)?;
            (
                lm_challenge.map(|c| c.into()),
                nt_challenge.map(|c| c.into()),
            )
            // let flags_data = &input[60..][..4];
            // return Err(nom::Err::Error(E::add_context(
            //     flags_data,
            //     "Invalid flags",
            //     E::from_error_kind(flags_data, nom::error::ErrorKind::Verify),
            // )));
        };

        let (_rest, domain) = context("domain", |i| domain_field.get_data(i))(input)?;
        let (_rest, user) = context("user", |i| user_field.get_data(i))(input)?;
        let (_rest, workstation) =
            context("workstation", |i| workstation_field.get_data(i))(input)?;
        let encrypted_random_session_key = if encrypted_random_session_key_field.len == 0 {
            None
        } else {
            Some(&input[encrypted_random_session_key_field.get_range()])
        };

        Ok((
            &b""[..],
            Self {
                lm_challenge_response_field,
                lm_challenge_response,
                nt_challenge_response_field,
                nt_challenge_response,
                domain_field,
                domain,
                user_field,
                user,
                workstation_field,
                workstation,
                encrypted_random_session_key_field,
                encrypted_random_session_key,
                negociate_flags,
                payload,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode() {
        let authenticate_message = Authenticate {
            lm_challenge_response_field: Fields {
                len: 0x18,
                max_len: 0x18,
                offset: 0x88,
            },
            lm_challenge_response: Some(LmChallenge::V2(Lmv2Challenge {
                response: [
                    101, 170, 123, 110, 103, 248, 74, 163, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
                challenge_from_client: [0, 0, 0, 0, 0, 0, 0, 0],
            })),
            nt_challenge_response_field: Fields {
                len: 0x18,
                max_len: 0x18,
                offset: 0xa0,
            },
            nt_challenge_response: None,
            domain_field: Fields {
                len: 0xe,
                max_len: 0xe,
                offset: 0x48,
            },
            domain: Some("example".into()),
            user_field: Fields {
                len: 0x1a,
                max_len: 0x1a,
                offset: 0x56,
            },
            user: Some("administrator".into()),
            workstation_field: Fields {
                len: 0x18,
                max_len: 0x18,
                offset: 0x70,
            },
            workstation: Some("WANG_WENCHAO".into()),
            encrypted_random_session_key_field: Fields {
                len: 0x0,
                max_len: 0x0,
                offset: 0xb8,
            },
            encrypted_random_session_key: None,
            negociate_flags: Flags(0xa2888205),
            payload: &[
                0x5, 0x1, 0x28, 0xa, 0x0, 0x0, 0x0, 0xf, 0x65, 0x0, 0x78, 0x0, 0x61, 0x0, 0x6d,
                0x0, 0x70, 0x0, 0x6c, 0x0, 0x65, 0x0, 0x61, 0x0, 0x64, 0x0, 0x6d, 0x0, 0x69, 0x0,
                0x6e, 0x0, 0x69, 0x0, 0x73, 0x0, 0x74, 0x0, 0x72, 0x0, 0x61, 0x0, 0x74, 0x0, 0x6f,
                0x0, 0x72, 0x0, 0x57, 0x0, 0x41, 0x0, 0x4e, 0x0, 0x47, 0x0, 0x5f, 0x0, 0x57, 0x0,
                0x45, 0x0, 0x4e, 0x0, 0x43, 0x0, 0x48, 0x0, 0x41, 0x0, 0x4f, 0x0, 0x65, 0xaa, 0x7b,
                0x6e, 0x67, 0xf8, 0x4a, 0xa3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xaa, 0x58, 0xdd, 0x5b, 0x9b, 0x65, 0x5c, 0x20, 0x7f,
                0xac, 0x3d, 0x27, 0xe6, 0x85, 0xc9, 0x9d, 0x7a, 0x16, 0x3a, 0x54, 0xb4, 0xb6, 0xf8,
                0xcc,
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
            lm_challenge_response_field: Fields {
                len: 0x18,
                max_len: 0x18,
                offset: 0x88,
            },
            lm_challenge_response: Some(LmChallenge::V2(Lmv2Challenge {
                response: [
                    101, 170, 123, 110, 103, 248, 74, 163, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
                challenge_from_client: [0, 0, 0, 0, 0, 0, 0, 0],
            })),
            nt_challenge_response_field: Fields {
                len: 0x18,
                max_len: 0x18,
                offset: 0xa0,
            },
            nt_challenge_response: None,
            domain_field: Fields {
                len: 0xe,
                max_len: 0xe,
                offset: 0x48,
            },
            domain: Some("example".into()),
            user_field: Fields {
                len: 0x1a,
                max_len: 0x1a,
                offset: 0x56,
            },
            user: Some("administrator".into()),
            workstation_field: Fields {
                len: 0x18,
                max_len: 0x18,
                offset: 0x70,
            },
            workstation: Some("WANG_WENCHAO".into()),
            encrypted_random_session_key_field: Fields {
                len: 0x0,
                max_len: 0x0,
                offset: 0xb8,
            },
            encrypted_random_session_key: None,
            negociate_flags: Flags(0xa2888205),
            payload: &[
                0x5, 0x1, 0x28, 0xa, 0x0, 0x0, 0x0, 0xf, 0x65, 0x0, 0x78, 0x0, 0x61, 0x0, 0x6d,
                0x0, 0x70, 0x0, 0x6c, 0x0, 0x65, 0x0, 0x61, 0x0, 0x64, 0x0, 0x6d, 0x0, 0x69, 0x0,
                0x6e, 0x0, 0x69, 0x0, 0x73, 0x0, 0x74, 0x0, 0x72, 0x0, 0x61, 0x0, 0x74, 0x0, 0x6f,
                0x0, 0x72, 0x0, 0x57, 0x0, 0x41, 0x0, 0x4e, 0x0, 0x47, 0x0, 0x5f, 0x0, 0x57, 0x0,
                0x45, 0x0, 0x4e, 0x0, 0x43, 0x0, 0x48, 0x0, 0x41, 0x0, 0x4f, 0x0, 0x65, 0xaa, 0x7b,
                0x6e, 0x67, 0xf8, 0x4a, 0xa3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xaa, 0x58, 0xdd, 0x5b, 0x9b, 0x65, 0x5c, 0x20, 0x7f,
                0xac, 0x3d, 0x27, 0xe6, 0x85, 0xc9, 0x9d, 0x7a, 0x16, 0x3a, 0x54, 0xb4, 0xb6, 0xf8,
                0xcc,
            ][..],
        };

        let message_base64 = "TlRMTVNTUAADAAAAGAAYAIgAAAAYABgAoAAAAA4ADgBIAAAAGgAaAFYAAAAYABgAcAAAAAAAAAC4AAAABYKIogUBKAoAAAAPZQB4AGEAbQBwAGwAZQBhAGQAbQBpAG4AaQBzAHQAcgBhAHQAbwByAFcAQQBOAEcAXwBXAEUATgBDAEgAQQBPAGWqe25n+EqjAAAAAAAAAAAAAAAAAAAAAKpY3VubZVwgf6w9J+aFyZ16FjpUtLb4zA==";
        pretty_assertions::assert_eq!(
            base64::encode(authenticate_message.serialize()),
            message_base64
        );
    }

    // #[test]
    // fn encode_decode() {
    //     let m1 = Authenticate::default();
    //     let ser = m1.serialize();
    //     let (rest, m2) =
    //         Authenticate::deserialize::<nom::error::VerboseError<_>>(&ser[..]).unwrap();
    //     pretty_assertions::assert_eq!(rest.len(), 0);
    //     pretty_assertions::assert_eq!(m1, m2);
    // }
}
