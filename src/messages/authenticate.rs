use std::fmt;
use std::mem::size_of_val;

use nom::bytes::complete::{tag, take};
use nom::combinator::verify;
use nom::error::context;
use nom::number::complete::le_u32;
use nom::sequence::{preceded, tuple};

use crate::messages::{
    flags::{self, Flags},
    structures::{EncryptedRandomSessionKey, LmChallenge, NtChallenge},
    utils::write_u32,
    Field, NomError, Version, Wire, SIGNATURE,
};

const MESSAGE_TYPE: u32 = 0x00000003;

#[derive(Default, PartialEq, Eq)]
pub struct Authenticate {
    pub lm_challenge_response: Option<LmChallenge>,
    pub nt_challenge_response: Option<NtChallenge>,
    pub domain: Option<String>,
    pub user: Option<String>,
    pub workstation: Option<String>,
    encrypted_random_session_key: Option<EncryptedRandomSessionKey>,
    pub negociate_flags: Flags,
    pub version: Version,
    pub mic: [u8; 16],
}

impl Authenticate {
    pub fn set_encrypted_random_session_key(
        &mut self,
        encrypted_random_session_key: Option<EncryptedRandomSessionKey>,
    ) -> &mut Self {
        self.encrypted_random_session_key = encrypted_random_session_key;
        if self.encrypted_random_session_key.is_some() {
            self.negociate_flags
                .set_flag(flags::NTLMSSP_NEGOTIATE_KEY_EXCH);
        } else {
            self.negociate_flags
                .clear_flag(flags::NTLMSSP_NEGOTIATE_KEY_EXCH);
        }
        self
    }

    pub fn get_encrypted_random_session_key(&self) -> Option<&EncryptedRandomSessionKey> {
        self.encrypted_random_session_key.as_ref()
    }
}

impl fmt::Debug for Authenticate {
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

impl<'a> Wire<'a> for Authenticate {
    fn serialize_into<W>(&self, writer: &mut W) -> std::io::Result<usize>
    where
        W: std::io::Write,
    {
        const PAYLOAD_OFFSET: usize = 64;

        let mut written = 0;
        let mut payload = Vec::with_capacity(PAYLOAD_OFFSET * 2);
        payload.resize(PAYLOAD_OFFSET, 0);
        payload.extend_from_slice(&self.version[..]);
        payload.extend_from_slice(&self.mic[..]);

        writer.write_all(&SIGNATURE[..])?;
        written += &SIGNATURE[..].len();
        written += write_u32(writer, MESSAGE_TYPE)?;
        written += Field::append(self.lm_challenge_response.as_ref(), &mut payload, writer)?;
        written += Field::append(self.nt_challenge_response.as_ref(), &mut payload, writer)?;
        written += Field::append(self.domain.as_ref(), &mut payload, writer)?;
        written += Field::append(self.user.as_ref(), &mut payload, writer)?;
        written += Field::append(self.workstation.as_ref(), &mut payload, writer)?;
        written += Field::append(
            self.encrypted_random_session_key.as_ref(),
            &mut payload,
            writer,
        )?;
        written += self.negociate_flags.serialize_into(writer)?;

        assert_eq!(written, PAYLOAD_OFFSET);
        writer.write_all(&payload[PAYLOAD_OFFSET..])?;
        written += payload.len();

        Ok(written)
    }

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        let mut mic = [0u8; 16];

        let (
            _rest,
            (
                lm_challenge_response_field,
                nt_challenge_response_field,
                domain_field,
                user_field,
                workstation_field,
                encrypted_random_session_key_field,
                negociate_flags,
                version,
                mic_data,
            ),
        ) = context(
            "Authenticate",
            preceded(
                tuple((tag(SIGNATURE), verify(le_u32, |mt| *mt == MESSAGE_TYPE))),
                tuple((
                    Field::deserialize,
                    Field::deserialize,
                    Field::deserialize,
                    Field::deserialize,
                    Field::deserialize,
                    Field::deserialize,
                    Flags::deserialize,
                    Version::deserialize,
                    take(size_of_val(&mic)),
                )),
            ),
        )(input)?;

        mic.copy_from_slice(mic_data);
        let lm_challenge_response =
            dbg!(lm_challenge_response_field).get_data_if("lm_challenge_response", input, true)?;
        let nt_challenge_response =
            dbg!(nt_challenge_response_field).get_data_if("nt_challenge_response", input, true)?;
        let domain = domain_field.get_data_if("domain", input, true)?;
        let user = user_field.get_data_if("user", input, true)?;
        let workstation = workstation_field.get_data_if("workstation", input, true)?;
        let encrypted_random_session_key = encrypted_random_session_key_field.get_data_if(
            "encrypted_random_session_key",
            input,
            negociate_flags.has_flag(flags::NTLMSSP_NEGOTIATE_KEY_EXCH),
        )?;

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
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::structures::{Lmv1Challenge, Ntv1Challenge};

    #[test]
    fn decode() {
        let authenticate_message = Authenticate {
            lm_challenge_response: Some(LmChallenge::V1(Lmv1Challenge {
                response: [
                    101, 170, 123, 110, 103, 248, 74, 163, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0,
                ],
            })),
            nt_challenge_response: Some(NtChallenge::V1(Ntv1Challenge {
                response: [
                    170, 88, 221, 91, 155, 101, 92, 32, 127, 172, 61, 39, 230, 133, 201, 157, 122,
                    22, 58, 84, 180, 182, 248, 204,
                ],
            })),
            domain: Some("example".into()),
            user: Some("administrator".into()),
            workstation: Some("WANG_WENCHAO".into()),
            encrypted_random_session_key: None,
            negociate_flags: Flags(0xa2888205),
            version: Version::from([0x5, 0x1, 0x28, 0xa, 0x0, 0x0, 0x0, 0xf]),
            mic: [
                0x65, 0x0, 0x78, 0x0, 0x61, 0x0, 0x6d, 0x0, 0x70, 0x0, 0x6c, 0x0, 0x65, 0x0, 0x61,
                0x0,
            ],
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
            lm_challenge_response: Some(LmChallenge::V1(Lmv1Challenge {
                response: [
                    101, 170, 123, 110, 103, 248, 74, 163, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0,
                ],
            })),
            nt_challenge_response: Some(NtChallenge::V1(Ntv1Challenge {
                response: [
                    170, 88, 221, 91, 155, 101, 92, 32, 127, 172, 61, 39, 230, 133, 201, 157, 122,
                    22, 58, 84, 180, 182, 248, 204,
                ],
            })),
            domain: Some("example".into()),
            user: Some("administrator".into()),
            workstation: Some("WANG_WENCHAO".into()),
            encrypted_random_session_key: None,
            negociate_flags: Flags(0xa2888205),
            version: Version::from([0x5, 0x1, 0x28, 0xa, 0x0, 0x0, 0x0, 0xf]),
            mic: [
                0x65, 0x0, 0x78, 0x0, 0x61, 0x0, 0x6d, 0x0, 0x70, 0x0, 0x6c, 0x0, 0x65, 0x0, 0x61,
                0x0,
            ],
        };

        let ser = authenticate_message.serialize();
        pretty_assertions::assert_eq!(
            authenticate_message,
            Authenticate::deserialize::<nom::error::VerboseError<&[u8]>>(&ser[..])
                .unwrap()
                .1
        );
    }
}
