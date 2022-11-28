use nom::bytes::complete::tag;
use nom::combinator::{cond, verify};
use nom::error::context;
use nom::number::complete::le_u32;
use nom::sequence::{preceded, tuple};

use crate::{
    crypto::hmac_md5,
    messages::{
        flags::{self, Flags},
        structures::{
            EncryptedRandomSessionKey, ExportedSessionKey, LmChallenge, Mic, NtChallenge, Version,
        },
        utils::write_u32,
        Challenge, Field, Negotiate, NomError, Wire, SIGNATURE,
    },
};

const MESSAGE_TYPE: u32 = 0x00000003;

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct Authenticate {
    pub lm_challenge_response: Option<LmChallenge>,
    pub nt_challenge_response: Option<NtChallenge>,
    pub domain: Option<String>,
    pub user: Option<String>,
    pub workstation: Option<String>,
    encrypted_random_session_key: Option<EncryptedRandomSessionKey>,
    pub negociate_flags: Flags,
    pub version: Option<Version>,
    pub mic: Mic,
    pub exported_session_key: Option<ExportedSessionKey>,
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

    pub fn compute_mic(&mut self, negociate: &Negotiate, challenge: &Challenge) {
        if let Some(exported_session_key) = self.exported_session_key.as_ref() {
            let mut buffer = Vec::with_capacity(256);
            self.mic = Mic::default();
            negociate.serialize_into(&mut buffer).unwrap();
            challenge.serialize_into(&mut buffer).unwrap();
            self.serialize_into(&mut buffer).unwrap();
            hmac_md5(&exported_session_key[..], &buffer[..], &mut self.mic[..]);
        } else {
            log::warn!("Cannot compute MIC as there is no `exported_session_key`.");
        }
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
        if let Some(ref version) = self.version {
            version.serialize_into(&mut payload).unwrap();
        }

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
        let (
            rest,
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
                    context("lm_challenge", Field::deserialize),
                    context("nt_challenge", Field::deserialize),
                    context("domain_field", Field::deserialize),
                    context("user_field", Field::deserialize),
                    context("workstation_field", Field::deserialize),
                    context("encrypted_random_session_key_field", Field::deserialize),
                    Flags::deserialize,
                )),
            ),
        )(input)?;
        let (rest, version) = cond(
            negociate_flags.has_flag(flags::NTLMSSP_NEGOTIATE_VERSION),
            context("Authenticate/version", Version::deserialize),
        )(rest)?;
        let (_, mic) = context("Authenticate/mic", Mic::deserialize)(rest)?;

        let lm_challenge_response =
            lm_challenge_response_field.get_data_if("lm_challenge_response", input, true)?;
        let nt_challenge_response =
            nt_challenge_response_field.get_data_if("nt_challenge_response", input, true)?;
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
                exported_session_key: None,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::structures::{FileTime, Lmv2Challenge, Ntv2Challenge};

    #[test]
    fn decode() {
        let authenticate_message = Authenticate {
            lm_challenge_response: Some(LmChallenge::V2(Lmv2Challenge {
                response: [
                    101, 170, 123, 110, 103, 248, 74, 163, 0, 0, 0, 0, 0, 0, 0, 0,
                ]
                .into(),
                challenge_from_client: [0, 0, 0, 0, 0, 0, 0, 0].into(),
            })),
            nt_challenge_response: Some(NtChallenge::V2(Ntv2Challenge {
                timestamp: FileTime {
                    low: 1299703936,
                    high: 388659,
                },
                challenge_from_client: [0, 1, 2, 3, 4, 5, 6, 7].into(),
                target_infos: Vec::new(),
            })),
            domain: Some("example".into()),
            user: Some("administrator".into()),
            workstation: Some("WANG_WENCHAO".into()),
            encrypted_random_session_key: None,
            negociate_flags: Flags(0xa2888205),
            version: Some(Version {
                major: 5,
                minor: 1,
                build: 0x0a28,
                revision_count: 0x0f,
            }),
            mic: [
                0x65, 0x0, 0x78, 0x0, 0x61, 0x0, 0x6d, 0x0, 0x70, 0x0, 0x6c, 0x0, 0x65, 0x0, 0x61,
                0x0,
            ]
            .into(),
            exported_session_key: None,
        };

        let m = "TlRMTVNTUAADAAAAGAAYAFgAAAAcABwAcAAAAA4ADgCMAAAAGgAaAJoAAAAYABgAtAAAAAAAAAAAAAAABYKIogUBKAoAAAAPZQB4AGEAbQBwAGwAZQBhAGWqe25n+EqjAAAAAAAAAAAAAAAAAAAAAAEBAAAAAAAAgOh3TTPuBQAAAQIDBAUGBwAAAABlAHgAYQBtAHAAbABlAGEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAVwBBAE4ARwBfAFcARQBOAEMASABBAE8A";
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
            lm_challenge_response: Some(LmChallenge::V2(Lmv2Challenge {
                response: [
                    0x86, 0xc3, 0x50, 0x97, 0xac, 0x9c, 0xec, 0x10, 0x25, 0x54, 0x76, 0x4a, 0x57,
                    0xcc, 0xcc, 0x19,
                ]
                .into(),
                challenge_from_client: [0, 0, 0, 0, 0, 0, 0, 0].into(),
            })),
            nt_challenge_response: Some(NtChallenge::V2(Ntv2Challenge {
                timestamp: FileTime {
                    low: 1299703936,
                    high: 388659,
                },
                challenge_from_client: [0, 1, 2, 3, 4, 5, 6, 7].into(),
                target_infos: Vec::new(),
            })),
            domain: Some("example".into()),
            user: Some("administrator".into()),
            workstation: Some("WANG_WENCHAO".into()),
            encrypted_random_session_key: None,
            negociate_flags: Flags(0xa2888205),
            version: Some(Version {
                major: 5,
                minor: 1,
                build: 0x0a28,
                revision_count: 0x0f,
            }),
            mic: [
                0x65, 0x0, 0x78, 0x0, 0x61, 0x0, 0x6d, 0x0, 0x70, 0x0, 0x6c, 0x0, 0x65, 0x0, 0x61,
                0x0,
            ]
            .into(),
            exported_session_key: None,
        };

        let ser = authenticate_message.serialize();
        eprintln!("b64 = {}", base64::encode(&ser[..]));
        pretty_assertions::assert_eq!(
            authenticate_message,
            Authenticate::deserialize::<nom::error::VerboseError<&[u8]>>(&ser[..])
                .unwrap()
                .1
        );
    }
}
