use std::fmt;

use nom::bytes::complete::tag;
use nom::combinator::verify;
use nom::error::context;
use nom::number::complete::{le_u32, le_u64};
use nom::sequence::{preceded, tuple};

use super::{
    flags::{self, Flags},
    structures::AvPair,
    utils::{write_u32, write_u64},
    Field, Version, Wire, SIGNATURE,
};

const MESSAGE_TYPE: u32 = 0x00000002;

#[derive(Default, PartialEq, Eq)]
pub struct Challenge {
    pub target_name: Option<String>,
    pub negociate_flags: Flags,
    pub server_challenge: u64,
    pub target_infos: Vec<AvPair>,
    pub version: Version,
}

impl fmt::Debug for Challenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Challenge")
            .field("target_name", &self.target_name)
            .field("negociate_flags", &self.negociate_flags)
            .field("server_challenge", &self.server_challenge)
            .field("target_infos", &self.target_infos)
            .finish()
    }
}

impl<'a> Wire<'a> for Challenge {
    fn serialize_into<W>(&self, writer: &mut W) -> std::io::Result<usize>
    where
        W: std::io::Write,
    {
        const PAYLOAD_OFFSET: usize = 48;

        let mut payload = Vec::with_capacity(PAYLOAD_OFFSET * 2);
        payload.resize(PAYLOAD_OFFSET, 0);
        let mut written = 0;

        self.version.serialize_into(&mut payload)?;

        payload.extend_from_slice(&self.version[..]);

        writer.write_all(&SIGNATURE[..])?;
        written += &SIGNATURE[..].len();
        written += write_u32(writer, MESSAGE_TYPE)?;
        written += Field::append(self.target_name.as_ref(), &mut payload, writer)?;
        written += self.negociate_flags.serialize_into(writer)?;
        written += write_u64(writer, self.server_challenge)?;
        written += write_u64(writer, 0)?;
        written += Field::append_many(&self.target_infos, &mut payload, writer)?;

        assert_eq!(written, PAYLOAD_OFFSET);
        writer.write_all(&payload[PAYLOAD_OFFSET..])?;
        written += payload.len();

        Ok(written)
    }

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: super::NomError<'a>,
    {
        let (
            _rest,
            (
                target_name_field,
                negociate_flags,
                server_challenge,
                _reserved,
                target_infos_field,
                version,
            ),
        ) = context(
            "Challenge",
            preceded(
                tuple((tag(SIGNATURE), verify(le_u32, |mt| *mt == MESSAGE_TYPE))),
                tuple((
                    Field::deserialize,
                    Flags::deserialize,
                    le_u64,
                    verify(le_u64, |reserved| *reserved == 0),
                    Field::deserialize,
                    Version::deserialize,
                )),
            ),
        )(input)?;

        let target_name = target_name_field.get_data_if(
            "target_name",
            input,
            negociate_flags.has_flag(flags::NTLMSSP_REQUEST_TARGET),
        )?;
        let target_infos = target_infos_field.get_many_if("target_infos", input, true)?;

        if let Some(last) = target_infos.last() {
            if !matches!(last, AvPair::MsvAvEOL) {
                let target_infos_data = &input[target_infos_field.get_range()];
                return Err(nom::Err::Error(E::add_context(
                    target_infos_data,
                    "Challenge/TargetInfos/EOL",
                    E::from_error_kind(target_infos_data, nom::error::ErrorKind::Verify),
                )));
            }
        }

        Ok((
            &b""[..],
            Self {
                target_name,
                negociate_flags,
                server_challenge,
                target_infos,
                version,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode() {
        let m = "TlRMTVNTUAACAAAAEAAQADAAAAAFgominWXBG0VA2i4AAAAAAAAAAHYAdgBAAAAAQwBJAFMAQwBPAEwAQQBCAAIAEABDAEkAUwBDAE8ATABBAEIAAQAQAFAATwBTAEUASQBEAE8ATgAEABgAYwBpAHMAYwBvAGwAYQBiAC4AYwBvAG0AAwAqAHAAbwBzAGUAaQBkAG8AbgAuAGMAaQBzAGMAbwBsAGEAYgAuAGMAbwBtAAAAAAA=";
        let challenge_message = Challenge {
            target_name: Some("CISCOLAB".into()),
            negociate_flags: Flags(2726920709),
            server_challenge: 3376081536230188445,
            target_infos: vec![
                AvPair::MsvAvNbDomainName("CISCOLAB".into()),
                AvPair::MsvAvNbComputerName("POSEIDON".into()),
                AvPair::MsvAvDnsDomainName("ciscolab.com".into()),
                AvPair::MsvAvDnsComputerName("poseidon.ciscolab.com".into()),
                AvPair::MsvAvEOL,
            ],
            version: Version::from([67, 0, 73, 0, 83, 0, 67, 0]),
        };
        let message = base64::decode(m).unwrap();
        let maybe_decoded_message =
            Challenge::deserialize::<nom::error::VerboseError<&[u8]>>(&message[..]);
        let (_, decoded_message) = maybe_decoded_message.unwrap();
        pretty_assertions::assert_eq!(decoded_message, challenge_message);
        eprintln!("challenge_message = {:#x?}", &challenge_message);
    }

    #[test]
    fn encode() {
        let challenge_message = Challenge {
            target_name: Some("CISCOLAB".into()),
            negociate_flags: Flags(2726920709),
            server_challenge: 3376081536230188445,
            target_infos: vec![
                AvPair::MsvAvNbDomainName("CISCOLAB".into()),
                AvPair::MsvAvNbComputerName("POSEIDON".into()),
                AvPair::MsvAvDnsDomainName("ciscolab.com".into()),
                AvPair::MsvAvDnsComputerName("poseidon.ciscolab.com".into()),
                AvPair::MsvAvEOL,
            ],
            version: Version::from([67, 0, 73, 0, 83, 0, 67, 0]),
        };
        let ser = challenge_message.serialize();
        pretty_assertions::assert_eq!(
            challenge_message,
            Challenge::deserialize::<()>(&ser[..]).unwrap().1
        );
    }
}
