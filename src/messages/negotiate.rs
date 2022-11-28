use nom::bytes::complete::tag;
use nom::combinator::{cond, verify};
use nom::error::context;
use nom::number::complete::le_u32;
use nom::sequence::{preceded, tuple};

use crate::messages::{
    flags::{self, Flags},
    structures::Version,
    utils::write_u32,
    Field, Wire, SIGNATURE,
};

const MESSAGE_TYPE: u32 = 0x00000001;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiate {
    pub negociate_flags: Flags,
    domain_name: Option<String>,
    workstation: Option<String>,
    pub version: Option<Version>,
}

impl Negotiate {
    pub fn set_domain_name(&mut self, domain_name: Option<String>) -> &mut Self {
        self.domain_name = domain_name;
        if self.domain_name.is_some() {
            self.negociate_flags
                .set_flag(flags::NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED);
        } else {
            self.negociate_flags
                .clear_flag(flags::NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED);
        }
        self
    }

    pub fn get_domain_name(&self) -> Option<&String> {
        self.domain_name.as_ref()
    }

    pub fn set_workstation(&mut self, workstation: Option<String>) -> &mut Self {
        self.workstation = workstation;
        if self.workstation.is_some() {
            self.negociate_flags
                .set_flag(flags::NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED);
        } else {
            self.negociate_flags
                .clear_flag(flags::NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED);
        }
        self
    }

    pub fn get_workstation(&self) -> Option<&String> {
        self.workstation.as_ref()
    }
}

impl Default for Negotiate {
    fn default() -> Self {
        Self {
            negociate_flags: Flags::default(),
            domain_name: None,
            workstation: None,
            version: Default::default(),
        }
    }
}

impl<'a> Wire<'a> for Negotiate {
    fn serialize_into<W>(&self, writer: &mut W) -> std::io::Result<usize>
    where
        W: std::io::Write,
    {
        const PAYLOAD_OFFSET: usize = 32;

        let mut payload = Vec::with_capacity(PAYLOAD_OFFSET * 2);
        payload.resize(PAYLOAD_OFFSET, 0);

        if let Some(ref version) = self.version {
            version.serialize_into(&mut payload).unwrap();
        }

        let mut written = 0;
        writer.write_all(&SIGNATURE[..])?;
        written += SIGNATURE.len();
        written += write_u32(writer, MESSAGE_TYPE)?;
        written += self.negociate_flags.serialize_into(writer)?;
        written += Field::append(self.domain_name.as_ref(), &mut payload, writer)?;
        written += Field::append(self.workstation.as_ref(), &mut payload, writer)?;

        assert_eq!(written, PAYLOAD_OFFSET);

        writer.write_all(&payload[PAYLOAD_OFFSET..])?;
        written += payload.len();

        Ok(written)
    }

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: super::NomError<'a>,
    {
        let (rest, (negociate_flags, domain_name_field, workstation_field)) = context(
            "Negotiate",
            preceded(
                tuple((tag(SIGNATURE), verify(le_u32, |mt| *mt == MESSAGE_TYPE))),
                tuple((
                    Flags::deserialize,
                    context("domain_name_field", Field::deserialize),
                    context("workstation_field", Field::deserialize),
                )),
            ),
        )(input)?;

        let (_, version) = cond(
            dbg!(negociate_flags).has_flag(flags::NTLMSSP_NEGOTIATE_VERSION),
            context("Negotiate/version", Version::deserialize),
        )(rest)?;

        let domain_name = domain_name_field.get_data_if(
            "domain",
            input,
            negociate_flags.has_flag(flags::NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED) || true,
        )?;
        let workstation = workstation_field.get_data_if(
            "workstation",
            input,
            negociate_flags.has_flag(flags::NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED) || true,
        )?;

        Ok((
            &b""[..],
            Self {
                negociate_flags,
                domain_name,
                workstation,
                version,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /*
    #[test]
    fn decode() {
        let negociate_message = Negotiate {
            negociate_flags: Flags(0),
            domain_name: Some("CONTOSIO".into()),
            workstation: Some("PC1".into()),
            version: None,
        };
        let raw_message = &[
            0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x82,
            0x0c, 0xa2, 0x10, 0x00, 0x10, 0x00, 0x28, 0x00, 0x00, 0x00, 0x06, 0x00, 0x06, 0x00,
            0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43, 0x00,
            0x4f, 0x00, 0x4e, 0x00, 0x54, 0x00, 0x4f, 0x00, 0x53, 0x00, 0x49, 0x00, 0x4f, 0x00,
            0x50, 0x00, 0x43, 0x00, 0x31, 0x00,
        ][..];
        let maybe_decoded_message =
            Negotiate::deserialize::<nom::error::VerboseError<&[u8]>>(&raw_message[..]);
        eprintln!("maybe_decoded_message = {:#x?}", &maybe_decoded_message);
        let (_, decoded_message) = maybe_decoded_message.unwrap();
        pretty_assertions::assert_eq!(decoded_message, negociate_message);
    }
    */

    #[test]
    fn encode() {
        let negociate_message = Negotiate {
            negociate_flags: Flags(crate::messages::flags::tests::FLAGS_NTLMV2),
            domain_name: Some("CONTOSIO".into()),
            workstation: Some("PC1".into()),
            version: Some(Version {
                major: 6,
                minor: 0,
                build: 0x7017,
                revision_count: 0x0f,
            }),
        };
        let ser = negociate_message.serialize();
        eprintln!("b64: {}", base64::encode(&ser[..]));
        eprintln!(
            "{:?}",
            Negotiate::deserialize::<nom::error::VerboseError<&[u8]>>(&ser[..])
        );
        pretty_assertions::assert_eq!(
            negociate_message,
            Negotiate::deserialize::<()>(&ser[..]).unwrap().1
        );
    }
}
