use std::fmt;

use nom::bytes::complete::tag;
use nom::combinator::verify;
use nom::error::context;
use nom::number::complete::le_u32;
use nom::sequence::{preceded, tuple};

use crate::messages::{
    flags::{self, Flags},
    utils::write_u32,
    Field, Version, Wire, SIGNATURE,
};

const MESSAGE_TYPE: u32 = 0x00000001;

#[derive(PartialEq, Eq)]
pub struct Negociate {
    pub negociate_flags: Flags,
    domain_name: Option<String>,
    workstation: Option<String>,
    pub version: Version,
}

impl Negociate {
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

impl Default for Negociate {
    fn default() -> Self {
        let mut negociate_flags = Flags::default();
        negociate_flags.set_flag(flags::NTLMSSP_REQUEST_NON_NT_SESSION_KEY);
        negociate_flags.set_flag(flags::NTLMSSP_TARGET_TYPE_DOMAIN);
        negociate_flags.set_flag(flags::NTLMSSP_REQUEST_TARGET);

        Self {
            negociate_flags,
            domain_name: None,
            workstation: None,
            version: Default::default(),
        }
    }
}

impl fmt::Debug for Negociate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Negociate")
            .field("negociate_flags", &self.negociate_flags)
            .field("domain_name", &self.domain_name)
            .field("workstation", &self.workstation)
            .finish()
    }
}

impl<'a> Wire<'a> for Negociate {
    fn serialize_into<W>(&self, writer: &mut W) -> std::io::Result<usize>
    where
        W: std::io::Write,
    {
        const PAYLOAD_OFFSET: usize = 32;

        let mut payload = Vec::with_capacity(PAYLOAD_OFFSET * 2);
        payload.resize(PAYLOAD_OFFSET, 0);

        payload.extend_from_slice(&self.version);
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
        let (_rest, (negociate_flags, domain_name_field, workstation_field, version)) =
            context(
                "Negociate",
                preceded(
                    tuple((tag(SIGNATURE), verify(le_u32, |mt| *mt == MESSAGE_TYPE))),
                    tuple((
                        Flags::deserialize,
                        Field::deserialize,
                        Field::deserialize,
                        Version::deserialize,
                    )),
                ),
            )(input)?;

        let domain_name = domain_name_field.get_data_if(
            "domain",
            input,
            negociate_flags.has_flag(flags::NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED),
        )?;
        let workstation = workstation_field.get_data_if(
            "workstation",
            input,
            negociate_flags.has_flag(flags::NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED),
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

    #[test]
    fn decode() {
        let negociate_message = Negociate {
            negociate_flags: Flags(0xa20c8207),
            domain_name: Some("CONTOSIO".into()),
            workstation: Some("PC1".into()),
            version: Version::default(),
        };
        let m =
            "TlRMTVNTUAABAAAAB4IMohAAEAAoAAAABgAGADgAAAAAAAAAAAAAAEMATwBOAFQATwBTAEkATwBQAEMAMQA=";
        let message = base64::decode(m).unwrap();
        let maybe_decoded_message =
            Negociate::deserialize::<nom::error::VerboseError<&[u8]>>(&message[..]);
        eprintln!("maybe_decoded_message = {:#x?}", &maybe_decoded_message);
        let (_, decoded_message) = maybe_decoded_message.unwrap();
        pretty_assertions::assert_eq!(decoded_message, negociate_message);
    }

    #[test]
    fn encode() {
        let negociate_message = Negociate {
            negociate_flags: Flags(0xa20c8207),
            domain_name: Some("CONTOSIO".into()),
            workstation: Some("PC1".into()),
            version: Version::default(),
        };
        let ser = negociate_message.serialize();
        eprintln!("b64: {}", base64::encode(&ser[..]));
        pretty_assertions::assert_eq!(
            negociate_message,
            Negociate::deserialize::<()>(&ser[..]).unwrap().1
        );
    }
}
