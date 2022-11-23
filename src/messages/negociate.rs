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

#[derive(Default, PartialEq, Eq)]
pub struct Negociate {
    pub negociate_flags: Flags,
    pub domain_name: Option<String>,
    pub workstation: Option<String>,
    pub version: Version,
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
            negociate_flags: Flags(0xa2088207),
            domain_name: None,
            workstation: None,
            version: Version::from([0x05, 0x01, 0x28, 0x0a, 0x00, 0x00, 0x00, 0x0f]),
        };
        let m = "TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAFASgKAAAADw==";
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
            negociate_flags: Flags(0xa2088207),
            domain_name: None,
            workstation: None,
            version: Version::from([0x05, 0x01, 0x28, 0x0a, 0x00, 0x00, 0x00, 0x0f]),
        };
        let ser = negociate_message.serialize();
        pretty_assertions::assert_eq!(
            negociate_message,
            Negociate::deserialize::<()>(&ser[..]).unwrap().1
        );
    }
}
