use std::fmt;

use nom::bytes::complete::tag;
use nom::combinator::verify;
use nom::error::context;
use nom::number::complete::le_u32;
use nom::sequence::{preceded, tuple};

use super::{
    utils::{write_u32, Fields},
    Wire, SIGNATURE,
};

const MESSAGE_TYPE: u32 = 0x00000001;

#[derive(Default, PartialEq, Eq)]
pub struct Negociate<'a> {
    pub negociate_flags: u32,
    pub domain_name_field: Fields,
    pub domain_name: Option<String>,
    pub workstation_field: Fields,
    pub workstation: Option<String>,
    pub payload: &'a [u8],
}

impl fmt::Debug for Negociate<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Negociate")
            .field("negociate_flags", &self.negociate_flags)
            .field("domain_name", &self.domain_name)
            .field("workstation", &self.workstation)
            .finish()
    }
}

impl<'a> Negociate<'a> {
    pub fn version(&'a self) -> &'a [u8] {
        &self.payload[..8]
    }
}

impl<'a> Wire<'a> for Negociate<'a> {
    fn serialize_into<W>(&self, writer: &mut W) -> std::io::Result<usize>
    where
        W: std::io::Write,
    {
        let mut written = 0;
        writer.write_all(&SIGNATURE[..])?;
        written += SIGNATURE.len();
        written += write_u32(writer, MESSAGE_TYPE)?;
        written += write_u32(writer, self.negociate_flags)?;
        written += self.domain_name_field.serialize_into(writer)?;
        written += self.workstation_field.serialize_into(writer)?;
        debug_assert_eq!(written, Self::header_size());

        writer.write_all(self.payload)?;
        written += self.payload.len();

        Ok(written)
    }

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: super::NomError<'a>,
    {
        let (payload, (negociate_flags, domain_name_field, workstation_field)) = context(
            "Negociate",
            preceded(
                tuple((
                    tag(SIGNATURE),
                    verify(le_u32, |mt| dbg!(*mt) == MESSAGE_TYPE),
                )),
                tuple((le_u32, Fields::deserialize, Fields::deserialize)),
            ),
        )(input)?;

        let (_rest, domain_name) = domain_name_field.get_data(input)?;
        let (_rest, workstation) = workstation_field.get_data(input)?;

        Ok((
            &b""[..],
            Self {
                negociate_flags,
                domain_name_field,
                domain_name,
                workstation_field,
                workstation,
                payload,
            },
        ))
    }

    fn header_size() -> usize {
        32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode() {
        let negociate_message = Negociate {
            negociate_flags: 0xa2088207,
            domain_name_field: Fields {
                len: 0,
                max_len: 0,
                offset: 0,
            },
            domain_name: None,
            workstation_field: Fields {
                len: 0,
                max_len: 0,
                offset: 0,
            },
            workstation: None,
            payload: &[0x05, 0x01, 0x28, 0x0a, 0x00, 0x00, 0x00, 0x0f][..],
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
            negociate_flags: 0xa2088207,
            domain_name_field: Fields {
                len: 0,
                max_len: 0,
                offset: 0,
            },
            domain_name: None,
            workstation_field: Fields {
                len: 0,
                max_len: 0,
                offset: 0,
            },
            workstation: None,
            payload: &[0x05, 0x01, 0x28, 0x0a, 0x00, 0x00, 0x00, 0x0f][..],
        };
        let m = "TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAFASgKAAAADw==";
        pretty_assertions::assert_eq!(base64::encode(negociate_message.serialize()), m);
    }

    #[test]
    fn encode_decode() {
        let m1 = Negociate::default();
        let ser = m1.serialize();
        let (rest, m2) = Negociate::deserialize::<nom::error::VerboseError<_>>(&ser[..]).unwrap();
        pretty_assertions::assert_eq!(rest.len(), 0);
        pretty_assertions::assert_eq!(m1, m2);
    }
}
