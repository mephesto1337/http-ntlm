use nom::bytes::complete::{tag, take};
use nom::combinator::verify;
use nom::error::context;
use nom::number::complete::be_u32;
use nom::sequence::{preceded, tuple};

use super::{
    utils::{write_u32, Fields},
    Wire, SIGNATURE,
};

const MESSAGE_TYPE: u32 = 0x00000001;

#[derive(Default, Debug, PartialEq, Eq)]
pub struct Negociate<'a> {
    pub negociate_flags: u32,
    pub domain_name_fields: Fields,
    pub workstation_fields: Fields,
    pub version: [u8; 8],
    pub payload: &'a [u8],
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
        written += self.domain_name_fields.serialize_into(writer)?;
        written += self.workstation_fields.serialize_into(writer)?;
        writer.write_all(&self.version[..])?;
        written += &self.version[..].len();
        writer.write_all(self.payload)?;
        written += self.payload.len();

        Ok(written)
    }

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: super::NomError<'a>,
    {
        let mut version = [0u8; 8];

        let (payload, (negociate_flags, domain_name_fields, workstation_fields, version_content)) =
            context(
                "Negociate",
                preceded(
                    tuple((tag(SIGNATURE), verify(be_u32, |mt| *mt == MESSAGE_TYPE))),
                    tuple((
                        be_u32,
                        Fields::deserialize,
                        Fields::deserialize,
                        take(std::mem::size_of_val(&version)),
                    )),
                ),
            )(input)?;

        version.copy_from_slice(version_content);
        Ok((
            &b""[..],
            Self {
                negociate_flags,
                domain_name_fields,
                workstation_fields,
                version,
                payload,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negociate_message() {
        let m = "tESsBmE/yNY3lb6a0L6vVQEZNqwQn0s8Unew";
        let message = base64::decode_config(m, base64::STANDARD).unwrap();
        let (_, decoded_message) =
            Negociate::deserialize::<nom::error::VerboseError<&[u8]>>(&message[..]).unwrap();
        assert_eq!(decoded_message, Negociate::default());
    }
}
