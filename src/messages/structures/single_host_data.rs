use nom::bytes::complete::take;
use nom::combinator::verify;
use nom::error::context;
use nom::number::complete::le_u32;
use nom::sequence::tuple;

use crate::messages::{utils::write_u32, Wire};

#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct SingleHostData {
    pub size: u32,
    pub z4: u32,
    pub custom_data: [u8; 8],
    pub machine_id: [u8; 32],
}

impl<'a> Wire<'a> for SingleHostData {
    fn serialize_into<W>(&self, writer: &mut W) -> std::io::Result<usize>
    where
        W: std::io::Write,
    {
        let mut written = 0;

        written += write_u32(writer, self.size)?;
        written += write_u32(writer, self.z4)?;
        writer.write_all(&self.custom_data[..])?;
        written += self.custom_data.len();
        writer.write_all(&self.machine_id[..])?;
        written += self.machine_id.len();

        Ok(written)
    }

    fn header_size() -> usize {
        48
    }

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: crate::messages::NomError<'a>,
    {
        let mut custom_data = [0u8; 8];
        let mut machine_id = [0u8; 32];
        let (rest, (size, z4, cd, mi)) = context(
            "SingleHostData",
            tuple((
                le_u32,
                verify(le_u32, |val| *val == 0),
                take(custom_data.len()),
                take(machine_id.len()),
            )),
        )(input)?;

        custom_data.copy_from_slice(cd);
        machine_id.copy_from_slice(mi);

        Ok((
            rest,
            Self {
                size,
                z4,
                custom_data,
                machine_id,
            },
        ))
    }
}
