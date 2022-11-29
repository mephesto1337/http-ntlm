use nom::combinator::verify;
use nom::error::context;
use nom::number::complete::le_u32;
use nom::sequence::tuple;

use crate::messages::{structures::RandomPad, utils::write_u32, Wire};

const VERSION: u32 = 1;

#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct MessageSignature {
    pub random_pad: RandomPad,
    pub checksum: u32,
    pub seq_num: u32,
}

impl<'a> Wire<'a> for MessageSignature {
    fn serialize_into<W>(&self, writer: &mut W) -> std::io::Result<usize>
    where
        W: std::io::Write,
    {
        let mut size = 0;

        size += write_u32(writer, VERSION)?;
        size += self.random_pad.serialize_into(writer)?;
        size += write_u32(writer, self.checksum)?;
        size += write_u32(writer, self.seq_num)?;

        Ok(size)
    }

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: crate::messages::NomError<'a>,
    {
        let (rest, (_version, random_pad, checksum, seq_num)) = context(
            "MessageSignature",
            tuple((
                context("version", verify(le_u32, |v| *v == VERSION)),
                RandomPad::deserialize,
                context("checksum", le_u32),
                context("seq_num", le_u32),
            )),
        )(input)?;

        Ok((
            rest,
            Self {
                random_pad,
                checksum,
                seq_num,
            },
        ))
    }
}
