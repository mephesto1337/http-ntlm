use std::io;
use std::ops::Range;

use super::{NomError, Wire};

use nom::combinator::opt;
use nom::error::context;
use nom::number::complete::{le_u16, le_u32};
use nom::sequence::tuple;

macro_rules! write_integer {
    ($name:ident, $type:ty) => {
        pub(super) fn $name(writer: &mut impl std::io::Write, n: $type) -> std::io::Result<usize> {
            let bytes = n.to_le_bytes();
            writer.write_all(&bytes[..])?;
            Ok(bytes.len())
        }
    };
}
write_integer!(write_u16, u16);
write_integer!(write_u32, u32);
write_integer!(write_u64, u64);

#[derive(Default, Debug, PartialEq, Eq)]
pub struct Fields {
    pub len: u16,
    pub max_len: u16,
    pub offset: u32,
}

impl<'a> Wire<'a> for Fields {
    fn serialize_into<W>(&self, writer: &mut W) -> std::io::Result<usize>
    where
        W: std::io::Write,
    {
        let mut written = 0;
        written += write_u16(writer, self.len)?;
        written += write_u16(writer, self.max_len)?;
        written += write_u32(writer, self.offset)?;
        Ok(written)
    }

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: super::NomError<'a>,
    {
        let (rest, (len, max_len, offset)) =
            context("Fields", tuple((le_u16, le_u16, le_u32)))(input)?;

        Ok((
            rest,
            Self {
                len,
                max_len,
                offset,
            },
        ))
    }
}

impl Fields {
    pub(crate) fn get_range(&self) -> Range<usize> {
        let start = self.offset as usize;
        let end = start + self.len as usize;
        start..end
    }

    pub(super) fn get_data<'a, T, E>(&self, input: &'a [u8]) -> nom::IResult<&'a [u8], Option<T>, E>
    where
        E: NomError<'a>,
        T: Wire<'a>,
    {
        if self.len == 0 {
            Ok((input, None))
        } else {
            let data = &input[self.get_range()];
            context("Fields::get_data", opt(T::deserialize))(data)
        }
    }
}

pub struct DevNull;

impl io::Write for DevNull {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
