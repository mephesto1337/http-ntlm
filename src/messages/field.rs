use std::io;
use std::ops::Range;

use crate::messages::{
    utils::{write_u16, write_u32},
    NomError, Wire,
};

use nom::error::context;
use nom::multi::many0;
use nom::number::complete::{le_u16, le_u32};
use nom::sequence::tuple;

#[derive(Default, Debug, PartialEq, Eq)]
pub struct Field {
    pub len: u16,
    pub max_len: u16,
    pub offset: u32,
}

impl<'a> Wire<'a> for Field {
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
            context("Field", tuple((le_u16, le_u16, le_u32)))(input)?;

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

impl Field {
    pub(crate) fn get_range(&self) -> Range<usize> {
        let start = self.offset as usize;
        let end = start + self.len as usize;
        start..end
    }

    pub(super) fn get_data_if<'a, T, E>(
        &self,
        typename: &'static str,
        input: &'a [u8],
        cond: bool,
    ) -> Result<Option<T>, nom::Err<E>>
    where
        E: NomError<'a>,
        T: Wire<'a> + std::fmt::Debug,
    {
        if cond {
            if self.len == 0 {
                log::warn!("Flag for {} is set but field is empty", typename);
                Ok(None)
            } else {
                let data = &input[self.get_range()];
                let (rest, value) =
                    context(typename, context("Field::get_data", T::deserialize))(data)?;
                if !rest.is_empty() {
                    log::warn!(
                        "Not all is consumed for {}. {} bytes remaning",
                        typename,
                        rest.len()
                    );
                }
                Ok(Some(value))
            }
        } else {
            Ok(None)
        }
    }

    pub(super) fn get_many_if<'a, T, E>(
        &self,
        typename: &'static str,
        input: &'a [u8],
        cond: bool,
    ) -> Result<Vec<T>, nom::Err<E>>
    where
        E: NomError<'a>,
        T: Wire<'a>,
    {
        if cond {
            if self.len == 0 {
                log::warn!("Flag for {} is set but field is empty", typename);
                Ok(Vec::new())
            } else {
                let data = &input[self.get_range()];
                let (rest, value) = context("Field::get_data", many0(T::deserialize))(data)?;
                if !rest.is_empty() {
                    log::warn!(
                        "Not all is consumed for {}. {} bytes remaning",
                        typename,
                        rest.len()
                    );
                }
                Ok(value)
            }
        } else {
            Ok(Vec::new())
        }
    }

    pub const fn zeroed() -> Self {
        Self {
            len: 0,
            max_len: 0,
            offset: 0,
        }
    }

    pub(super) fn append_many<'a, T, W>(
        values: &Vec<T>,
        data: &mut Vec<u8>,
        writer: &mut W,
    ) -> io::Result<usize>
    where
        T: Wire<'a>,
        W: io::Write,
    {
        let field = if values.is_empty() {
            Self::zeroed()
        } else {
            let offset: u32 = data.len().try_into().expect("Cannot fit usize into u32");
            let len: u16 = values
                .serialize_into(data)
                .expect("Write into Vec should never fail")
                .try_into()
                .expect("Cannot fit usize into u16");
            Self {
                len,
                max_len: len,
                offset,
            }
        };
        field.serialize_into(writer)
    }

    pub(super) fn append<'a, T, W>(
        value: Option<&T>,
        data: &mut Vec<u8>,
        writer: &mut W,
    ) -> io::Result<usize>
    where
        T: Wire<'a> + std::fmt::Debug,
        W: io::Write,
    {
        let field = if let Some(val) = value {
            let offset: u32 = data.len().try_into().expect("Cannot fit usize into u32");
            let len: u16 = val
                .serialize_into(data)
                .expect("Write into Vec should never fail")
                .try_into()
                .expect("Cannot fit usize into u16");
            Self {
                len,
                max_len: len,
                offset,
            }
        } else {
            Self::zeroed()
        };
        field.serialize_into(writer)
    }
}
