use std::fmt;
use std::io;
use std::ops::{Deref, DerefMut};
use std::string::FromUtf16Error;

use nom::combinator::{map_opt, opt, verify};
use nom::error::context;
use nom::multi::fold_many0;
use nom::number::complete::le_u16;
use nom::sequence::terminated;

use crate::messages::{utils::write_u16, Wire};

pub struct UnicodeString(String);

impl Deref for UnicodeString {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for UnicodeString {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<String> for UnicodeString {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<UnicodeString> for String {
    fn from(s: UnicodeString) -> Self {
        s.into_inner()
    }
}

impl fmt::Display for UnicodeString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::Debug for UnicodeString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl UnicodeString {
    pub fn from_bytes(data: &[u8]) -> Result<Self, FromUtf16Error> {
        assert_eq!(
            data.len() % 2,
            0,
            "A UTF 16 string must have an even number of bytes"
        );
        let utf16_buffer =
            unsafe { std::slice::from_raw_parts(data.as_ptr().cast(), data.len() / 2) };
        String::from_utf16(utf16_buffer).map(|s| Self(s))
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl<'a> Wire<'a> for UnicodeString {
    fn serialize_into<W>(&self, writer: &mut W) -> io::Result<usize>
    where
        W: io::Write,
    {
        let mut size = 0;
        for b in self.0.encode_utf16() {
            size += write_u16(writer, b)?;
        }
        Ok(size)
    }

    fn header_size() -> usize {
        0
    }

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: super::NomError<'a>,
    {
        let (rest, s) = context(
            "UTF-16 string",
            terminated(
                fold_many0(
                    map_opt(le_u16, |b| {
                        if b == 0 {
                            None
                        } else {
                            char::decode_utf16(std::iter::once(b)).next().unwrap().ok()
                        }
                    }),
                    String::new,
                    |mut acc: String, c| {
                        acc.push(c);
                        acc
                    },
                ),
                opt(verify(le_u16, |b| *b == 0)),
            ),
        )(input)?;

        Ok((rest, Self(s)))
    }
}
