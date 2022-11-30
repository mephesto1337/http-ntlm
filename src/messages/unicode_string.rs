use std::fmt;
use std::io;
use std::ops::{Deref, DerefMut};

use nom::combinator::{map, map_opt};
use nom::error::context;
use nom::multi::fold_many0;
use nom::number::complete::le_u16;

use crate::messages::{utils::write_u16, Wire};

macro_rules! impl_string {
    ($typename:ident) => {
        #[derive(PartialEq, Eq, Default, Clone)]
        pub struct $typename(String);

        impl Deref for $typename {
            type Target = String;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl DerefMut for $typename {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }

        impl From<String> for $typename {
            fn from(s: String) -> Self {
                Self(s)
            }
        }

        impl From<&str> for $typename {
            fn from(s: &str) -> Self {
                Self(s.to_owned())
            }
        }

        impl From<$typename> for String {
            fn from(s: $typename) -> Self {
                s.0
            }
        }

        impl fmt::Display for $typename {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl fmt::Debug for $typename {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Debug::fmt(&self.0, f)
            }
        }
    };
}

impl_string!(UnicodeString);
impl_string!(OEMString);

impl<'a> Wire<'a> for OEMString {
    fn serialize_into<W>(&self, writer: &mut W) -> io::Result<usize>
    where
        W: io::Write,
    {
        let bytes = self.0.as_bytes();
        writer.write_all(bytes)?;
        Ok(bytes.len())
    }

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: super::NomError<'a>,
    {
        context(
            "OEM string",
            map(
                map_opt(nom::combinator::rest, |b| {
                    std::str::from_utf8(b).map(|s| s.to_owned()).ok()
                }),
                |s| OEMString(s),
            ),
        )(input)
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

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: super::NomError<'a>,
    {
        context(
            "Unicode string",
            map(
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
                |s| UnicodeString(s),
            ),
        )(input)
    }
}
