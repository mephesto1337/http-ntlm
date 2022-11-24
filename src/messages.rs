use std::io::{self, Write};

macro_rules! generate_setter_getter {
    ($field:ident, $flag:expr, $type:ty, $set:ident, $get:ident) => {
        pub fn $set(&mut self, $field: Option<impl Into<$type>>) -> &mut Self {
            self.$field = $field.map(|s| s.into());
            if self.$field.is_some() {
                self.negociate_flags.set_flag($flag);
            } else {
                self.negociate_flags.clear_flag($flag);
            }
            self
        }
        pub fn $get(&self) -> Option<&$type> {
            self.$field.as_ref()
        }
    };
    ($field:ident, $flag:expr, $type:ty, $add:ident, $del:ident, $clear:ident, $get:ident) => {
        pub fn $add(&mut self, item: $type) -> &mut Self {
            if self.$field.contains(&item) {
                return self;
            }
            self.$field.push(item);
            self.negociate_flags.set_flag($flag);
            self
        }

        pub fn $del(&mut self, item: &$type) -> &mut Self {
            let mut found = None;
            for (index, val) in self.$field.iter().enumerate() {
                if val == item {
                    found = Some(index);
                    break;
                }
            }
            if let Some(index) = found {
                self.$field.remove(index);
                if self.$field.is_empty() {
                    self.negociate_flags.clear_flag($flag);
                }
            }
            self
        }
        pub fn $clear(&mut self) -> &mut Self {
            self.$field.clear();
            self.negociate_flags.clear_flag($flag);
            self
        }
        pub fn $get(&self) -> &[$type] {
            &self.$field[..]
        }
    };
}

pub trait NomError<'a>:
    nom::error::ContextError<&'a [u8]> + nom::error::ParseError<&'a [u8]> + std::fmt::Debug
{
}

impl<'a, E> NomError<'a> for E where
    E: nom::error::ParseError<&'a [u8]> + nom::error::ContextError<&'a [u8]> + std::fmt::Debug
{
}

pub(super) trait Wire<'a>: Sized {
    fn serialize_into<W>(&self, writer: &mut W) -> io::Result<usize>
    where
        W: Write;
    fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        self.serialize_into(&mut data)
            .expect("Writing to a Vec should never failed");
        data
    }

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>;
}

impl<'a, T> Wire<'a> for Vec<T>
where
    T: Wire<'a>,
{
    fn serialize_into<W>(&self, writer: &mut W) -> io::Result<usize>
    where
        W: Write,
    {
        let mut size = 0;
        for item in self.iter() {
            size += item.serialize_into(writer)?;
        }
        Ok(size)
    }

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        nom::multi::many0(T::deserialize)(input)
    }
}

const SIGNATURE: &'static [u8; 8] = b"NTLMSSP\0";

pub mod authenticate;
pub mod challenge;
mod field;
pub mod flags;
pub mod negociate;
pub mod structures;
mod unicode_string;
mod utils;
mod version;

pub use authenticate::Authenticate;
pub use challenge::Challenge;
pub use flags::Flags;
pub use negociate::Negociate;

use field::Field;
use version::Version;
