use std::fmt;
use std::ops::{Deref, DerefMut};
use std::string::FromUtf16Error;

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
}
