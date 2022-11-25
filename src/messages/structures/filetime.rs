use std::time::{Duration, SystemTime, SystemTimeError, UNIX_EPOCH};

use nom::error::context;
use nom::number::complete::le_u32;
use nom::sequence::tuple;

use crate::messages::{utils::write_u32, Wire};

#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct FileTime {
    pub low: u32,
    pub high: u32,
}
const NANO_TO_MILLI: u64 = 1_000_000;

impl TryFrom<SystemTime> for FileTime {
    type Error = Option<SystemTimeError>;

    fn try_from(value: SystemTime) -> Result<Self, Self::Error> {
        let seconds = value.duration_since(UNIX_EPOCH).map_err(Some)?.as_secs();
        let nsec = seconds.checked_mul(NANO_TO_MILLI).ok_or(None)?;
        Ok(Self {
            high: (nsec >> 32) as u32,
            low: (nsec & 0xffff_ffff) as u32,
        })
    }
}

impl FileTime {
    pub fn to_system_time(&self) -> Option<SystemTime> {
        let ts = self.as_u64() / NANO_TO_MILLI;
        UNIX_EPOCH.checked_add(Duration::from_secs(ts))
    }

    pub fn as_u64(&self) -> u64 {
        ((self.high as u64) << 32) | (self.low as u64)
    }

    pub fn now() -> Self {
        SystemTime::now()
            .try_into()
            .expect("now should be after UNIX_EPOCH")
    }
}

impl<'a> Wire<'a> for FileTime {
    fn serialize_into<W>(&self, writer: &mut W) -> std::io::Result<usize>
    where
        W: std::io::Write,
    {
        let mut written = 0;

        written += write_u32(writer, self.low)?;
        written += write_u32(writer, self.high)?;

        Ok(written)
    }

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: crate::messages::NomError<'a>,
    {
        let (rest, (low, high)) = context("FileTime", tuple((le_u32, le_u32)))(input)?;
        let me = Self { low, high };

        if me.to_system_time().is_none() {
            Err(nom::Err::Error(E::from_error_kind(
                input,
                nom::error::ErrorKind::Verify,
            )))
        } else {
            Ok((rest, me))
        }
    }
}
