use std::io;
use std::mem::size_of;

use nom::bytes::complete::take;
use nom::combinator::{map_opt, verify};
use nom::error::context;
use nom::multi::length_data;
use nom::number::complete::{le_u16, le_u32};
use nom::sequence::tuple;

use crate::messages::{
    structures::{FileTime, SingleHostData},
    unicode_string::UnicodeString,
    utils::{write_u16, write_u32},
    NomError, Wire,
};

#[derive(Debug, PartialEq, Eq, Default, Copy, Clone)]
#[repr(u16)]
pub enum AvId {
    #[default]
    MsvAvEOL = 0x0000,
    MsvAvNbComputerName = 0x0001,
    MsvAvNbDomainName = 0x0002,
    MsvAvDnsComputerName = 0x0003,
    MsvAvDnsDomainName = 0x0004,
    MsvAvDnsTreeName = 0x0005,
    MsvAvFlags = 0x0006,
    MsvAvTimestamp = 0x0007,
    MsvAvSingleHost = 0x0008,
    MsvAvTargetName = 0x0009,
    MsvAvChannelBindings = 0x000a,
}

impl<'a> Wire<'a> for AvId {
    fn serialize_into<W>(&self, writer: &mut W) -> io::Result<usize>
    where
        W: io::Write,
    {
        write_u16(writer, *self as u16)
    }

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        context(
            "AvId",
            map_opt(le_u16, |val| match val {
                0x0000 => Some(Self::MsvAvEOL),
                0x0001 => Some(Self::MsvAvNbComputerName),
                0x0002 => Some(Self::MsvAvNbDomainName),
                0x0003 => Some(Self::MsvAvDnsComputerName),
                0x0004 => Some(Self::MsvAvDnsDomainName),
                0x0005 => Some(Self::MsvAvDnsTreeName),
                0x0006 => Some(Self::MsvAvFlags),
                0x0007 => Some(Self::MsvAvTimestamp),
                0x0008 => Some(Self::MsvAvSingleHost),
                0x0009 => Some(Self::MsvAvTargetName),
                0x000a => Some(Self::MsvAvChannelBindings),
                _ => None,
            }),
        )(input)
    }
}

#[derive(Default, Debug, PartialEq, Eq)]
pub struct MsvAvFlags {
    /// Indicates to the client that the account authentication is constrained.
    account_authentication_constrained: bool,
    /// Indicates that the client is providing message integrity in the MIC field (section 2.2.1.3) in the AUTHENTICATE_MESSAGE.
    mic_present: bool,
    /// Indicates that the client is providing a target SPN generated from an untrusted source.
    generated_spn_from_untrusted_source: bool,
}

impl<'a> Wire<'a> for MsvAvFlags {
    fn serialize_into<W>(&self, writer: &mut W) -> io::Result<usize>
    where
        W: io::Write,
    {
        let mut flags = 0;

        if self.account_authentication_constrained {
            flags |= 0x0000_0001;
        }
        if self.mic_present {
            flags |= 0x0000_0002;
        }
        if self.generated_spn_from_untrusted_source {
            flags |= 0x0000_0004;
        }
        write_u32(writer, flags)
    }

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        let (rest, flags) = context("MsvAvFlags", verify(le_u32, |f| *f & !0x7 == 0))(input)?;

        let account_authentication_constrained = flags & 0x0000_0001 != 0;
        let mic_present = flags & 0x0000_0002 != 0;
        let generated_spn_from_untrusted_source = flags & 0x0000_0004 != 0;

        Ok((
            rest,
            Self {
                account_authentication_constrained,
                mic_present,
                generated_spn_from_untrusted_source,
            },
        ))
    }
}

#[derive(Default, Debug, PartialEq, Eq)]
pub enum AvPair {
    /// Indicates that this is the last AV_PAIR in the list. AvLen MUST be 0. This type of information MUST be present in the AV pair list.
    #[default]
    MsvAvEOL,
    /// The server's NetBIOS computer name. The name MUST be in Unicode, and is not null-terminated. This type of information MUST be present in the AV_pair list.
    MsvAvNbComputerName(String),
    /// The server's NetBIOS domain name. The name MUST be in Unicode, and is not null-terminated. This type of information MUST be present in the AV_pair list.
    MsvAvNbDomainName(String),
    /// The fully qualified domain name (FQDN) of the computer. The name MUST be in Unicode, and is not null-terminated. The FQDN of the domain. The name MUST be in Unicode, and is not null-terminated.
    MsvAvDnsComputerName(String),
    /// The FQDN of the domain. The name MUST be in Unicode, and is not null-terminated.
    MsvAvDnsDomainName(String),
    /// The FQDN of the forest. The name MUST be in Unicode, and is not null-terminated.
    MsvAvDnsTreeName(String),
    /// A 32-bit value indicating server or client configuration.
    MsvAvFlags(MsvAvFlags),
    /// A FILETIME structure ([MS-DTYP] section 2.3.3) in little-endian byte order that contains the server local time. This structure is always sent in the CHALLENGE_MESSAGE.
    MsvAvTimestamp(FileTime),
    /// A Single_Host_Data (section 2.2.2.2) structure. The Value field contains a platform-specific blob, as well as a MachineID created at computer startup to identify the calling machine.
    MsvAvSingleHost(SingleHostData),
    /// The SPN of the target server. The name MUST be in Unicode and is not null-terminated.
    MsvAvTargetName(String),
    /// A channel bindings hash. The Value field contains an MD5 hash ([RFC4121] section 4.1.1.2) of a gss_channel_bindings_struct ([RFC2744] section 3.11). An all-zero value of the hash is used to indicate absence of channel bindings.
    MsvAvChannelBindings([u8; 16]),
}

impl AvPair {
    pub fn get_id(&self) -> AvId {
        match self {
            Self::MsvAvEOL => AvId::MsvAvEOL,
            Self::MsvAvNbComputerName(_) => AvId::MsvAvNbComputerName,
            Self::MsvAvNbDomainName(_) => AvId::MsvAvNbDomainName,
            Self::MsvAvDnsComputerName(_) => AvId::MsvAvDnsComputerName,
            Self::MsvAvDnsDomainName(_) => AvId::MsvAvDnsDomainName,
            Self::MsvAvDnsTreeName(_) => AvId::MsvAvDnsTreeName,
            Self::MsvAvFlags(_) => AvId::MsvAvFlags,
            Self::MsvAvTimestamp(_) => AvId::MsvAvTimestamp,
            Self::MsvAvSingleHost(_) => AvId::MsvAvSingleHost,
            Self::MsvAvTargetName(_) => AvId::MsvAvTargetName,
            Self::MsvAvChannelBindings(_) => AvId::MsvAvChannelBindings,
        }
    }
}

fn encode_string<W>(s: &String, writer: &mut W) -> io::Result<usize>
where
    W: io::Write,
{
    let mut written = 0;
    let utf16: Vec<_> = s.encode_utf16().collect();
    let data = unsafe { std::slice::from_raw_parts(utf16.as_ptr().cast(), utf16.len() * 2) };
    written += write_u16(writer, data.len().try_into().expect("String too long"))?;
    written += writer.write(&data[..])?;

    Ok(written)
}

impl<'a> Wire<'a> for AvPair {
    fn serialize_into<W>(&self, writer: &mut W) -> io::Result<usize>
    where
        W: io::Write,
    {
        let mut written = 0;
        written += self.get_id().serialize_into(writer)?;
        match self {
            Self::MsvAvEOL => {
                written += write_u16(writer, 0)?;
            }
            Self::MsvAvNbComputerName(ref s) => {
                written += encode_string(s, writer)?;
            }
            Self::MsvAvNbDomainName(ref s) => {
                written += encode_string(s, writer)?;
            }
            Self::MsvAvDnsComputerName(ref s) => {
                written += encode_string(s, writer)?;
            }
            Self::MsvAvDnsDomainName(ref s) => {
                written += encode_string(s, writer)?;
            }
            Self::MsvAvDnsTreeName(ref s) => {
                written += encode_string(s, writer)?;
            }
            Self::MsvAvFlags(ref flags) => {
                written += write_u16(writer, size_of::<u32>() as u16)?;
                written += flags.serialize_into(writer)?;
            }
            Self::MsvAvTimestamp(ref filetime) => {
                written += write_u16(writer, (size_of::<u32>() * 2) as u16)?;
                written += filetime.serialize_into(writer)?;
            }
            Self::MsvAvSingleHost(ref shd) => {
                written += write_u16(writer, std::mem::size_of_val(shd) as u16)?;
                written += shd.serialize_into(writer)?;
            }
            Self::MsvAvTargetName(ref s) => {
                written += encode_string(s, writer)?;
            }
            Self::MsvAvChannelBindings(ref hash) => {
                written += write_u16(writer, hash.len() as u16)?;
                written += hash.len();
                writer.write_all(&hash[..])?;
            }
        }

        Ok(written)
    }

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        let (rest, (id, data)) =
            context("AvPair", tuple((AvId::deserialize, length_data(le_u16))))(input)?;
        match id {
            AvId::MsvAvEOL => {
                if !data.is_empty() {
                    return Err(nom::Err::Error(E::from_error_kind(
                        data,
                        nom::error::ErrorKind::Verify,
                    )));
                }
                Ok((rest, Self::MsvAvEOL))
            }
            AvId::MsvAvNbComputerName => {
                let (r, s) = UnicodeString::deserialize(data)?;
                debug_assert_eq!(r.len(), 0);
                Ok((rest, Self::MsvAvNbComputerName(s.into())))
            }
            AvId::MsvAvNbDomainName => {
                let (r, s) = UnicodeString::deserialize(data)?;
                debug_assert_eq!(r.len(), 0);
                Ok((rest, Self::MsvAvNbDomainName(s.into())))
            }
            AvId::MsvAvDnsComputerName => {
                let (r, s) = UnicodeString::deserialize(data)?;
                debug_assert_eq!(r.len(), 0);
                Ok((rest, Self::MsvAvDnsComputerName(s.into())))
            }
            AvId::MsvAvDnsDomainName => {
                let (r, s) = UnicodeString::deserialize(data)?;
                debug_assert_eq!(r.len(), 0);
                Ok((rest, Self::MsvAvDnsDomainName(s.into())))
            }
            AvId::MsvAvDnsTreeName => {
                let (r, s) = UnicodeString::deserialize(data)?;
                debug_assert_eq!(r.len(), 0);
                Ok((rest, Self::MsvAvDnsTreeName(s.into())))
            }
            AvId::MsvAvFlags => {
                let (r, f) = MsvAvFlags::deserialize(data)?;
                debug_assert_eq!(r.len(), 0);
                Ok((rest, Self::MsvAvFlags(f)))
            }
            AvId::MsvAvTimestamp => {
                let (r, ts) = FileTime::deserialize(data)?;
                debug_assert_eq!(r.len(), 0);
                Ok((rest, Self::MsvAvTimestamp(ts)))
            }
            AvId::MsvAvSingleHost => {
                let (r, shd) = SingleHostData::deserialize(data)?;
                debug_assert_eq!(r.len(), 0);
                Ok((rest, Self::MsvAvSingleHost(shd)))
            }
            AvId::MsvAvTargetName => {
                let (r, s) = UnicodeString::deserialize(data)?;
                debug_assert_eq!(r.len(), 0);
                Ok((rest, Self::MsvAvTargetName(s.into())))
            }
            AvId::MsvAvChannelBindings => {
                let mut buf = [0u8; 16];
                let (r, s) = take(buf.len())(data)?;
                debug_assert_eq!(r.len(), 0);
                buf.copy_from_slice(s);
                Ok((rest, Self::MsvAvChannelBindings(buf)))
            }
        }
    }
}
