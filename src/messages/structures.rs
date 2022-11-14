use nom::bytes::complete::take;
use nom::combinator::map_opt;
use nom::error::context;
use nom::number::complete::le_u16;
use nom::sequence::tuple;

use crate::messages::{utils::write_u16, Wire};

#[derive(Debug, PartialEq, Eq, Default)]
#[repr(u16)]
pub enum AvId {
    /// Indicates that this is the last AV_PAIR in the list. AvLen MUST be 0. This type of information MUST be present in the AV pair list.
    #[default]
    MsvAvEOL = 0x0000,
    /// The server's NetBIOS computer name. The name MUST be in Unicode, and is not null-terminated. This type of information MUST be present in the AV_pair list.
    MsvAvNbComputerName = 0x0001,
    /// The server's NetBIOS domain name. The name MUST be in Unicode, and is not null-terminated. This type of information MUST be present in the AV_pair list.
    MsvAvNbDomainName = 0x0002,
    /// The fully qualified domain name (FQDN) of the computer. The name MUST be in Unicode, and is not null-terminated. The FQDN of the domain. The name MUST be in Unicode, and is not null-terminated.
    MsvAvDnsComputerName = 0x0003,
    /// The FQDN of the domain. The name MUST be in Unicode, and is not null-terminated.
    MsvAvDnsDomainName = 0x0004,
    /// The FQDN of the forest. The name MUST be in Unicode, and is not null-terminated.
    MsvAvDnsTreeName = 0x0005,
    /// A 32-bit value indicating server or client configuration.
    /// * 0x00000001: Indicates to the client that the account authentication is constrained.
    /// * 0x00000002: Indicates that the client is providing message integrity in the MIC field (section 2.2.1.3) in the AUTHENTICATE_MESSAGE.
    /// * 0x00000004: Indicates that the client is providing a target SPN generated from an untrusted source.
    MsvAvFlags = 0x0006,
    /// A FILETIME structure ([MS-DTYP] section 2.3.3) in little-endian byte order that contains the server local time. This structure is always sent in the CHALLENGE_MESSAGE.
    MsvAvTimestamp = 0x0007,
    /// A Single_Host_Data (section 2.2.2.2) structure. The Value field contains a platform-specific blob, as well as a MachineID created at computer startup to identify the calling machine.
    MsvAvSingleHost = 0x0008,
    /// The SPN of the target server. The name MUST be in Unicode and is not null-terminated.
    MsvAvTargetName = 0x0009,
    /// A channel bindings hash. The Value field contains an MD5 hash ([RFC4121] section 4.1.1.2) of a gss_channel_bindings_struct ([RFC2744] section 3.11). An all-zero value of the hash is used to indicate absence of channel bindings.
    MsvAvChannelBindings = 0x000a,
}

impl<'a> Wire<'a> for AvId {
    fn serialize_into<W>(&self, writer: &mut W) -> std::io::Result<usize>
    where
        W: std::io::Write,
    {
        write_u16(writer, *self as u16)
    }

    fn header_size() -> usize {
        2
    }

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: super::NomError<'a>,
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
pub struct AvPair<'a> {
    pub id: AvId,
    pub len: u16,
    pub data: &'a [u8],
}

impl<'a> Wire<'a> for AvPair<'a> {
    fn serialize_into<W>(&self, writer: &mut W) -> std::io::Result<usize>
    where
        W: std::io::Write,
    {
        let mut written = 0;
        written += self.id.serialize_into(writer)?;
        written += write_u16(writer, self.len)?;

        writer.write_all(self.data)?;
        written += self.data.len();

        Ok(written)
    }

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: super::NomError<'a>,
    {
        let (rest, (id, len)) = context("Avid", tuple((AvId::deserialize, le_u16)))(input)?;
        let (rest, data) = context("Avid/data", take(len as usize))(rest)?;

        Ok((rest, Self { id, len, data }))
    }

    fn header_size() -> usize {
        4
    }
}
