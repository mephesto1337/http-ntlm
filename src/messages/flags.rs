use std::fmt;

use crate::messages::{utils::write_u32, NomError, Wire};

use nom::combinator::{map, verify};
use nom::error::context;
use nom::number::complete::le_u32;

/// Each tuple is of a format: (BIT_INDEX, BIT_COUNT)

/// If set, requests 56-bit encryption. If the client sends NTLMSSP_NEGOTIATE_SEAL or
/// NTLMSSP_NEGOTIATE_SIGN with NTLMSSP_NEGOTIATE_56 to the server in the NEGOTIATE_MESSAGE, the
/// server MUST return NTLMSSP_NEGOTIATE_56 to the client in the CHALLENGE_MESSAGE. Otherwise it is
/// ignored. If both NTLMSSP_NEGOTIATE_56 and NTLMSSP_NEGOTIATE_128 are requested and supported by
/// the client and server, NTLMSSP_NEGOTIATE_56 and NTLMSSP_NEGOTIATE_128 will both be returned to
/// the client. Clients and servers that set NTLMSSP_NEGOTIATE_SEAL SHOULD set NTLMSSP_NEGOTIATE_56
/// if it is supported.
pub const NTLMSSP_NEGOTIATE_56: u32 = 0;

/// f set, requests an explicit key exchange. This capability SHOULD be used because it improves
/// security for message integrity or confidentiality. See sections 3.2.5.1.2, 3.2.5.2.1, and
/// 3.2.5.2.2 for details.
pub const NTLMSSP_NEGOTIATE_KEY_EXCH: u32 = 1;

/// If set, requests 128-bit session key negotiation. If the client sends NTLMSSP_NEGOTIATE_128 to
/// the server in the NEGOTIATE_MESSAGE, the server MUST return NTLMSSP_NEGOTIATE_128 to the client
/// in the CHALLENGE_MESSAGE only if the client sets NTLMSSP_NEGOTIATE_SEAL or
/// NTLMSSP_NEGOTIATE_SIGN. Otherwise it is ignored. If both NTLMSSP_NEGOTIATE_56 and
/// NTLMSSP_NEGOTIATE_128 are requested and supported by the client and server,
/// NTLMSSP_NEGOTIATE_56 and NTLMSSP_NEGOTIATE_128 will both be returned to the client. Clients and
/// servers that set NTLMSSP_NEGOTIATE_SEAL SHOULD set NTLMSSP_NEGOTIATE_128 if it is supported.
pub const NTLMSSP_NEGOTIATE_128: u32 = 2;

/// Unused bit that must be set to 0
pub const R1: u32 = 3;

/// Unused bit that must be set to 0
pub const R2: u32 = 4;

/// Unused bit that must be set to 0
pub const R3: u32 = 5;

/// If set, requests the protocol version number. The data corresponding to this flag is provided
/// in the Version field of the NEGOTIATE_MESSAGE, the CHALLENGE_MESSAGE, and the
/// AUTHENTICATE_MESSAGE.<
pub const NTLMSSP_NEGOTIATE_VERSION: u32 = 6;

/// Unused bit that must be set to 0
pub const R4: u32 = 7;

/// If set, indicates that the TargetInfo fields in the CHALLENGE_MESSAGE (section 2.2.1.2) are
/// populated.
pub const NTLMSSP_NEGOTIATE_TARGET_INFO: u32 = 8;

/// If set, requests the usage of the LMOWF.
pub const NTLMSSP_REQUEST_NON_NT_SESSION_KEY: u32 = 9;

/// Unused bit that must be set to 0
pub const R5: u32 = 10;

/// If set, requests an identify level token.
pub const NTLMSSP_NEGOTIATE_IDENTIFY: u32 = 11;

/// If set, requests usage of the NTLM v2 session security. NTLM v2 session security is a misnomer
/// because it is not NTLM v2. It is NTLM v1 using the extended session security that is also in
/// NTLM v2. NTLMSSP_NEGOTIATE_LM_KEY and NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY are mutually
/// exclusive. If both NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY and NTLMSSP_NEGOTIATE_LM_KEY are
/// requested, NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY alone MUST be returned to the client.
/// NTLM v2 authentication session key generation MUST be supported by both the client and the DC
/// in order to be used, and extended session security signing and sealing requires support from
/// the client and the server in order to be used.
pub const NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 12;

/// Unused bit that must be set to 0
pub const R6: u32 = 13;

/// If set, TargetName MUST be a server name. The data corresponding to this flag is provided by
/// the server in the TargetName field of the CHALLENGE_MESSAGE. If this bit is set, then
/// NTLMSSP_TARGET_TYPE_DOMAIN MUST NOT be set. This flag MUST be ignored in the NEGOTIATE_MESSAGE
/// and the AUTHENTICATE_MESSAGE.
pub const NTLMSSP_TARGET_TYPE_SERVER: u32 = 14;

/// If set, TargetName MUST be a domain name. The data corresponding to this flag is
/// provided by the server in the TargetName field of the CHALLENGE_MESSAGE. If set, then
/// NTLMSSP_TARGET_TYPE_SERVER MUST NOT be set. This flag MUST be ignored in the
/// NEGOTIATE_MESSAGE and the AUTHENTICATE_MESSAGE.
pub const NTLMSSP_TARGET_TYPE_DOMAIN: u32 = 15;

/// If set, a session key is generated regardless of the states of NTLMSSP_NEGOTIATE_SIGN
/// and NTLMSSP_NEGOTIATE_SEAL. A session key MUST always exist to generate the MIC (section
/// 3.1.5.1.2) in the authenticate message. NTLMSSP_NEGOTIATE_ALWAYS_SIGN MUST be set in the
/// NEGOTIATE_MESSAGE to the server and the CHALLENGE_MESSAGE to the client.
/// NTLMSSP_NEGOTIATE_ALWAYS_SIGN is overridden by NTLMSSP_NEGOTIATE_SIGN and
/// NTLMSSP_NEGOTIATE_SEAL, if they are supported.
pub const NTLMSSP_NEGOTIATE_ALWAYS_SIGN: u32 = 16;

/// Unused bit that must be set to 0
pub const R7: u32 = 17;

/// his flag indicates whether the Workstation field is present. If this flag is not set, the
/// Workstation field MUST be ignored. If this flag is set, the length of the Workstation field
/// specifies whether the workstation name is nonempty or not.
pub const NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED: u32 = 18;

/// If set, the domain name is provided (section 2.2.1.1).
pub const NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED: u32 = 19;

/// If set, the connection SHOULD be anonymous.<28>
pub const NTLMSSP_ANONYMOUS: u32 = 20;

/// Unused bit that must be set to 0
pub const R8: u32 = 21;

/// If set, requests usage of the NTLM v1 session security protocol.
/// NTLMSSP_NEGOTIATE_NTLM MUST be set in the NEGOTIATE_MESSAGE to the server and the
/// CHALLENGE_MESSAGE to the client.
pub const NTLMSSP_NEGOTIATE_NTLM: u32 = 22;

/// Unused bit that must be set to 0
pub const R9: u32 = 23;

/// If set, requests LAN Manager (LM) session key computation. NTLMSSP_NEGOTIATE_LM_KEY and
/// NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY are mutually exclusive. If both
/// NTLMSSP_NEGOTIATE_LM_KEY and NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY are requested,
/// NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY alone MUST be returned to the client. NTLM v2
/// authentication session key generation MUST be supported by both the client and the DC in order
/// to be used, and extended session security signing and sealing requires support from the client
/// and the server to be used.
pub const NTLMSSP_NEGOTIATE_LM_KEY: u32 = 24;

/// If set, requests connectionless authentication. If NTLMSSP_NEGOTIATE_DATAGRAM is set, then
/// NTLMSSP_NEGOTIATE_KEY_EXCH MUST always be set in the AUTHENTICATE_MESSAGE to the server and the
/// CHALLENGE_MESSAGE to the client.
pub const NTLMSSP_NEGOTIATE_DATAGRAM: u32 = 25;

/// If set, requests session key negotiation for message confidentiality. If the client sends
/// NTLMSSP_NEGOTIATE_SEAL to the server in the NEGOTIATE_MESSAGE, the server MUST return
/// NTLMSSP_NEGOTIATE_SEAL to the client in the CHALLENGE_MESSAGE. Clients and servers that set
/// NTLMSSP_NEGOTIATE_SEAL SHOULD always set NTLMSSP_NEGOTIATE_56 and NTLMSSP_NEGOTIATE_128, if
/// they are supported.
pub const NTLMSSP_NEGOTIATE_SEAL: u32 = 26;

/// If set, requests session key negotiation for message signatures. If the client sends
/// NTLMSSP_NEGOTIATE_SIGN to the server in the NEGOTIATE_MESSAGE, the server MUST return
/// NTLMSSP_NEGOTIATE_SIGN to the client in the CHALLENGE_MESSAGE.
pub const NTLMSSP_NEGOTIATE_SIGN: u32 = 27;

/// Unused bit that must be set to 0
pub const R10: u32 = 28;

/// If set, a TargetName field of the CHALLENGE_MESSAGE (section 2.2.1.2) MUST be supplied.
pub const NTLMSSP_REQUEST_TARGET: u32 = 29;

/// If set, requests OEM character set encoding. See bit [NTLMSSP_NEGOTIATE_UNICODE.] for details.
pub const NTLM_NEGOTIATE_OEM: u32 = 30;

/// If set, requests Unicode character set encoding. An alternate name for this field is
/// NTLMSSP_NEGOTIATE_UNICODE.
/// The A and B bits are evaluated together as follows:
/// * A==1: The choice of character set encoding MUST be Unicode.
/// * A==0 and B==1: The choice of character set encoding MUST be OEM.
/// * A==0 and B==0: The protocol MUST return SEC_E_INVALID_TOKEN.
pub const NTLMSSP_NEGOTIATE_UNICODE: u32 = 31;

#[derive(PartialEq, Eq, Copy, Clone)]
#[repr(transparent)]
pub struct Flags(pub u32);

impl Default for Flags {
    fn default() -> Self {
        let mut flags = Self(0);
        flags.set_flag(NTLMSSP_NEGOTIATE_56);
        flags.set_flag(NTLMSSP_NEGOTIATE_KEY_EXCH);
        flags.set_flag(NTLMSSP_NEGOTIATE_128);
        flags.set_flag(NTLMSSP_NEGOTIATE_DATAGRAM);
        flags.set_flag(NTLMSSP_NEGOTIATE_UNICODE);

        flags
    }
}

impl<'a> Wire<'a> for Flags {
    fn serialize_into<W>(&self, writer: &mut W) -> std::io::Result<usize>
    where
        W: std::io::Write,
    {
        write_u32(writer, self.0)
    }

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: NomError<'a>,
    {
        context("Flags", map(verify(le_u32, Self::validate), |f| Self(f)))(input)
    }
}

impl Flags {
    pub fn has_flag(&self, bit: u32) -> bool {
        debug_assert!(bit <= 31);
        self.0 & (1 << bit) != 0
    }

    pub fn set_flag(&mut self, bit: u32) {
        debug_assert!(bit <= 31);
        self.0 |= 1 << bit;
    }

    pub fn clear_flag(&mut self, bit: u32) {
        debug_assert!(bit <= 31);
        self.0 &= u32::MAX & !(1 << bit);
    }

    fn validate(flags: &u32) -> bool {
        let flags = Self(*flags);

        if flags.has_flag(R1) {
            log::warn!("flags.has_flag(R1)");
            return false;
        }
        if flags.has_flag(R2) {
            log::warn!("flags.has_flag(R2)");
            return false;
        }
        if flags.has_flag(R3) {
            log::warn!("flags.has_flag(R3)");
            return false;
        }
        if flags.has_flag(R4) {
            log::warn!("flags.has_flag(R4)");
            return false;
        }
        if flags.has_flag(R5) {
            log::warn!("flags.has_flag(R5)");
            return false;
        }
        if flags.has_flag(R6) {
            log::warn!("flags.has_flag(R6)");
            return false;
        }
        if flags.has_flag(R7) {
            log::warn!("flags.has_flag(R7)");
            return false;
        }
        if flags.has_flag(R8) {
            log::warn!("flags.has_flag(R8)");
            return false;
        }
        if flags.has_flag(R9) {
            log::warn!("flags.has_flag(R9)");
            // return false;
        }
        if flags.has_flag(R10) {
            log::warn!("flags.has_flag(R10)");
            return false;
        }

        if flags.has_flag(NTLMSSP_TARGET_TYPE_DOMAIN) && flags.has_flag(NTLMSSP_TARGET_TYPE_SERVER)
        {
            log::warn!(
                "flags cannot have NTLMSSP_TARGET_TYPE_DOMAIN and NTLMSSP_TARGET_TYPE_SERVER"
            );
            return false;
        }

        if !flags.has_flag(NTLMSSP_NEGOTIATE_UNICODE) && !flags.has_flag(NTLM_NEGOTIATE_OEM) {
            log::warn!("!flags.has_flag(NTLMSSP_NEGOTIATE_UNICODE) && !flags.has_flag(NTLM_NEGOTIATE_OEM) ");
            return false;
        }

        true
    }
}

impl fmt::Debug for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        if self.has_flag(NTLMSSP_NEGOTIATE_56) {
            if first {
                f.write_str("NTLMSSP_NEGOTIATE_56")?;
            } else {
                f.write_str("|NTLMSSP_NEGOTIATE_56")?;
            }
            first = false;
        }
        if self.has_flag(NTLMSSP_NEGOTIATE_KEY_EXCH) {
            if first {
                f.write_str("NTLMSSP_NEGOTIATE_KEY_EXCH")?;
            } else {
                f.write_str("|NTLMSSP_NEGOTIATE_KEY_EXCH")?;
            }
            first = false;
        }
        if self.has_flag(NTLMSSP_NEGOTIATE_128) {
            if first {
                f.write_str("NTLMSSP_NEGOTIATE_128")?;
            } else {
                f.write_str("|NTLMSSP_NEGOTIATE_128")?;
            }
            first = false;
        }
        if self.has_flag(R1) {
            if first {
                f.write_str("R1")?;
            } else {
                f.write_str("|R1")?;
            }
            first = false;
        }
        if self.has_flag(R2) {
            if first {
                f.write_str("R2")?;
            } else {
                f.write_str("|R2")?;
            }
            first = false;
        }
        if self.has_flag(R3) {
            if first {
                f.write_str("R3")?;
            } else {
                f.write_str("|R3")?;
            }
            first = false;
        }
        if self.has_flag(NTLMSSP_NEGOTIATE_VERSION) {
            if first {
                f.write_str("NTLMSSP_NEGOTIATE_VERSION")?;
            } else {
                f.write_str("|NTLMSSP_NEGOTIATE_VERSION")?;
            }
            first = false;
        }
        if self.has_flag(R4) {
            if first {
                f.write_str("R4")?;
            } else {
                f.write_str("|R4")?;
            }
            first = false;
        }
        if self.has_flag(NTLMSSP_NEGOTIATE_TARGET_INFO) {
            if first {
                f.write_str("NTLMSSP_NEGOTIATE_TARGET_INFO")?;
            } else {
                f.write_str("|NTLMSSP_NEGOTIATE_TARGET_INFO")?;
            }
            first = false;
        }
        if self.has_flag(NTLMSSP_REQUEST_NON_NT_SESSION_KEY) {
            if first {
                f.write_str("NTLMSSP_REQUEST_NON_NT_SESSION_KEY")?;
            } else {
                f.write_str("|NTLMSSP_REQUEST_NON_NT_SESSION_KEY")?;
            }
            first = false;
        }
        if self.has_flag(R5) {
            if first {
                f.write_str("R5")?;
            } else {
                f.write_str("|R5")?;
            }
            first = false;
        }
        if self.has_flag(NTLMSSP_NEGOTIATE_IDENTIFY) {
            if first {
                f.write_str("NTLMSSP_NEGOTIATE_IDENTIFY")?;
            } else {
                f.write_str("|NTLMSSP_NEGOTIATE_IDENTIFY")?;
            }
            first = false;
        }
        if self.has_flag(NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) {
            if first {
                f.write_str("NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY")?;
            } else {
                f.write_str("|NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY")?;
            }
            first = false;
        }
        if self.has_flag(R6) {
            if first {
                f.write_str("R6")?;
            } else {
                f.write_str("|R6")?;
            }
            first = false;
        }
        if self.has_flag(NTLMSSP_TARGET_TYPE_SERVER) {
            if first {
                f.write_str("NTLMSSP_TARGET_TYPE_SERVER")?;
            } else {
                f.write_str("|NTLMSSP_TARGET_TYPE_SERVER")?;
            }
            first = false;
        }
        if self.has_flag(NTLMSSP_TARGET_TYPE_DOMAIN) {
            if first {
                f.write_str("NTLMSSP_TARGET_TYPE_DOMAIN")?;
            } else {
                f.write_str("|NTLMSSP_TARGET_TYPE_DOMAIN")?;
            }
            first = false;
        }
        if self.has_flag(NTLMSSP_NEGOTIATE_ALWAYS_SIGN) {
            if first {
                f.write_str("NTLMSSP_NEGOTIATE_ALWAYS_SIGN")?;
            } else {
                f.write_str("|NTLMSSP_NEGOTIATE_ALWAYS_SIGN")?;
            }
            first = false;
        }
        if self.has_flag(R7) {
            if first {
                f.write_str("R7")?;
            } else {
                f.write_str("|R7")?;
            }
            first = false;
        }
        if self.has_flag(NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED) {
            if first {
                f.write_str("NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED")?;
            } else {
                f.write_str("|NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED")?;
            }
            first = false;
        }
        if self.has_flag(NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED) {
            if first {
                f.write_str("NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED")?;
            } else {
                f.write_str("|NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED")?;
            }
            first = false;
        }
        if self.has_flag(NTLMSSP_ANONYMOUS) {
            if first {
                f.write_str("NTLMSSP_ANONYMOUS")?;
            } else {
                f.write_str("|NTLMSSP_ANONYMOUS")?;
            }
            first = false;
        }
        if self.has_flag(R8) {
            if first {
                f.write_str("R8")?;
            } else {
                f.write_str("|R8")?;
            }
            first = false;
        }
        if self.has_flag(NTLMSSP_NEGOTIATE_NTLM) {
            if first {
                f.write_str("NTLMSSP_NEGOTIATE_NTLM")?;
            } else {
                f.write_str("|NTLMSSP_NEGOTIATE_NTLM")?;
            }
            first = false;
        }
        if self.has_flag(R9) {
            if first {
                f.write_str("R9")?;
            } else {
                f.write_str("|R9")?;
            }
            first = false;
        }
        if self.has_flag(NTLMSSP_NEGOTIATE_LM_KEY) {
            if first {
                f.write_str("NTLMSSP_NEGOTIATE_LM_KEY")?;
            } else {
                f.write_str("|NTLMSSP_NEGOTIATE_LM_KEY")?;
            }
            first = false;
        }
        if self.has_flag(NTLMSSP_NEGOTIATE_DATAGRAM) {
            if first {
                f.write_str("NTLMSSP_NEGOTIATE_DATAGRAM")?;
            } else {
                f.write_str("|NTLMSSP_NEGOTIATE_DATAGRAM")?;
            }
            first = false;
        }
        if self.has_flag(NTLMSSP_NEGOTIATE_SEAL) {
            if first {
                f.write_str("NTLMSSP_NEGOTIATE_SEAL")?;
            } else {
                f.write_str("|NTLMSSP_NEGOTIATE_SEAL")?;
            }
            first = false;
        }
        if self.has_flag(NTLMSSP_NEGOTIATE_SIGN) {
            if first {
                f.write_str("NTLMSSP_NEGOTIATE_SIGN")?;
            } else {
                f.write_str("|NTLMSSP_NEGOTIATE_SIGN")?;
            }
            first = false;
        }
        if self.has_flag(R10) {
            if first {
                f.write_str("R10")?;
            } else {
                f.write_str("|R10")?;
            }
            first = false;
        }
        if self.has_flag(NTLMSSP_REQUEST_TARGET) {
            if first {
                f.write_str("NTLMSSP_REQUEST_TARGET")?;
            } else {
                f.write_str("|NTLMSSP_REQUEST_TARGET")?;
            }
            first = false;
        }
        if self.has_flag(NTLM_NEGOTIATE_OEM) {
            if first {
                f.write_str("NTLM_NEGOTIATE_OEM")?;
            } else {
                f.write_str("|NTLM_NEGOTIATE_OEM")?;
            }
            first = false;
        }
        if self.has_flag(NTLMSSP_NEGOTIATE_UNICODE) {
            if first {
                f.write_str("NTLMSSP_NEGOTIATE_UNICODE")?;
            } else {
                f.write_str("|NTLMSSP_NEGOTIATE_UNICODE")?;
            }
        }
        Ok(())
    }
}
