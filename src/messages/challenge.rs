use std::env;
use std::fmt;

use nom::bytes::complete::tag;
use nom::combinator::verify;
use nom::error::context;
use nom::number::complete::{le_u32, le_u64};
use nom::sequence::{preceded, tuple};

use crate::messages::{
    flags::{self, Flags},
    structures::{AvPair, FileTime, MsvAvFlags, SingleHostData},
    utils::{write_u32, write_u64},
    Field, Version, Wire, SIGNATURE,
};

const MESSAGE_TYPE: u32 = 0x00000002;

#[derive(PartialEq, Eq)]
pub struct Challenge {
    target_name: Option<String>,
    pub negociate_flags: Flags,
    pub server_challenge: u64,
    target_infos: Vec<AvPair>,
    pub version: Version,
}

impl Challenge {
    generate_setter_getter!(
        target_name,
        flags::NTLMSSP_REQUEST_TARGET,
        String,
        set_target_name,
        get_target_name
    );

    fn add_target_info(&mut self, info: AvPair) {
        if self.target_infos.is_empty() {
            self.target_infos.push(info);
            self.target_infos.push(AvPair::MsvAvEOL);
            self.negociate_flags
                .set_flag(flags::NTLMSSP_NEGOTIATE_TARGET_INFO);
        } else {
            let index = self.target_infos.len() - 1;
            self.target_infos.insert(index, info);
        }
    }

    pub fn target_infos_add_computername(&mut self, computername: impl Into<String>) -> &mut Self {
        self.add_target_info(AvPair::MsvAvNbComputerName(computername.into()));
        self
    }

    pub fn target_infos_add_domainname(&mut self, domainname: impl Into<String>) -> &mut Self {
        self.add_target_info(AvPair::MsvAvNbDomainName(domainname.into()));
        self
    }

    pub fn target_infos_add_dnscomputername(
        &mut self,
        dnscomputername: impl Into<String>,
    ) -> &mut Self {
        self.add_target_info(AvPair::MsvAvDnsComputerName(dnscomputername.into()));
        self
    }

    pub fn target_infos_add_dnsdomainname(
        &mut self,
        dnsdomainname: impl Into<String>,
    ) -> &mut Self {
        self.add_target_info(AvPair::MsvAvDnsDomainName(dnsdomainname.into()));
        self
    }

    pub fn target_infos_add_dnstreename(&mut self, dnstreename: impl Into<String>) -> &mut Self {
        self.add_target_info(AvPair::MsvAvDnsTreeName(dnstreename.into()));
        self
    }

    pub fn target_infos_add_flags(&mut self, flags: MsvAvFlags) -> &mut Self {
        self.add_target_info(AvPair::MsvAvFlags(flags));
        self
    }

    pub fn target_infos_add_timestamp(&mut self, timestamp: FileTime) -> &mut Self {
        self.add_target_info(AvPair::MsvAvTimestamp(timestamp));
        self
    }

    pub fn target_infos_add_singlehost(&mut self, singlehost: SingleHostData) -> &mut Self {
        self.add_target_info(AvPair::MsvAvSingleHost(singlehost));
        self
    }

    pub fn target_infos_add_targetname(&mut self, targetname: impl Into<String>) -> &mut Self {
        self.add_target_info(AvPair::MsvAvTargetName(targetname.into()));
        self
    }

    pub fn target_infos_add_channelbindings(&mut self, channelbindings: [u8; 16]) -> &mut Self {
        self.add_target_info(AvPair::MsvAvChannelBindings(channelbindings));
        self
    }

    pub fn fill_from_env(&mut self) {
        if let Ok(computer_name) = env::var("COMPUTERNAME") {
            self.target_infos_add_computername(computer_name.to_uppercase());
        }
        if let Ok(dns_computer_name) = env::var("COMPUTERDNSNAME") {
            self.target_infos_add_dnscomputername(dns_computer_name);
        }
        if let Ok(domain_name) = env::var("USERDOMAIN") {
            self.target_infos_add_domainname(domain_name.to_uppercase());
        }
        if let Ok(dns_domain_name) = env::var("USERDNSDOMAIN") {
            self.target_infos_add_dnsdomainname(dns_domain_name);
        }
    }
}

impl Default for Challenge {
    fn default() -> Self {
        let mut me = Self {
            target_name: None,
            negociate_flags: Flags::default(),
            server_challenge: Default::default(),
            target_infos: Vec::new(),
            version: Default::default(),
        };

        me.fill_from_env();
        me
    }
}

impl fmt::Debug for Challenge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Challenge")
            .field("target_name", &self.target_name)
            .field("negociate_flags", &self.negociate_flags)
            .field("server_challenge", &self.server_challenge)
            .field("target_infos", &self.target_infos)
            .finish()
    }
}

impl<'a> Wire<'a> for Challenge {
    fn serialize_into<W>(&self, writer: &mut W) -> std::io::Result<usize>
    where
        W: std::io::Write,
    {
        const PAYLOAD_OFFSET: usize = 48;

        let mut payload = Vec::with_capacity(PAYLOAD_OFFSET * 2);
        payload.resize(PAYLOAD_OFFSET, 0);
        let mut written = 0;

        self.version.serialize_into(&mut payload)?;

        payload.extend_from_slice(&self.version[..]);

        writer.write_all(&SIGNATURE[..])?;
        written += &SIGNATURE[..].len();
        written += write_u32(writer, MESSAGE_TYPE)?;
        written += Field::append(self.target_name.as_ref(), &mut payload, writer)?;
        written += self.negociate_flags.serialize_into(writer)?;
        written += write_u64(writer, self.server_challenge)?;
        written += write_u64(writer, 0)?;
        written += Field::append_many(&self.target_infos, &mut payload, writer)?;

        assert_eq!(written, PAYLOAD_OFFSET);
        writer.write_all(&payload[PAYLOAD_OFFSET..])?;
        written += payload.len();

        Ok(written)
    }

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: super::NomError<'a>,
    {
        let (
            _rest,
            (
                target_name_field,
                negociate_flags,
                server_challenge,
                _reserved,
                target_infos_field,
                version,
            ),
        ) = context(
            "Challenge",
            preceded(
                tuple((tag(SIGNATURE), verify(le_u32, |mt| *mt == MESSAGE_TYPE))),
                tuple((
                    Field::deserialize,
                    Flags::deserialize,
                    le_u64,
                    verify(le_u64, |reserved| *reserved == 0),
                    Field::deserialize,
                    Version::deserialize,
                )),
            ),
        )(input)?;

        let target_name = target_name_field.get_data_if(
            "target_name",
            input,
            negociate_flags.has_flag(flags::NTLMSSP_REQUEST_TARGET),
        )?;
        let target_infos = target_infos_field.get_many_if("target_infos", input, true)?;

        if let Some(last) = target_infos.last() {
            if !matches!(last, AvPair::MsvAvEOL) {
                let target_infos_data = &input[target_infos_field.get_range()];
                return Err(nom::Err::Error(E::add_context(
                    target_infos_data,
                    "Challenge/TargetInfos/EOL",
                    E::from_error_kind(target_infos_data, nom::error::ErrorKind::Verify),
                )));
            }
        }

        Ok((
            &b""[..],
            Self {
                target_name,
                negociate_flags,
                server_challenge,
                target_infos,
                version,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode() {
        let m = "TlRMTVNTUAACAAAAEAAQADAAAAAFgominWXBG0VA2i4AAAAAAAAAAHYAdgBAAAAAQwBJAFMAQwBPAEwAQQBCAAIAEABDAEkAUwBDAE8ATABBAEIAAQAQAFAATwBTAEUASQBEAE8ATgAEABgAYwBpAHMAYwBvAGwAYQBiAC4AYwBvAG0AAwAqAHAAbwBzAGUAaQBkAG8AbgAuAGMAaQBzAGMAbwBsAGEAYgAuAGMAbwBtAAAAAAA=";
        let challenge_message = Challenge {
            target_name: Some("CISCOLAB".into()),
            negociate_flags: Flags(2726920709),
            server_challenge: 3376081536230188445,
            target_infos: vec![
                AvPair::MsvAvNbDomainName("CISCOLAB".into()),
                AvPair::MsvAvNbComputerName("POSEIDON".into()),
                AvPair::MsvAvDnsDomainName("ciscolab.com".into()),
                AvPair::MsvAvDnsComputerName("poseidon.ciscolab.com".into()),
                AvPair::MsvAvEOL,
            ],
            version: Version::from([67, 0, 73, 0, 83, 0, 67, 0]),
        };

        let message = base64::decode(m).unwrap();
        let maybe_decoded_message =
            Challenge::deserialize::<nom::error::VerboseError<&[u8]>>(&message[..]);
        let (_, decoded_message) = maybe_decoded_message.unwrap();
        pretty_assertions::assert_eq!(decoded_message, challenge_message);
        eprintln!("challenge_message = {:#x?}", &challenge_message);
    }

    #[test]
    fn encode() {
        let mut challenge_message = Challenge::default();
        challenge_message
            .set_target_name(Some("CISCOLAB"))
            .target_infos_add_domainname("CISCOLAB")
            .target_infos_add_computername("POSEIDON")
            .target_infos_add_dnsdomainname("ciscolab.com")
            .target_infos_add_dnscomputername("poseidon.ciscolab.com");
        challenge_message.server_challenge = 3376081536230188445;

        let ser = challenge_message.serialize();
        pretty_assertions::assert_eq!(
            challenge_message,
            Challenge::deserialize::<()>(&ser[..]).unwrap().1
        );
    }
}
