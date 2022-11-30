use std::env;

use nom::bytes::complete::tag;
use nom::combinator::{cond, verify};
use nom::error::context;
use nom::number::complete::{le_u32, le_u64};
use nom::sequence::{preceded, tuple};

use crate::messages::{
    flags::{self, Flags},
    structures::{AvPair, FileTime, MsvAvFlags, ServerChallenge, SingleHostData, Version},
    unicode_string::UnicodeString,
    utils::{write_u32, write_u64},
    Field, Wire, SIGNATURE,
};

const MESSAGE_TYPE: u32 = 0x00000002;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Challenge {
    target_name: Option<UnicodeString>,
    pub negotiate_flags: Flags,
    pub server_challenge: ServerChallenge,
    pub(crate) target_infos: Vec<AvPair>,
    pub version: Option<Version>,
}

impl Challenge {
    generate_setter_getter!(
        target_name,
        flags::NTLMSSP_REQUEST_TARGET,
        UnicodeString,
        set_target_name,
        get_target_name
    );

    fn add_target_info(&mut self, info: AvPair) {
        if self.target_infos.is_empty() {
            self.target_infos.push(info);
            self.target_infos.push(AvPair::MsvAvEOL);
            self.negotiate_flags
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

    pub fn get_target_infos(&self) -> &[AvPair] {
        &self.target_infos[..]
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

        if let Some(ref version) = self.version {
            version.serialize_into(&mut payload).unwrap();
        }

        writer.write_all(&SIGNATURE[..])?;
        written += &SIGNATURE[..].len();
        written += write_u32(writer, MESSAGE_TYPE)?;
        written += Field::append(self.target_name.as_ref(), &mut payload, writer)?;
        written += self.negotiate_flags.serialize_into(writer)?;
        written += self.server_challenge.serialize_into(writer)?;
        written += write_u64(writer, 0)?;
        written += Field::append_many(&self.target_infos, &mut payload, writer)?;

        assert_eq!(written, PAYLOAD_OFFSET);
        writer.write_all(&payload[PAYLOAD_OFFSET..])?;
        written += payload[PAYLOAD_OFFSET..].len();

        Ok(written)
    }

    fn deserialize<E>(input: &'a [u8]) -> nom::IResult<&'a [u8], Self, E>
    where
        E: super::NomError<'a>,
    {
        let parse_reserved = le_u64;

        #[cfg(feature = "strict")]
        let parse_reserved = verify(parse_reserved, |reserved| *reserved == 0);
        let (
            rest,
            (target_name_field, negotiate_flags, server_challenge, _reserved, target_infos_field),
        ) = context(
            "Challenge",
            preceded(
                tuple((tag(SIGNATURE), verify(le_u32, |mt| *mt == MESSAGE_TYPE))),
                tuple((
                    context("target_name_field", Field::deserialize),
                    context("negotiate_flags", Flags::deserialize),
                    ServerChallenge::deserialize,
                    context("reserved", parse_reserved),
                    context("target_infos_field", Field::deserialize),
                )),
            ),
        )(input)?;
        let (_, version) = cond(
            negotiate_flags.has_flag(flags::NTLMSSP_NEGOTIATE_VERSION),
            context("version", Version::deserialize),
        )(rest)?;

        let target_name = target_name_field.get_data_if(
            "target_name",
            input,
            negotiate_flags.has_flag(flags::NTLMSSP_REQUEST_TARGET) || true,
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
                negotiate_flags,
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
    use crate::messages::flags::tests::{FLAGS_NTLMV1, FLAGS_NTLMV2};

    #[test]
    fn decode_ntlmv1() {
        let raw_message = &[
            0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x02, 0x00, 0x00, 0x00, 0x0c, 0x00,
            0x0c, 0x00, 0x38, 0x00, 0x00, 0x00, 0x33, 0x82, 0x0a, 0x82, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x70, 0x17, 0x00, 0x00, 0x00, 0x0f,
            0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00,
        ][..];
        let challenge_message = Challenge {
            target_name: Some("Server".into()),
            negotiate_flags: Flags(FLAGS_NTLMV1),
            server_challenge: [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef].into(),
            target_infos: vec![],
            version: Some(Version {
                major: 6,
                minor: 0,
                build: 0x1770,
                revision_count: 0x0f,
            }),
        };

        let maybe_decoded_message =
            Challenge::deserialize::<nom::error::VerboseError<&[u8]>>(&raw_message[..]);
        let (_, decoded_message) = maybe_decoded_message.unwrap();
        pretty_assertions::assert_eq!(decoded_message, challenge_message);
        eprintln!("challenge_message = {:#x?}", &challenge_message);
    }

    #[test]
    fn decode_ntlmv2() {
        let raw_message = &[
            0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x02, 0x00, 0x00, 0x00, 0x0c, 0x00,
            0x0c, 0x00, 0x38, 0x00, 0x00, 0x00, 0x33, 0x82, 0x8a, 0xe2, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00,
            0x24, 0x00, 0x44, 0x00, 0x00, 0x00, 0x06, 0x00, 0x70, 0x17, 0x00, 0x00, 0x00, 0x0f,
            0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x02, 0x00,
            0x0c, 0x00, 0x44, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6e, 0x00,
            0x01, 0x00, 0x0c, 0x00, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x65, 0x00,
            0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
        ][..];
        let challenge_message = Challenge {
            target_name: Some("Server".into()),
            negotiate_flags: Flags(FLAGS_NTLMV2),
            server_challenge: [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef].into(),
            target_infos: vec![
                AvPair::MsvAvNbDomainName("Domain".into()),
                AvPair::MsvAvNbComputerName("Server".into()),
                AvPair::MsvAvEOL,
            ],
            version: Some(Version {
                major: 6,
                minor: 0,
                build: 0x1770,
                revision_count: 0x0f,
            }),
        };

        let maybe_decoded_message =
            Challenge::deserialize::<nom::error::VerboseError<&[u8]>>(&raw_message[..]);
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
        challenge_message.server_challenge =
            [0x9d, 0x65, 0xc1, 0x1b, 0x45, 0x40, 0xda, 0x2e].into();

        let ser = challenge_message.serialize();
        pretty_assertions::assert_eq!(
            challenge_message,
            Challenge::deserialize::<()>(&ser[..]).unwrap().1
        );
    }
}
