use crate::{
    crypto::{hmac_md5, lm::LmHash, nt::NtHash},
    messages::{
        flags::Flags,
        structures::{
            AvPair, ClientChallenge, FileTime, Lmv2Challenge, NtProofStr, Ntv2Challenge,
            Response16, ServerChallenge, SessionBaseKey,
        },
        Wire,
    },
};

use hmac::{Hmac, Mac};

pub fn compute_response(
    _flags: &Flags,
    response_key_nt: &NtHash,
    response_key_lm: &LmHash,
    server_challenge: &ServerChallenge,
    client_challenge: &ClientChallenge,
    time: Option<&FileTime>,
    server_name: &[AvPair],
) -> (NtProofStr, Lmv2Challenge, Ntv2Challenge, SessionBaseKey) {
    // TODO: handle anonymous authentication if user and password are empty
    let nt_challenge = Ntv2Challenge {
        timestamp: time.map(|ts| ts.clone()).unwrap_or_else(FileTime::now),
        challenge_from_client: client_challenge.clone(),
        target_infos: server_name.to_vec(),
    };
    let mut temp = nt_challenge.serialize();
    temp.extend_from_slice(&[0, 0, 0, 0][..]);
    let mut input = Vec::from(&**server_challenge);
    input.extend_from_slice(&temp[..]);

    let mut nt_proof_str = NtProofStr::default();
    hmac_md5(&response_key_nt[..], &input[..], &mut nt_proof_str[..]);

    let mut mac = <Hmac<md5::Md5>>::new_from_slice(&response_key_lm[..]).unwrap();
    mac.update(server_challenge);
    mac.update(client_challenge);
    let mut response = Response16::default();
    response.copy_from_slice(&mac.finalize().into_bytes()[..]);

    let lm_challenge = Lmv2Challenge {
        response,
        challenge_from_client: client_challenge.clone(),
    };

    let mut session_base_key = SessionBaseKey::default();
    hmac_md5(
        &response_key_nt[..],
        &nt_proof_str[..],
        &mut session_base_key,
    );

    (nt_proof_str, lm_challenge, nt_challenge, session_base_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::encrypt_random_session_key;
    use crate::crypto::tests::*;
    use crate::messages::flags::*;
    use crate::messages::structures::*;

    const FLAGS: u32 = (1 << NTLMSSP_NEGOTIATE_KEY_EXCH)
        | (1 << NTLMSSP_NEGOTIATE_56)
        | (1 << NTLMSSP_NEGOTIATE_128)
        | (1 << NTLMSSP_NEGOTIATE_VERSION)
        | (1 << NTLMSSP_NEGOTIATE_TARGET_INFO)
        | (1 << NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)
        | (1 << NTLMSSP_TARGET_TYPE_SERVER)
        | (1 << NTLMSSP_NEGOTIATE_ALWAYS_SIGN)
        | (1 << NTLMSSP_NEGOTIATE_NTLM)
        | (1 << NTLMSSP_NEGOTIATE_SEAL)
        | (1 << NTLMSSP_NEGOTIATE_SIGN)
        | (1 << NTLM_NEGOTIATE_OEM)
        | (1 << NTLMSSP_NEGOTIATE_UNICODE);

    #[test]
    fn compute_test() {
        let temp = [
            0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x0c, 0x00, 0x44, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x69, 0x00,
            0x6e, 0x00, 0x01, 0x00, 0x0c, 0x00, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00,
            0x65, 0x00, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let nt_challenge = Ntv2Challenge {
            timestamp: FileTime { low: 0, high: 0 },
            challenge_from_client: [0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa].into(),
            target_infos: vec![
                AvPair::MsvAvNbDomainName("Domain".into()),
                AvPair::MsvAvNbComputerName("Server".into()),
                AvPair::MsvAvEOL,
            ],
        };
        let mut buffer = nt_challenge.serialize();
        buffer.extend_from_slice(&[0, 0, 0, 0][..]);
        pretty_assertions::assert_eq!(&temp[..], &buffer[..]);
    }

    #[test]
    fn lmv2_response() {
        let flags = Flags(FLAGS);
        let hash: NtHash = [
            0x0c, 0x86, 0x8a, 0x40, 0x3b, 0xfd, 0x7a, 0x93, 0xa3, 0x00, 0x1e, 0xf2, 0x2e, 0xf0,
            0x2e, 0x3f,
        ]
        .into();
        let lm_response = Lmv2Challenge {
            response: [
                0x86, 0xc3, 0x50, 0x97, 0xac, 0x9c, 0xec, 0x10, 0x25, 0x54, 0x76, 0x4a, 0x57, 0xcc,
                0xcc, 0x19,
            ]
            .into(),
            challenge_from_client: [0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa].into(),
        };
        let nt_proof_str: NtProofStr = [
            0x68, 0xcd, 0x0a, 0xb8, 0x51, 0xe5, 0x1c, 0x96, 0xaa, 0xbc, 0x92, 0x7b, 0xeb, 0xef,
            0x6a, 0x1c,
        ]
        .into();
        let session_base_key: SessionBaseKey = [
            0x8d, 0xe4, 0x0c, 0xca, 0xdb, 0xc1, 0x4a, 0x82, 0xf1, 0x5c, 0xb0, 0xad, 0x0d, 0xe9,
            0x5c, 0xa3,
        ]
        .into();

        let server_name = vec![
            AvPair::MsvAvNbDomainName("Domain".into()),
            AvPair::MsvAvNbComputerName("Server".into()),
            AvPair::MsvAvEOL,
        ];

        let (nps, lmv2_challenge, _ntv2_challenge, sbk) = compute_response(
            &flags,
            &hash,
            &hash,
            &SERVER_CHALLENGE.into(),
            &CLIENT_CHALLENGE.into(),
            Some(&TIME),
            &server_name[..],
        );
        pretty_assertions::assert_eq!(session_base_key, sbk);
        pretty_assertions::assert_eq!(nt_proof_str, nps);
        pretty_assertions::assert_eq!(lmv2_challenge, lm_response);

        let key_exchange_key = session_base_key.clone().into();

        let encrypted_random_session_key: EncryptedRandomSessionKey = [
            0xc5, 0xda, 0xd2, 0x54, 0x4f, 0xc9, 0x79, 0x90, 0x94, 0xce, 0x1c, 0xe9, 0x0b, 0xc9,
            0xd0, 0x3e,
        ]
        .into();

        let (_, ersk) =
            encrypt_random_session_key(&flags, &key_exchange_key, Some(RANDOM_SESSION_KEY.into()));
        eprintln!("kek  = {:?}", &key_exchange_key);
        eprintln!("ersk = {:?}", &ersk);
        pretty_assertions::assert_eq!(encrypted_random_session_key, ersk);
    }
}
