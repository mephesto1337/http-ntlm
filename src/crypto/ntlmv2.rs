use crate::{
    crypto::{hmac_md5, lm::LmHash, nt::NtHash},
    messages::{
        flags::{
            Flags, NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY, NTLMSSP_NEGOTIATE_KEY_EXCH,
            NTLMSSP_NEGOTIATE_LM_KEY, NTLMSSP_NEGOTIATE_SEAL, NTLMSSP_NEGOTIATE_SIGN,
            NTLMSSP_REQUEST_NON_NT_SESSION_KEY,
        },
        structures::{
            AvPair, ClientChallenge, EncryptedRandomSessionKey, ExportedSessionKey, FileTime,
            KeyExchangeKey, Lmv2Challenge, NtProofStr, Ntv2Challenge, Response16, ServerChallenge,
            SessionBaseKey,
        },
        Wire,
    },
};

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

    let mut input = [0u8; 16];
    (&mut input[..8]).copy_from_slice(&**server_challenge);
    (&mut input[8..]).copy_from_slice(&**client_challenge);
    let mut response = Response16::default();
    hmac_md5(&response_key_lm[..], &input[..], &mut response[..]);

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

pub fn kxkey(
    flags: &Flags,
    session_base_key: &SessionBaseKey,
    lm_response: &Lmv2Challenge,
    lm_hash: &LmHash,
    server_challenge: Option<&ServerChallenge>,
) -> KeyExchangeKey {
    todo!();
}

pub fn encrypt_random_session_key(
    flags: &Flags,
    key_exchange_key: &KeyExchangeKey,
    exported_session_key: Option<ExportedSessionKey>,
) -> (ExportedSessionKey, EncryptedRandomSessionKey) {
    todo!();
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn ntowfv2 {
        let hash = [0x0c, 0x86, 0x8a, 0x40, 0x3b, 0xfd, 0x7a, 0x93, 0xa3, 0x00, 0x1e, 0xf2, 0x2e, 0xf0, 0x2e, 0x3f];
        todo!();
    }
    

    #[test]
    fn session_base_key() {
        let key: SessionBaseKey = [
            0x8d, 0xe4, 0x0c, 0xca, 0xdb, 0xc1, 0x4a, 0x82, 0xf1, 0x5c, 0xb0, 0xad, 0x0d, 0xe9,
            0x5c, 0xa3,
        ].into();

    }
}
