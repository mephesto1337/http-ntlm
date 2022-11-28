use crate::{
    crypto::{lm::LmHash, nt::NtHash},
    messages::{
        flags::{Flags, NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY},
        structures::{
            ClientChallenge, Lmv1Challenge, Ntv1Challenge, ServerChallenge, SessionBaseKey,
        },
    },
};

/// MS-NLMP 3.1.1.1 Variables Internal to the Protocol
// pub const NO_LM_RESPONSE_NTLM_V1: bool = true;

pub fn compute_response(
    flags: &Flags,
    response_key_nt: &NtHash,
    response_key_lm: &LmHash,
    server_challenge: &ServerChallenge,
    client_challenge: &ClientChallenge,
    lm_response_ntlm_v1: bool,
) -> (Lmv1Challenge, Ntv1Challenge, SessionBaseKey) {
    // TODO: handle anonymous authentication if user and password are empty
    let mut session_base_key = SessionBaseKey::default();
    super::md4(response_key_nt, &mut session_base_key);
    if flags.has_flag(NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) {
        let mut server_client_challenge = [0u8; 16];
        (&mut server_client_challenge[..8]).copy_from_slice(server_challenge);
        (&mut server_client_challenge[8..]).copy_from_slice(client_challenge);
        let mut data = [0u8; 16];

        super::md5(&server_client_challenge[..], &mut data[..]);

        let nt_response = Ntv1Challenge {
            response: super::desl(response_key_nt, &data[..8]).into(),
        };
        let lm_response = Lmv1Challenge::from_client_challenge(client_challenge);
        (lm_response, nt_response, session_base_key)
    } else {
        let nt_response = Ntv1Challenge {
            response: super::desl(response_key_nt, server_challenge),
        };
        let lm_response = if lm_response_ntlm_v1 {
            Lmv1Challenge {
                response: nt_response.response.clone(),
            }
        } else {
            Lmv1Challenge {
                response: super::desl(response_key_lm, server_challenge),
            }
        };
        (lm_response, nt_response, session_base_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::tests::*;
    use crate::crypto::{encrypt_random_session_key, kxkey};
    use crate::messages::flags::*;
    use crate::messages::structures::*;

    #[test]
    fn without_extented_session_security() {
        let nt_response = Ntv1Challenge {
            response: [
                0x67, 0xc4, 0x30, 0x11, 0xf3, 0x02, 0x98, 0xa2, 0xad, 0x35, 0xec, 0xe6, 0x4f, 0x16,
                0x33, 0x1c, 0x44, 0xbd, 0xbe, 0xd9, 0x27, 0x84, 0x1f, 0x94,
            ]
            .into(),
        };
        let lm_response = Lmv1Challenge {
            response: [
                0x98, 0xde, 0xf7, 0xb8, 0x7f, 0x88, 0xaa, 0x5d, 0xaf, 0xe2, 0xdf, 0x77, 0x96, 0x88,
                0xa1, 0x72, 0xde, 0xf1, 0x1c, 0x7d, 0x5c, 0xcd, 0xef, 0x13,
            ]
            .into(),
        };
        let session_base_key: SessionBaseKey = SESSION_BASE_KEY.into();

        let flags = Flags(FLAGS);
        let (lm, nt, sbk) = super::compute_response(
            &flags,
            &NT_HASH,
            &LM_HASH,
            &SERVER_CHALLENGE.into(),
            &CLIENT_CHALLENGE.into(),
            false,
        );

        pretty_assertions::assert_eq!(nt_response, nt);
        pretty_assertions::assert_eq!(lm_response, lm);
        pretty_assertions::assert_eq!(session_base_key, sbk);
    }

    #[test]
    fn with_extented_session_security() {
        let nt_response = Ntv1Challenge {
            response: [
                0x75, 0x37, 0xf8, 0x03, 0xae, 0x36, 0x71, 0x28, 0xca, 0x45, 0x82, 0x04, 0xbd, 0xe7,
                0xca, 0xf8, 0x1e, 0x97, 0xed, 0x26, 0x83, 0x26, 0x72, 0x32,
            ]
            .into(),
        };
        let lm_response = Lmv1Challenge {
            response: [
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
            .into(),
        };
        let session_base_key: SessionBaseKey = SESSION_BASE_KEY.into();

        let mut flags = Flags(FLAGS);
        flags.set_flag(NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY);
        let (lm, nt, sbk) = super::compute_response(
            &flags,
            &NT_HASH,
            &LM_HASH,
            &SERVER_CHALLENGE.into(),
            &CLIENT_CHALLENGE.into(),
            false,
        );
        pretty_assertions::assert_eq!(nt_response, nt);
        pretty_assertions::assert_eq!(lm_response, lm);
        pretty_assertions::assert_eq!(session_base_key, sbk);
    }

    #[test]
    fn negociate_lm_key() {
        let session_base_key: SessionBaseKey = SESSION_BASE_KEY.into();
        let key_exchange_key: KeyExchangeKey = [
            0xb0, 0x9e, 0x37, 0x9f, 0x7f, 0xbe, 0xcb, 0x1e, 0xaf, 0x0a, 0xfd, 0xcb, 0x03, 0x83,
            0xc8, 0xa0,
        ]
        .into();
        let lm_response = Lmv1Challenge {
            response: [
                0x98, 0xde, 0xf7, 0xb8, 0x7f, 0x88, 0xaa, 0x5d, 0xaf, 0xe2, 0xdf, 0x77, 0x96, 0x88,
                0xa1, 0x72, 0xde, 0xf1, 0x1c, 0x7d, 0x5c, 0xcd, 0xef, 0x13,
            ]
            .into(),
        };

        let mut flags = Flags(FLAGS);
        flags.set_flag(NTLMSSP_NEGOTIATE_LM_KEY);
        let kek = kxkey(
            &flags,
            &session_base_key,
            &lm_response.response[..8],
            &LM_HASH,
            None,
        );
        pretty_assertions::assert_eq!(key_exchange_key, kek);
    }

    #[test]
    fn encrypted_session_key() {
        let key_exchange_key: KeyExchangeKey = [
            0xd8, 0x72, 0x62, 0xb0, 0xcd, 0xe4, 0xb1, 0xcb, 0x74, 0x99, 0xbe, 0xcc, 0xcd, 0xf1,
            0x07, 0x84,
        ]
        .into();
        let mut flags = Flags(FLAGS);

        let encrypted_random_session_key: EncryptedRandomSessionKey = [
            0x51, 0x88, 0x22, 0xb1, 0xb3, 0xf3, 0x50, 0xc8, 0x95, 0x86, 0x82, 0xec, 0xbb, 0x3e,
            0x3c, 0xb7,
        ]
        .into();
        pretty_assertions::assert_eq!(
            encrypted_random_session_key,
            encrypt_random_session_key(&flags, &key_exchange_key, Some(RANDOM_SESSION_KEY.into()))
                .1
        );

        flags.set_flag(NTLMSSP_REQUEST_NON_NT_SESSION_KEY);
        let key_exchange_key: KeyExchangeKey = [
            0xe5, 0x2c, 0xac, 0x67, 0x41, 0x9a, 0x9a, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ]
        .into();
        let encrypted_random_session_key: EncryptedRandomSessionKey = [
            0x74, 0x52, 0xca, 0x55, 0xc2, 0x25, 0xa1, 0xca, 0x04, 0xb4, 0x8f, 0xae, 0x32, 0xcf,
            0x56, 0xfc,
        ]
        .into();
        pretty_assertions::assert_eq!(
            encrypted_random_session_key,
            encrypt_random_session_key(&flags, &key_exchange_key, Some(RANDOM_SESSION_KEY.into()))
                .1
        );

        flags.clear_flag(NTLMSSP_REQUEST_NON_NT_SESSION_KEY);
        flags.set_flag(NTLMSSP_NEGOTIATE_LM_KEY);
        let key_exchange_key: KeyExchangeKey = [
            0xb0, 0x9e, 0x37, 0x9f, 0x7f, 0xbe, 0xcb, 0x1e, 0xaf, 0x0a, 0xfd, 0xcb, 0x03, 0x83,
            0xc8, 0xa0,
        ]
        .into();
        let encrypted_random_session_key: EncryptedRandomSessionKey = [
            0x4c, 0xd7, 0xbb, 0x57, 0xd6, 0x97, 0xef, 0x9b, 0x54, 0x9f, 0x02, 0xb8, 0xf9, 0xb3,
            0x78, 0x64,
        ]
        .into();
        pretty_assertions::assert_eq!(
            encrypted_random_session_key,
            encrypt_random_session_key(&flags, &key_exchange_key, Some(RANDOM_SESSION_KEY.into()))
                .1
        );
    }
}
