use std::marker::PhantomData;

use crate::{
    crypto::{encrypt_random_session_key, kxkey, lm::LmHash, nt::NtHash, ntlmv1, ntlmv2},
    messages::{
        flags,
        structures::{AvPair, ClientChallenge, Version},
        Authenticate, Challenge, Negotiate, Wire,
    },
    NtlmVersion,
};

#[derive(Debug, Default)]
enum ClientState {
    #[default]
    New,
    NegociateSent(Negotiate),
    ChallengeReceived(Negotiate, Challenge),
    AuthenticateSent(Negotiate, Challenge, Authenticate),
}

pub struct Client<V> {
    state: ClientState,
    username: String,
    lm_hash: LmHash,
    nt_hash: NtHash,
    ntlmv2_hash: NtHash,
    domain: String,
    workstation: Option<String>,
    target: String,
    buffer: Vec<u8>,
    version: Option<Version>,
    _version: PhantomData<V>,
}

impl<V> Client<V>
where
    V: NtlmVersion,
{
    pub fn new(username: String, password: String, target: String) -> Self {
        if let Some((domain, user)) = username.split_once('\\') {
            return Self::new_with_domain(user.to_owned(), domain.to_owned(), password, target);
        }
        if let Some((user, domain)) = username.split_once('@') {
            Self::new_with_domain(user.to_owned(), domain.to_owned(), password, target)
        } else {
            Self::new_with_domain(username.to_owned(), "".to_owned(), password, target)
        }
    }

    pub fn new_with_domain(
        username: String,
        domain: String,
        password: String,
        target: String,
    ) -> Self {
        let (lm_hash, nt_hash, ntlmv2_hash) =
            Self::compute_ntlm_hashes(username.as_str(), password.as_str(), domain.as_str());
        Self {
            state: ClientState::New,
            username,
            lm_hash,
            nt_hash,
            ntlmv2_hash,
            domain,
            workstation: Self::get_workstation_name(),
            target,
            buffer: Vec::with_capacity(128),
            version: None,
            _version: PhantomData,
        }
    }

    fn compute_ntlm_hashes(
        username: &str,
        password: &str,
        domain: &str,
    ) -> (LmHash, NtHash, NtHash) {
        let lm_hash = crate::crypto::lm::lmowfv1(password);
        let nt_hash = crate::crypto::nt::ntowfv1(password);
        let ntlmv2_hash = crate::crypto::nt::ntowfv2(username, &nt_hash, domain);

        (lm_hash, nt_hash, ntlmv2_hash)
    }

    pub fn send_negociate(&mut self) -> &[u8] {
        let mut msg = Negotiate::default();
        msg.negotiate_flags.set_flag(flags::NTLM_NEGOTIATE_OEM);
        msg.negotiate_flags.set_flag(flags::NTLMSSP_NEGOTIATE_128);
        msg.negotiate_flags
            .set_flag(flags::NTLMSSP_NEGOTIATE_ALWAYS_SIGN);
        msg.negotiate_flags.set_flag(flags::NTLMSSP_NEGOTIATE_SEAL);
        msg.negotiate_flags.set_flag(flags::NTLMSSP_NEGOTIATE_SIGN);
        msg.negotiate_flags
            .set_flag(flags::NTLMSSP_NEGOTIATE_UNICODE);
        msg.negotiate_flags
            .set_flag(flags::NTLMSSP_TARGET_TYPE_SERVER);

        match V::version() {
            0 => {
                msg.negotiate_flags.set_flag(flags::NTLMSSP_NEGOTIATE_NTLM);
                msg.negotiate_flags
                    .set_flag(flags::NTLMSSP_NEGOTIATE_LM_KEY);
                msg.negotiate_flags
                    .set_flag(flags::NTLMSSP_NEGOTIATE_KEY_EXCH);
            }
            1 => {
                msg.negotiate_flags.set_flag(flags::NTLMSSP_NEGOTIATE_NTLM);
                msg.negotiate_flags
                    .set_flag(flags::NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY);
            }
            2 | 3 | 4 | 5 => {
                msg.negotiate_flags
                    .set_flag(flags::NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY);
                msg.negotiate_flags
                    .set_flag(flags::NTLMSSP_NEGOTIATE_KEY_EXCH);
                msg.negotiate_flags
                    .set_flag(flags::NTLMSSP_NEGOTIATE_TARGET_INFO);
            }
            _ => {
                panic!("Only 0 to 5 are supported values for NTLM version");
            }
        }
        if let Some(v) = self.version.as_ref().map(|v| v.clone()) {
            msg.negotiate_flags
                .set_flag(flags::NTLMSSP_NEGOTIATE_VERSION);
            msg.version = Some(v);
        }
        if !self.domain.is_empty() {
            msg.set_domain_name(Some(self.domain.clone()));
        }
        msg.negotiate_flags.set_flag(flags::NTLMSSP_REQUEST_TARGET);
        self.buffer.clear();
        let size = msg.serialize_into(&mut self.buffer).unwrap();
        self.state = ClientState::NegociateSent(msg);
        dbg!(self.buffer.len());
        dbg!(size);
        &self.buffer[..size]
    }

    pub fn recv_challenge(&mut self, challenge: Challenge) {
        if !matches!(self.state, ClientState::NegociateSent(_)) {
            return;
        }
        match std::mem::replace(&mut self.state, ClientState::New) {
            ClientState::NegociateSent(negotiate) => {
                self.state = ClientState::ChallengeReceived(negotiate, challenge);
            }
            _ => unreachable!(),
        }
    }

    fn get_challenge(&self) -> &Challenge {
        match self.state {
            ClientState::ChallengeReceived(_, ref c) => c,
            ClientState::AuthenticateSent(_, ref c, _) => c,
            _ => unreachable!("Invalid client state"),
        }
    }

    fn get_negotiate(&self) -> &Negotiate {
        match self.state {
            ClientState::ChallengeReceived(ref n, _) => n,
            ClientState::AuthenticateSent(ref n, _, _) => n,
            _ => unreachable!("Invalid client state"),
        }
    }

    fn send_authenticate_ntlmv1(&mut self, client_challenge: ClientChallenge) -> Authenticate {
        let challenge = self.get_challenge();
        let (lm_challenge, nt_challenge, session_base_key) = ntlmv1::compute_response(
            &challenge.negotiate_flags,
            &self.nt_hash,
            &self.lm_hash,
            &challenge.server_challenge,
            &client_challenge,
            V::version() != 0,
        );

        let key_exchange_key = kxkey(
            &challenge.negotiate_flags,
            &session_base_key,
            &lm_challenge.response[..8],
            &self.lm_hash,
            Some(&challenge.server_challenge),
        );

        let (exported_session_key, encrypted_random_session_key) =
            encrypt_random_session_key(&challenge.negotiate_flags, &key_exchange_key, None);

        let mut auth = Authenticate::default();
        auth.negotiate_flags = challenge.negotiate_flags;
        auth.lm_challenge_response = Some(lm_challenge.into());
        auth.nt_challenge_response = Some(nt_challenge.into());
        auth.domain = Some(self.domain.to_owned());
        auth.user = Some(self.username.to_owned());
        auth.workstation = None;
        auth.set_encrypted_random_session_key(Some(encrypted_random_session_key));
        // auth.mic = mic;
        auth.exported_session_key = Some(exported_session_key);
        auth
    }

    fn send_authenticate_ntlmv2(&mut self, client_challenge: ClientChallenge) -> Authenticate {
        let negotiate = self.get_negotiate();
        let challenge = self.get_challenge();
        let mut time = None;
        for val in &challenge.target_infos[..] {
            match val {
                AvPair::MsvAvTimestamp(ref ts) => {
                    time = Some(ts);
                    break;
                }
                _ => continue,
            }
        }
        let (nt_proof_str, lm_challenge, nt_challenge, session_base_key) = ntlmv2::compute_response(
            &challenge.negotiate_flags,
            &self.ntlmv2_hash,
            &self.ntlmv2_hash,
            &challenge.server_challenge,
            &client_challenge,
            time,
            &challenge.target_infos[..],
        );

        let key_exchange_key = session_base_key.clone().into();

        let (exported_session_key, encrypted_random_session_key) =
            encrypt_random_session_key(&challenge.negotiate_flags, &key_exchange_key, None);

        let mut auth = Authenticate::default();
        auth.lm_challenge_response = Some(lm_challenge.into());
        auth.nt_challenge_response = Some(nt_challenge.into());
        auth.domain = Some(self.domain.to_owned());
        auth.user = Some(self.username.to_owned());
        auth.workstation = None;
        auth.set_encrypted_random_session_key(Some(encrypted_random_session_key));
        auth.exported_session_key = Some(exported_session_key);
        auth.compute_mic(negotiate, challenge);

        auth
    }

    fn set_authenticated_state(&mut self, auth: Authenticate) {
        if !matches!(self.state, ClientState::ChallengeReceived(_, _)) {
            return;
        }
        match std::mem::replace(&mut self.state, ClientState::New) {
            ClientState::ChallengeReceived(n, c) => {
                self.state = ClientState::AuthenticateSent(n, c, auth);
            }
            _ => unreachable!(),
        }
    }

    fn get_workstation_name() -> Option<String> {
        if let Ok(computer_name) = std::env::var("COMPUTERNAME") {
            return Some(computer_name);
        }
        let hostname = std::fs::read_to_string("/etc/hostname").ok()?;
        let firstline = hostname.lines().next().unwrap();
        if let Some((cn, _)) = firstline.split_once('.') {
            Some(cn.trim().to_uppercase())
        } else {
            Some(firstline.trim().to_uppercase())
        }
    }

    pub fn send_authenticate(&mut self) -> &[u8] {
        let client_challenge = ClientChallenge::random();
        let mut auth = match V::version() {
            0 | 1 | 2 => self.send_authenticate_ntlmv1(client_challenge),
            3 | 4 | 5 => self.send_authenticate_ntlmv2(client_challenge),
            _ => unreachable!("Invalid version"),
        };
        if let Some(workstation) = self.workstation.as_ref().map(|w| w.clone()) {
            auth.workstation = Some(workstation);
        }
        if let Some(v) = self.version.as_ref().map(|v| v.clone()) {
            auth.negotiate_flags
                .set_flag(flags::NTLMSSP_NEGOTIATE_VERSION);
            auth.version = Some(v);
        }
        auth.negotiate_flags
            .clear_flag(flags::NTLMSSP_TARGET_TYPE_SERVER);
        auth.negotiate_flags.clear_flag(flags::NTLM_NEGOTIATE_OEM);
        auth.negotiate_flags
            .set_flag(flags::NTLMSSP_NEGOTIATE_TARGET_INFO);
        auth.negotiate_flags.set_flag(flags::NTLMSSP_REQUEST_TARGET);
        self.buffer.clear();
        auth.serialize_into(&mut self.buffer).unwrap();
        self.set_authenticated_state(auth);
        &self.buffer[..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NtlmV1;
    impl NtlmVersion for NtlmV1 {
        fn version() -> u32 {
            0
        }
    }

    #[test]
    fn ntlmv1() {
        let mut client = Client::<NtlmV1>::new_with_domain(
            "User".into(),
            "Domain".into(),
            "Password".into(),
            "".into(),
        );
        client.workstation = Some("COMPUTER".into());
        client.version = Some((5, 1, 2600).into());
        client.send_negociate();
        let raw_challenge = &[
            0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x02, 0x00, 0x00, 0x00, 0x0c, 0x00,
            0x0c, 0x00, 0x38, 0x00, 0x00, 0x00, 0x33, 0x82, 0x02, 0xe2, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x70, 0x17, 0x00, 0x00, 0x00, 0x0f,
            0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00,
        ][..];
        let (_, challenge) = Challenge::deserialize::<()>(raw_challenge).unwrap();
        client.recv_challenge(challenge);

        let raw_authenticate = &[
            0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x03, 0x00, 0x00, 0x00, 0x18, 0x00,
            0x18, 0x00, 0x6c, 0x00, 0x00, 0x00, 0x18, 0x00, 0x18, 0x00, 0x84, 0x00, 0x00, 0x00,
            0x0c, 0x00, 0x0c, 0x00, 0x48, 0x00, 0x00, 0x00, 0x08, 0x00, 0x08, 0x00, 0x54, 0x00,
            0x00, 0x00, 0x10, 0x00, 0x10, 0x00, 0x5c, 0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00,
            0x9c, 0x00, 0x00, 0x00, 0x35, 0x82, 0x80, 0xe2, 0x05, 0x01, 0x28, 0x0a, 0x00, 0x00,
            0x00, 0x0f, 0x44, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6e, 0x00,
            0x55, 0x00, 0x73, 0x00, 0x65, 0x00, 0x72, 0x00, 0x43, 0x00, 0x4f, 0x00, 0x4d, 0x00,
            0x50, 0x00, 0x55, 0x00, 0x54, 0x00, 0x45, 0x00, 0x52, 0x00, 0x98, 0xde, 0xf7, 0xb8,
            0x7f, 0x88, 0xaa, 0x5d, 0xaf, 0xe2, 0xdf, 0x77, 0x96, 0x88, 0xa1, 0x72, 0xde, 0xf1,
            0x1c, 0x7d, 0x5c, 0xcd, 0xef, 0x13, 0x67, 0xc4, 0x30, 0x11, 0xf3, 0x02, 0x98, 0xa2,
            0xad, 0x35, 0xec, 0xe6, 0x4f, 0x16, 0x33, 0x1c, 0x44, 0xbd, 0xbe, 0xd9, 0x27, 0x84,
            0x1f, 0x94, 0x51, 0x88, 0x22, 0xb1, 0xb3, 0xf3, 0x50, 0xc8, 0x95, 0x86, 0x82, 0xec,
            0xbb, 0x3e, 0x3c, 0xb7,
        ][..];

        let raw_authenticate_clnt = client.send_authenticate().to_owned();
        let auth_ref = Authenticate::deserialize::<()>(raw_authenticate).unwrap().1;
        let auth_clt = match client.state {
            ClientState::AuthenticateSent(_, _, a) => a,
            _ => unreachable!(),
        };
        pretty_assertions::assert_eq!(auth_clt, auth_ref);
        pretty_assertions::assert_eq!(raw_authenticate_clnt, raw_authenticate);
    }

    fn ntlmv1_challenge() {
        let mut client = Client::<NtlmV1>::new_with_domain(
            "User".into(),
            "Domain".into(),
            "Password".into(),
            "".into(),
        );
        client.send_negociate();
        let raw_challenge = &[
            0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x02, 0x00, 0x00, 0x00, 0x0c, 0x00,
            0x0c, 0x00, 0x38, 0x00, 0x00, 0x00, 0x33, 0x82, 0x02, 0xe2, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x70, 0x17, 0x00, 0x00, 0x00, 0x0f,
            0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00,
        ][..];
        let (_, challenge) = Challenge::deserialize::<()>(raw_challenge).unwrap();
        client.recv_challenge(challenge);
        let raw_authenticate = &[
            0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x03, 0x00, 0x00, 0x00, 0x18, 0x00,
            0x18, 0x00, 0x6c, 0x00, 0x00, 0x00, 0x18, 0x00, 0x18, 0x00, 0x84, 0x00, 0x00, 0x00,
            0x0c, 0x00, 0x0c, 0x00, 0x48, 0x00, 0x00, 0x00, 0x08, 0x00, 0x08, 0x00, 0x54, 0x00,
            0x00, 0x00, 0x10, 0x00, 0x10, 0x00, 0x5c, 0x00, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00,
            0x9c, 0x00, 0x00, 0x00, 0x35, 0x82, 0x80, 0xe2, 0x05, 0x01, 0x28, 0x0a, 0x00, 0x00,
            0x00, 0x0f, 0x44, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x69, 0x00, 0x6e, 0x00,
            0x55, 0x00, 0x73, 0x00, 0x65, 0x00, 0x72, 0x00, 0x43, 0x00, 0x4f, 0x00, 0x4d, 0x00,
            0x50, 0x00, 0x55, 0x00, 0x54, 0x00, 0x45, 0x00, 0x52, 0x00, 0x98, 0xde, 0xf7, 0xb8,
            0x7f, 0x88, 0xaa, 0x5d, 0xaf, 0xe2, 0xdf, 0x77, 0x96, 0x88, 0xa1, 0x72, 0xde, 0xf1,
            0x1c, 0x7d, 0x5c, 0xcd, 0xef, 0x13, 0x67, 0xc4, 0x30, 0x11, 0xf3, 0x02, 0x98, 0xa2,
            0xad, 0x35, 0xec, 0xe6, 0x4f, 0x16, 0x33, 0x1c, 0x44, 0xbd, 0xbe, 0xd9, 0x27, 0x84,
            0x1f, 0x94, 0x51, 0x88, 0x22, 0xb1, 0xb3, 0xf3, 0x50, 0xc8, 0x95, 0x86, 0x82, 0xec,
            0xbb, 0x3e, 0x3c, 0xb7,
        ][..];

        pretty_assertions::assert_eq!(client.send_authenticate(), raw_authenticate);
    }
}
