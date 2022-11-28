use std::marker::PhantomData;

use crate::{
    crypto::{encrypt_random_session_key, kxkey, lm::LmHash, nt::NtHash, ntlmv1, ntlmv2},
    messages::{
        flags,
        structures::{AvPair, ClientChallenge},
        Authenticate, Challenge, Negotiate, Wire,
    },
    NtlmVersion,
};

#[derive(Debug, Default)]
enum ClientState {
    #[default]
    New,
    NegociateSent(Option<Negotiate>),
    ChallengeReceived(Negotiate, Challenge),
    AuthenticateSent,
}

pub struct Client<V> {
    state: ClientState,
    username: String,
    lm_hash: LmHash,
    nt_hash: NtHash,
    ntlmv2_hash: NtHash,
    domain: String,
    target: String,
    buffer: Vec<u8>,
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
            let (lm_hash, nt_hash, ntlmv2_hash) =
                Self::compute_ntlm_hashes(username.as_str(), password.as_str(), "");
            Self {
                state: ClientState::New,
                username,
                lm_hash,
                nt_hash,
                ntlmv2_hash,
                domain: "".into(),
                target,
                buffer: Vec::with_capacity(128),
                _version: PhantomData,
            }
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
            target,
            buffer: Vec::with_capacity(128),
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
        match V::version() {
            0 => {
                msg.negociate_flags.set_flag(flags::NTLMSSP_NEGOTIATE_NTLM);
                msg.negociate_flags
                    .set_flag(flags::NTLMSSP_NEGOTIATE_LM_KEY);
            }
            1 => {
                msg.negociate_flags.set_flag(flags::NTLMSSP_NEGOTIATE_NTLM);
                msg.negociate_flags
                    .set_flag(flags::NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY);
            }
            2 | 3 | 4 | 5 => {
                msg.negociate_flags
                    .set_flag(flags::NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY);
            }
            _ => {
                panic!("Only 0 to 5 are supported values for NTLM version");
            }
        }
        if !self.domain.is_empty() {
            msg.set_domain_name(Some(self.domain.clone()));
        }
        msg.negociate_flags.set_flag(flags::NTLMSSP_REQUEST_TARGET);
        self.buffer.clear();
        let size = msg.serialize_into(&mut self.buffer).unwrap();
        self.state = ClientState::NegociateSent(Some(msg));
        &self.buffer[..size]
    }

    pub fn recv_challenge(&mut self, challenge: Challenge) {
        let negotiate = match &mut self.state {
            ClientState::NegociateSent(negotiate) => {
                negotiate.take().expect("Invalid state for client")
            }
            _ => unreachable!(),
        };
        self.state = ClientState::ChallengeReceived(negotiate, challenge);
    }

    fn send_authenticate_ntlmv1(&mut self, client_challenge: ClientChallenge) -> &[u8] {
        let challenge = match self.state {
            ClientState::ChallengeReceived(_, ref c) => c,
            _ => unreachable!("Invalid client state"),
        };
        let (lm_challenge, nt_challenge, session_base_key) = ntlmv1::compute_response(
            &challenge.negociate_flags,
            &self.nt_hash,
            &self.lm_hash,
            &challenge.server_challenge,
            &client_challenge,
            true,
        );

        let key_exchange_key = kxkey(
            &challenge.negociate_flags,
            &session_base_key,
            &lm_challenge.response[..8],
            &self.lm_hash,
            Some(&challenge.server_challenge),
        );

        let (exported_session_key, encrypted_random_session_key) =
            encrypt_random_session_key(&challenge.negociate_flags, &key_exchange_key, None);

        let mut auth = Authenticate::default();
        auth.lm_challenge_response = Some(lm_challenge.into());
        auth.nt_challenge_response = Some(nt_challenge.into());
        auth.domain = Some(self.domain.to_owned());
        auth.user = Some(self.username.to_owned());
        auth.workstation = None;
        auth.set_encrypted_random_session_key(Some(encrypted_random_session_key));
        // auth.mic = mic;
        auth.exported_session_key = Some(exported_session_key);

        self.buffer.clear();
        auth.serialize_into(&mut self.buffer).unwrap();
        self.state = ClientState::AuthenticateSent;
        &self.buffer[..]
    }

    fn send_authenticate_ntlmv2(&mut self, client_challenge: ClientChallenge) -> &[u8] {
        let (negotiate, challenge) = match self.state {
            ClientState::ChallengeReceived(ref n, ref c) => (n, c),
            _ => unreachable!("Invalid client state"),
        };
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
            &challenge.negociate_flags,
            &self.ntlmv2_hash,
            &self.ntlmv2_hash,
            &challenge.server_challenge,
            &client_challenge,
            time,
            &challenge.target_infos[..],
        );

        let key_exchange_key = session_base_key.clone().into();

        let (exported_session_key, encrypted_random_session_key) =
            encrypt_random_session_key(&challenge.negociate_flags, &key_exchange_key, None);

        let mut auth = Authenticate::default();
        auth.lm_challenge_response = Some(lm_challenge.into());
        auth.nt_challenge_response = Some(nt_challenge.into());
        auth.domain = Some(self.domain.to_owned());
        auth.user = Some(self.username.to_owned());
        auth.workstation = None;
        auth.set_encrypted_random_session_key(Some(encrypted_random_session_key));
        auth.exported_session_key = Some(exported_session_key);
        auth.compute_mic(negotiate, challenge);

        self.buffer.clear();
        auth.serialize_into(&mut self.buffer).unwrap();
        self.state = ClientState::AuthenticateSent;
        &self.buffer[..]
    }

    pub fn send_authenticate(&mut self) -> &[u8] {
        let client_challenge = ClientChallenge::random();
        match V::version() {
            0 | 1 | 2 => self.send_authenticate_ntlmv1(client_challenge),
            3 | 4 | 5 => self.send_authenticate_ntlmv2(client_challenge),
            _ => unreachable!("Invalid version"),
        }
    }
}
