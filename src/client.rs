use std::marker::PhantomData;

use crate::{
    crypto::{lm::LmHash, nt::NtHash, ntlmv1},
    messages::{
        flags,
        structures::{
            AvPair, ClientChallenge, LmChallenge, Lmv1Challenge, Lmv2Challenge, MsvAvFlags,
            NtChallenge, Ntv1Challenge, Ntv2Challenge, ServerChallenge, SessionBaseKey,
        },
        Authenticate, Challenge, Negociate, Wire,
    },
    NtlmVersion,
};

use rand::{rngs::OsRng, RngCore};
use rc4::{KeyInit, Rc4, StreamCipher};

#[derive(Debug, Default)]
enum ClientState {
    #[default]
    New,
    NegociateSent(Negociate),
    ChallengeReceived(Challenge),
    AuthenticateSent,
}

pub struct Client<V> {
    state: ClientState,
    username: String,
    lm_hash: LmHash,
    nt_hash: NtHash,
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
            let (lm_hash, nt_hash) = Self::compute_ntlm_hashes(password.as_str());
            Self {
                state: ClientState::New,
                username,
                lm_hash,
                nt_hash,
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
        let (lm_hash, nt_hash) = Self::compute_ntlm_hashes(password.as_str());
        Self {
            state: ClientState::New,
            username,
            lm_hash,
            nt_hash,
            domain,
            target,
            buffer: Vec::with_capacity(128),
            _version: PhantomData,
        }
    }

    fn compute_ntlm_hashes(password: &str) -> (LmHash, NtHash) {
        let lm_hash = crate::crypto::lm::lmowfv1(password);
        let nt_hash = crate::crypto::nt::ntowfv1(password);

        (lm_hash, nt_hash)
    }

    pub fn send_negociate(&mut self) -> &[u8] {
        let mut msg = Negociate::default();
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
        self.state = ClientState::NegociateSent(msg);
        &self.buffer[..size]
    }

    pub fn recv_challenge(&mut self, challenge: Challenge) {
        self.state = ClientState::ChallengeReceived(challenge);
    }

    /*
        fn compute_lm_challenge(&self, challenge: &Challenge) -> LmChallenge {
            let mut client_challenge = ClientChallenge::default();
            OsRng.fill_bytes(&mut *client_challenge);

            match V::version() {
                0..=2
                    if challenge
                        .negociate_flags
                        .has_flag(flags::NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) =>
                {
                    let mut r = Lmv1Challenge::default();
                    (&mut r.response[16..]).copy_from_slice(&client_challenge);
                    r.into()
                }
                0 | 1 => {
                    Lmv1Challenge::from_server_challenge(challenge.server_challenge, &self.lm_hash[..])
                        .into()
                }
                2 => {
                    Lmv1Challenge::from_server_challenge(challenge.server_challenge, &self.nt_hash[..])
                        .into()
                }
                3..=5 => {
                    let mut has_timestamp = false;
                    for ti in challenge.get_target_infos() {
                        match ti {
                            AvPair::MsvAvTimestamp(_) => {
                                has_timestamp = true;
                                break;
                            }
                            _ => continue,
                        }
                    }

                    if has_timestamp {
                        Lmv1Challenge::default().into()
                    } else {
                        let nt_hash = crate::crypto::nt::ntowfv2(
                            self.username.as_str(),
                            &self.nt_hash,
                            self.domain.as_str(),
                        );

                        Lmv2Challenge::from_server_challenge(
                            challenge.server_challenge,
                            &nt_hash[..],
                            client_challenge,
                        )
                        .into()
                    }
                }
                _ => {
                    panic!("Only 0 to 5 are supported values for NTLM version");
                }
            }
        }

        fn compute_nt_challenge(
            &self,
            challenge: &Challenge,
            client_challenge: [u8; 8],
        ) -> (NtChallenge, SessionBaseKey, Option<[u8; 16]>) {
            match V::version() {
                0..=2 => {
                    let chal = if challenge
                        .negociate_flags
                        .has_flag(flags::NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)
                    {
                        let mut chal = [0u8; 16];
                        (&mut chal[..8]).copy_from_slice(&challenge.server_challenge.to_le_bytes()[..]);
                        (&mut chal[8..]).copy_from_slice(&client_challenge[..]);

                        let mut nt_session_hash = [0u8; 16];
                        md5(&chal[..], &mut nt_session_hash);

                        let mut new_challenge = [0u8; 8];
                        (&mut new_challenge).copy_from_slice(&nt_session_hash[..8]);

                        u64::from_le_bytes(new_challenge)
                    } else {
                        challenge.server_challenge
                    };

                    let response = compute_response(chal, &self.nt_hash[..]);
                    let mut session_base_key = SessionBaseKey::default();
                    md4(&self.nt_hash[..], &mut session_base_key[..]);
                    (Ntv1Challenge { response }.into(), session_base_key, None)
                }
                3..=5 => {
                    let mut timestamp = None;
                    for ti in challenge.get_target_infos() {
                        match ti {
                            AvPair::MsvAvTimestamp(ref ts) => {
                                timestamp = Some(ts);
                                break;
                            }
                            _ => continue,
                        }
                    }
                    let timestamp = match timestamp {
                        Some(ts) => ts.clone(),
                        None => std::time::SystemTime::now().try_into().unwrap(),
                    };

                    let mut target_infos = challenge.target_infos.clone();
                    let mut av_flags = None;
                    for ti in &mut target_infos {
                        match ti {
                            AvPair::MsvAvFlags(ref mut flags) => {
                                av_flags = Some(flags);
                                break;
                            }
                            _ => continue,
                        }
                    }
                    if let Some(flags) = av_flags {
                        flags.mic_present = true;
                    } else {
                        let flags = MsvAvFlags {
                            account_authentication_constrained: false,
                            mic_present: true,
                            generated_spn_from_untrusted_source: false,
                        };
                        if target_infos.is_empty() {
                            target_infos.push(AvPair::MsvAvFlags(flags));
                            target_infos.push(AvPair::MsvAvEOL);
                        } else {
                            target_infos.insert(target_infos.len() - 1, AvPair::MsvAvFlags(flags));
                        }
                    }

                    let nt_hash =
                        nt::ntowfv2(self.username.as_str(), &self.nt_hash, self.domain.as_str());

                    let temp = Ntv2Challenge {
                        timestamp,
                        challenge_from_client: client_challenge,
                        target_infos,
                    };
                    let mut buffer = Vec::with_capacity(128);
                    buffer.extend_from_slice(&challenge.server_challenge.to_le_bytes()[..]);
                    temp.serialize_into(&mut buffer).unwrap();

                    let mut mic = [0u8; 16];
                    hmac_md5(&nt_hash[..], &buffer[..], &mut mic[..]);

                    let mut session_base_key = SessionBaseKey::default();
                    hmac_md5(&nt_hash[..], &mic[..], &mut session_base_key[..]);

                    (temp.into(), session_base_key, Some(mic))
                }
                _ => {
                    panic!("Only 0 to 5 are supported values for NTLM version");
                }
            }
        }
    */

    pub fn send_authenticate(&mut self) -> &[u8] {
        let challenge = match self.state {
            ClientState::ChallengeReceived(ref c) => c,
            _ => unreachable!("Invalid client state"),
        };
        let client_challenge = ClientChallenge::random();
        let (lm_challenge, nt_challenge, session_base_key) = ntlmv1::compute_response(
            &challenge.negociate_flags,
            &self.nt_hash,
            &self.lm_hash,
            &challenge.server_challenge,
            &client_challenge,
            true,
        );

        let key_exchange_key = ntlmv1::kxkey(
            &challenge.negociate_flags,
            &session_base_key,
            &lm_challenge,
            &self.lm_hash,
            Some(&challenge.server_challenge),
        );

        let (exported_session_key, encrypted_random_session_key) =
            ntlmv1::encrypt_random_session_key(&challenge.negociate_flags, &key_exchange_key, None);

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
}
