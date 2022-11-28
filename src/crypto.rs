use crate::messages::{
    flags::{
        Flags, NTLMSSP_NEGOTIATE_KEY_EXCH, NTLMSSP_NEGOTIATE_LM_KEY, NTLMSSP_NEGOTIATE_SEAL,
        NTLMSSP_NEGOTIATE_SIGN, NTLMSSP_REQUEST_NON_NT_SESSION_KEY,
    },
    structures::{
        EncryptedRandomSessionKey, ExportedSessionKey, KeyExchangeKey, Response24, ServerChallenge,
        SessionBaseKey,
    },
};

use rc4::{KeyInit, Rc4, StreamCipher};

use hmac::{Hmac, Mac};
use md4::Md4;
use md5::{Digest, Md5};

pub mod des;
pub mod lm;
pub mod nt;
pub mod ntlmv1;
pub mod ntlmv2;

pub fn md4(input: &[u8], out: &mut [u8]) {
    let mut hasher = Md4::new();
    hasher.update(input);
    let out = md4::digest::generic_array::GenericArray::from_mut_slice(out);
    hasher.finalize_into(out);
}

pub fn md5(input: &[u8], out: &mut [u8]) {
    let mut hasher = Md5::new();
    hasher.update(input);
    let out = md5::digest::generic_array::GenericArray::from_mut_slice(out);
    hasher.finalize_into(out);
}

pub fn hmac_md5(key: &[u8], input: &[u8], out: &mut [u8]) {
    let mut mac = <Hmac<Md5> as hmac::Mac>::new_from_slice(key).unwrap();
    mac.update(input);
    let result = mac.finalize().into_bytes();

    out.copy_from_slice(&result[..]);
}

fn desl(key: &[u8], data: &[u8]) -> Response24 {
    assert!(key.len() == 16 && data.len() == 8);

    let mut extended_hash = [0u8; 21];
    (&mut extended_hash[..16]).copy_from_slice(&key[..]);
    let mut response = [0u8; 24];

    des::des7_encrypt(&extended_hash[..7], data, &mut response[..8]);
    des::des7_encrypt(&extended_hash[7..14], data, &mut response[8..16]);
    des::des7_encrypt(&extended_hash[14..], data, &mut response[16..]);

    response.into()
}

pub fn kxkey(
    flags: &Flags,
    session_base_key: &SessionBaseKey,
    lm_response_first_8: &[u8],
    hash: &[u8],
    server_challenge: Option<&ServerChallenge>,
) -> KeyExchangeKey {
    let mut key_exchange_key = KeyExchangeKey::default();
    assert_eq!(lm_response_first_8.len(), 8);

    if let Some(server_challenge) = server_challenge {
        let mut mac = <Hmac<md5::Md5> as hmac::Mac>::new_from_slice(session_base_key).unwrap();
        mac.update(server_challenge);
        mac.update(lm_response_first_8);
        key_exchange_key.copy_from_slice(&mac.finalize().into_bytes()[..]);
    } else {
        assert_eq!(hash.len(), 16);
        if flags.has_flag(NTLMSSP_NEGOTIATE_LM_KEY) {
            des::des7_encrypt(&hash[..7], lm_response_first_8, &mut key_exchange_key[..8]);
            let key = [hash[7], 0xbd, 0xbd, 0xbd, 0xbd, 0xbd, 0xbd];
            des::des7_encrypt(&key, lm_response_first_8, &mut key_exchange_key[8..]);
        } else {
            if flags.has_flag(NTLMSSP_REQUEST_NON_NT_SESSION_KEY) {
                (&mut key_exchange_key[..8]).copy_from_slice(&hash[..8]);
            } else {
                (&mut key_exchange_key).copy_from_slice(session_base_key);
            }
        }
    }
    key_exchange_key
}

pub fn encrypt_random_session_key(
    flags: &Flags,
    key_exchange_key: &KeyExchangeKey,
    exported_session_key: Option<ExportedSessionKey>,
) -> (ExportedSessionKey, EncryptedRandomSessionKey) {
    if flags.has_flag(NTLMSSP_NEGOTIATE_KEY_EXCH)
        && (flags.has_flag(NTLMSSP_NEGOTIATE_SIGN) || flags.has_flag(NTLMSSP_NEGOTIATE_SEAL))
    {
        let exported_session_key = if let Some(e) = exported_session_key {
            e
        } else {
            ExportedSessionKey::random()
        };
        let mut kek = [0u8; 16];
        (&mut kek).copy_from_slice(key_exchange_key);

        let mut encrypted_random_session_key: EncryptedRandomSessionKey =
            exported_session_key.clone().into();
        let mut rc4 = Rc4::new(&kek.into());
        rc4.apply_keystream(&mut encrypted_random_session_key);
        (exported_session_key, encrypted_random_session_key)
    } else {
        let mut exported_session_key = ExportedSessionKey::default();
        (&mut exported_session_key).copy_from_slice(key_exchange_key);
        (exported_session_key, EncryptedRandomSessionKey::default())
    }
}

#[cfg(test)]
mod tests {
    use super::lm::LmHash;
    use super::nt::NtHash;
    use crate::messages::flags::*;
    use crate::messages::structures::FileTime;

    pub const FLAGS: u32 = (1 << NTLMSSP_NEGOTIATE_KEY_EXCH)
        | (1 << NTLMSSP_NEGOTIATE_56)
        | (1 << NTLMSSP_NEGOTIATE_128)
        | (1 << NTLMSSP_NEGOTIATE_VERSION)
        | (1 << NTLMSSP_TARGET_TYPE_SERVER)
        | (1 << NTLMSSP_NEGOTIATE_ALWAYS_SIGN)
        | (1 << NTLMSSP_NEGOTIATE_NTLM)
        | (1 << NTLMSSP_NEGOTIATE_SEAL)
        | (1 << NTLMSSP_NEGOTIATE_SIGN)
        | (1 << NTLM_NEGOTIATE_OEM)
        | (1 << NTLMSSP_NEGOTIATE_UNICODE);

    pub const LM_HASH: LmHash = [
        0xe5, 0x2c, 0xac, 0x67, 0x41, 0x9a, 0x9a, 0x22, 0x4a, 0x3b, 0x10, 0x8f, 0x3f, 0xa6, 0xcb,
        0x6d,
    ];
    pub const NT_HASH: NtHash = [
        0xa4, 0xf4, 0x9c, 0x40, 0x65, 0x10, 0xbd, 0xca, 0xb6, 0x82, 0x4e, 0xe7, 0xc3, 0x0f, 0xd8,
        0x52,
    ];
    pub const SERVER_CHALLENGE: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    pub const CLIENT_CHALLENGE: [u8; 8] = [0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa];
    pub const SESSION_BASE_KEY: [u8; 16] = [
        0xd8, 0x72, 0x62, 0xb0, 0xcd, 0xe4, 0xb1, 0xcb, 0x74, 0x99, 0xbe, 0xcc, 0xcd, 0xf1, 0x07,
        0x84,
    ];
    pub const RANDOM_SESSION_KEY: [u8; 16] = [
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55,
    ];
    pub const TIME: FileTime = FileTime { high: 0, low: 0 };
}
