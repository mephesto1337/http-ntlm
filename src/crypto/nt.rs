use super::{hmac_md5, md4};

pub type NtHash = [u8; 16];

pub fn ntowfv1(password: &str) -> NtHash {
    let bytes: Vec<_> = password.encode_utf16().collect();
    let mut nt_hash = NtHash::default();

    md4(
        unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast(), bytes.len() * 2) },
        &mut nt_hash,
    );

    nt_hash
}

pub fn ntowfv2(username: &str, hash: &NtHash, domain_name: &str) -> NtHash {
    let user = format!("{}{}", username.to_uppercase(), domain_name);
    let raw_user: Vec<_> = user.encode_utf16().collect();
    let mut nt_hash = NtHash::default();

    hmac_md5(
        &hash[..],
        unsafe { std::slice::from_raw_parts(raw_user.as_ptr().cast(), raw_user.len() * 2) },
        &mut nt_hash[..],
    );
    nt_hash
}
