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

#[cfg(test)]
mod tests {
    const PASSWORD: &'static str = "Password";
    const USERNAME: &'static str = "User";
    const DOMAIN: &'static str = "Domain";

    #[test]
    fn ntowfv1() {
        let hash = [
            0xa4, 0xf4, 0x9c, 0x40, 0x65, 0x10, 0xbd, 0xca, 0xb6, 0x82, 0x4e, 0xe7, 0xc3, 0x0f,
            0xd8, 0x52,
        ];
        pretty_assertions::assert_eq!(super::ntowfv1(PASSWORD), hash);
    }

    #[test]
    fn ntowfv2() {
        let hash = [
            0x0c, 0x86, 0x8a, 0x40, 0x3b, 0xfd, 0x7a, 0x93, 0xa3, 0x00, 0x1e, 0xf2, 0x2e, 0xf0,
            0x2e, 0x3f,
        ];
        pretty_assertions::assert_eq!(
            super::ntowfv2(USERNAME, &super::ntowfv1(PASSWORD), DOMAIN),
            hash
        );
    }
}
