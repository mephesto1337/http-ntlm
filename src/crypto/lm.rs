use super::des::des7_encrypt;

fn prepare_password(password: &str) -> String {
    if password.len() < 14 {
        let mut p = password.to_uppercase();
        while p.len() < 14 {
            p.push('\0');
        }
        p
    } else {
        (&password[..14]).to_uppercase()
    }
}

pub type LmHash = [u8; 16];

pub fn lmowfv1(password: &str) -> LmHash {
    let mut lm_hash = LmHash::default();
    let magic = b"KGS!@#$%";
    let password = prepare_password(password);
    let (key1, key2) = password.split_at(7);

    des7_encrypt(key1.as_bytes(), &magic[..], &mut lm_hash[..8]);
    des7_encrypt(key2.as_bytes(), &magic[..], &mut lm_hash[8..]);

    lm_hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_password() {
        let password = "password";
        let hash = [
            0xe5, 0x2c, 0xac, 0x67, 0x41, 0x9a, 0x9a, 0x22, 0x4a, 0x3b, 0x10, 0x8f, 0x3f, 0xa6,
            0xcb, 0x6d,
        ];

        pretty_assertions::assert_eq!(hash, lmowfv1(password));
    }
}
