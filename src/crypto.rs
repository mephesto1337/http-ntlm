use hmac::{Hmac, Mac};
use md4::Md4;
use md5::{Digest, Md5};

pub mod des;
pub mod lm;
pub mod nt;

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
    let mut mac = <Hmac<Md5>>::new_from_slice(key).unwrap();
    mac.update(input);
    let result = mac.finalize().into_bytes();

    out.copy_from_slice(&result[..]);
}

pub fn compute_response(server_challenge: u64, hash: &[u8]) -> [u8; 24] {
    let mut extended_hash = [0u8; 21];
    (&mut extended_hash[..hash.len()]).copy_from_slice(hash);
    let server_challenge = &server_challenge.to_le_bytes()[..];
    let mut response = [0u8; 24];

    des::des7_encrypt(&extended_hash[..7], server_challenge, &mut response[..8]);
    des::des7_encrypt(
        &extended_hash[7..14],
        server_challenge,
        &mut response[8..16],
    );
    des::des7_encrypt(&extended_hash[14..], server_challenge, &mut response[16..]);

    response
}
