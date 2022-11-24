pub fn des_56bits_to_64bits(key7: &[u8]) -> [u8; 8] {
    assert_eq!(key7.len(), 7);

    let mut key8 = [0u8; 8];
    for b in 0..8 {
        let mut v = if b == 0 {
            key7[0]
        } else if b == 7 {
            key7[6] << 1
        } else {
            let a = key7[b - 1] << (8 - b);
            let b = key7[b] >> b;
            a | b
        };
        // Clear the last bit
        v = v & !1;

        // Set the last bit if the number of set bits are even
        if v.count_ones() % 2 == 0 {
            v |= 1;
        }
        key8[b] = v;
    }

    key8
}

pub fn des7_encrypt(key7: &[u8], plain: &[u8], cipher: &mut [u8]) {
    let key8 = des_56bits_to_64bits(key7);
    des_encrypt(&key8[..], plain, cipher);
}

pub fn des_encrypt(key8: &[u8], plain: &[u8], cipher: &mut [u8]) {
    use des::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};

    let c = <des::Des as KeyInit>::new_from_slice(&key8[..]).unwrap();
    let mut block = GenericArray::clone_from_slice(&plain[..]);
    c.encrypt_block(&mut block);
    cipher.copy_from_slice(block.as_slice());
}
