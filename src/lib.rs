extern crate blake2_rfc;
mod random;


pub struct PrivKey;
struct KeyPair {
    x: [[u8;48];256],
    y: [[u8;48];256],
}

impl PrivKey {
    fn new () -> [u8;48] {
        return random::random_48().unwrap() // 384 bits
    }
}

impl KeyPair {
    fn init () -> KeyPair {
        let output = KeyPair {
            x: [[0u8;48];256],
            y: [[0u8;48];256],
        };
        return output
    }
    fn new () -> KeyPair {
        KeyPair::init()
    }
}

pub struct LamportKeyPair {
    Sk: String,
    Pk: String,
}

pub fn generate(){

}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
