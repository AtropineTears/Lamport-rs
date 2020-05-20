
/// All Simple Generation Using Default Generation And Each Hashing Algorithm
#[cfg(test)]
mod simple_generation_tests {
    use leslie_lamport::{LamportKeyPair,Algorithms};
    #[test]
    fn generate_sha256(){
        let _sha256 = LamportKeyPair::generate(Algorithms::OS_SHA256);
    }
    #[test]
    fn generate_sha512(){
        let _sha512 = LamportKeyPair::generate(Algorithms::OS_SHA512);
    }
    #[test]
    fn generate_blake2b(){
        let _blake2b = LamportKeyPair::generate(Algorithms::BLAKE2B);
    }
    #[test]
    fn generate_blake2b_64(){
        let _blake2b_64 = LamportKeyPair::generate(Algorithms::BLAKE2B_64);
    }
}

#[cfg(test)]
mod advanced_generation_tests {
    use leslie_lamport::{LamportKeyPair,Algorithms};
    #[test]
    fn advanced_generate_sha256(){
        // `n` of 16
        // `d` of 128
        let _sha256 = LamportKeyPair::generate_advanced(Algorithms::OS_SHA256,16,128);
    }
    #[test]
    fn advanced_generate_sha512(){
        // `n` of 128
        // `d` of 64
        let _sha512 = LamportKeyPair::generate_advanced(Algorithms::OS_SHA512,128,64);
    }
    #[test]
    fn advanced_generate_blake2b(){
        // `n` of 128
        // `d` of 48
        let _blake2b = LamportKeyPair::generate_advanced(Algorithms::BLAKE2B,128,48);
    }
    #[test]
    fn advanced_generate_blake2b_64(){
        // `n` of 32
        // `d` of 32
        let _blake2b_64 = LamportKeyPair::generate_advanced(Algorithms::BLAKE2B_64,32,32);
    }
    #[test]
    #[should_panic]
    fn panic_advanced_generate_d_of_24(){
        // Should Panic with `d = 24` being wrong size
        let _panic_sha256 = LamportKeyPair::generate_advanced(Algorithms::OS_SHA256,64,24);
    }
    #[test]
    #[should_panic]
    fn panic_generate_d_of_256(){
        // Should Panic with `d = 24` being wrong size
        let _panic_blake2b = LamportKeyPair::generate_advanced(Algorithms::BLAKE2B,64,256);
    }
}

#[cfg(test)]
mod simple_signing_tests {
    use leslie_lamport::{LamportKeyPair,Algorithms};
    #[test]
    fn sign_sha256(){
        let keypair = LamportKeyPair::generate(Algorithms::OS_SHA256);
        let _sig = keypair.sign("B8E8F75AA31A62B9083A70A5414C772A860E648B078108DA13CEEF3D4550193699D5080D1255CFB3F4641EC16852A28A7C507E7CCD58033FAE1C866B62DC6CB8");
    }
    #[test]
    fn sign_sha512(){
        let keypair = LamportKeyPair::generate(Algorithms::OS_SHA512);
        let _sig = keypair.sign("C9B18725328C3CE3E9F4497A9C7E35153A5B9DFC1AA7A3C9C685EFF4F4B8C68DAB78B8187BE11310A41978148AC4C459BE8D8FBD21ED4AE10A3922E22C4A1092");
        
    }
    #[test]
    fn sign_blake2b(){
        let keypair = LamportKeyPair::generate(Algorithms::BLAKE2B);
        let _sig = keypair.sign("691D9AA7E47C73F3793DBEC9D1AFEBB5E46BAF08B08B10A0128AFA6D58E68D3EAA8911C62D527AB9C857A3E7E182DBB18F4E4D671233F7D3EB6BF7C25EE078DE");
        
    }
    #[test]
    fn sign_blake2b_64(){
        let keypair = LamportKeyPair::generate(Algorithms::BLAKE2B_64);
        let _sig = keypair.sign("AC084B8138498A2E1AF06F87A19EE93D3148BE57A98824CD64F4E3E3023395A44BBC58721229F66038F3B224C443B502561D99186C32D9012F850A400093AD4A");
    }

    #[test]
    #[should_panic]
    fn panic_sign_sha256_odd_length(){
        let keypair = LamportKeyPair::generate(Algorithms::OS_SHA256);
        let _sig = keypair.sign("B8E8F75AA31A62B9083A70A5414C772A860E648B078108DA13CEEF3D4550193699D5080D1255CFB3F4641EC16852A28A7C507E7CCD58033FAE1C866B62DC6CB87");
    }
    #[test]
    #[should_panic]
    fn panic_sign_sha256_extra_byte(){
        let keypair = LamportKeyPair::generate(Algorithms::OS_SHA256);
        let _sig = keypair.sign("B8E8F75AA31A62B9083A70A5414C772A860E648B078108DA13CEEF3D4550193699D5080D1255CFB3F4641EC16852A28A7C507E7CCD58033FAE1C866B62DC6CB877");
    }
    #[test]
    fn sign_sha256_less_bytes(){
        let keypair = LamportKeyPair::generate(Algorithms::OS_SHA256);
        let sig = keypair.sign("B8E8F75AA31A62B9083A70A5414C772A860E648B078108DA13CEEF3D4550193699D5080D1255CFB3F4641EC16852A28A7C507E7CCD58033FAE1C866B62");
        let verification = sig.verify();

        assert_eq!(verification, true);
    }
}
#[cfg(test)]
mod simple_verification {
    #[allow(unused_imports)]
    use leslie_lamport::{LamportKeyPair,Algorithms,LamportSignature};
    #[test]
    fn verify_sha256(){
        let keypair = LamportKeyPair::generate(Algorithms::OS_SHA256);
        let sig = keypair.sign("da329e6afb23429177b3a98aad8f3ee6a230614973513485e039b08817bb2d8017376b56b6f3c6d525c2f007a5f765a6be035edda4fadc9c8f5c744152b1745c");
        let verification = sig.verify();

        assert_eq!(verification, true);
    }
    #[test]
    fn verify_sha512() {
        let keypair = LamportKeyPair::generate(Algorithms::OS_SHA512);
        let sig = keypair.sign("da329e6afb23429177b3a98aad8f3ee6a230614973513485e039b08817bb2d8017376b56b6f3c6d525c2f007a5f765a6be035edda4fadc9c8f5c744152b1745c");
        let verification = sig.verify();

        assert_eq!(verification, true);
    }
    #[test]
    fn verify_blake2b(){
        let keypair = LamportKeyPair::generate(Algorithms::BLAKE2B);
        let sig = keypair.sign("da329e6afb23429177b3a98aad8f3ee6a230614973513485e039b08817bb2d8017376b56b6f3c6d525c2f007a5f765a6be035edda4fadc9c8f5c744152b1745c");
        let verification = sig.verify();

        assert_eq!(verification, true);
    }
    #[test]
    fn verify_blake2b_64(){
        let keypair = LamportKeyPair::generate(Algorithms::BLAKE2B_64);
        let sig = keypair.sign("da329e6afb23429177b3a98aad8f3ee6a230614973513485e039b08817bb2d8017376b56b6f3c6d525c2f007a5f765a6be035edda4fadc9c8f5c744152b1745c");
        let verification = sig.verify();

        assert_eq!(verification, true);
    }
    #[test]
    #[should_panic]
    fn panic_verify_extra_byte_in_input(){
        let keypair = LamportKeyPair::generate(Algorithms::BLAKE2B_64);
        let mut sig = keypair.sign("da329e6afb23429177b3a98aad8f3ee6a230614973513485e039b08817bb2d8017376b56b6f3c6d525c2f007a5f765a6be035edda4fadc9c8f5c744152b1745c");
        sig.input = "da329e6afb23429177b3a98aad8f3ee6a230614973513485e039b08817bb2d8017376b56b6f3c6d525c2f007a5f765a6be035edda4fadc9c8f5c744152b1745c00".to_string();
        let verification = sig.verify();

        assert_eq!(verification, false);
    }
    #[test]
    fn verify_wrong_signature(){
        let keypair = LamportKeyPair::generate(Algorithms::BLAKE2B_64);
        let mut sig = keypair.sign("da329e6afb23429177b3a98aad8f3ee6a230614973513485e039b08817bb2d8017376b56b6f3c6d525c2f007a5f765a6be035edda4fadc9c8f5c744152b1745c");
        sig.signature[511] = "da329e6afb23429177b3a98aad8f3ee6a230614973513485e039b08817bb2d8017376b56b6f3c6d525c2f007a5f765a6be035edda4fadc9c8f5c744152b1745c".to_string();
        let verification = sig.verify();

        assert_eq!(verification, false);
    }
    #[test]
    fn verify_wrong_input(){
        let keypair = LamportKeyPair::generate(Algorithms::BLAKE2B_64);
        let mut sig = keypair.sign("da329e6afb23429177b3a98aad8f3ee6a230614973513485e039b08817bb2d8017376b56b6f3c6d525c2f007a5f765a6be035edda4fadc9c8f5c744152b1745c");
        sig.input = "da329e6afb23429177b3a98aad8f3ee6a230614973513485e039b08817bb2d8017376b56b6f3c6d525c2f007a5f765a6be035edda4fadc9c8f5c744152b1845c".to_string();
        let verification = sig.verify();

        assert_eq!(verification, false);
    }
    #[test]
    fn verify_wrong_pk_but_right_bit(){
        let keypair = LamportKeyPair::generate(Algorithms::OS_SHA256);
        let mut sig = keypair.sign("da329e6afb23429177b3a98aad8f3ee6a230614973513485e039b08817bb2d8017376b56b6f3c6d525c2f007a5f765a6be035edda4fadc9c8f5c744152b1745c");
        sig.pk[1023] = "da329e6afb23429177b3a98aad8f3ee6a230614973513485e039b08817bb2d8017376b56b6f3c6d525c2f007a5f765a6be035edda4fadc9c8f5c744152b1845c".to_string();
        let verification: bool = sig.verify();

        assert_eq!(verification, true);
    }
    #[test]
    fn verify_wrong_pk() {
        let keypair = LamportKeyPair::generate(Algorithms::OS_SHA256);
        let mut sig = keypair.sign("da329e6afb23429177b3a98aad8f3ee6a230614973513485e039b08817bb2d8017376b56b6f3c6d525c2f007a5f765a6be035edda4fadc9c8f5c744152b1745c");
        sig.pk[1022] = "da329e6afb23429177b3a98aad8f3ee6a230614973513485e039b08817bb2d8017376b56b6f3c6d525c2f007a5f765a6be035edda4fadc9c8f5c744152b1845c".to_string();
        let verification: bool = sig.verify();

        assert_eq!(verification, false);
    }
}

#[cfg(test)]
mod random_tests {
    use leslie_lamport::random;
    #[test]
    fn retrieve_all() {
        let _r32 = random::random_32();
        let _r48 = random::random_48();
        let _r64 = random::random_64();
        let _r128 = random::random_128();
    }
    #[test]
    fn retrieve_32(){
        let _random: [u8;32] = random::random_32();
    }
}