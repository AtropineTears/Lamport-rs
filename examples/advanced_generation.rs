#[allow(unused_imports)]
use leslie_lamport::{LamportKeyPair,Algorithms,LamportSignature};

fn main() {
    sha256_advanced();
    sha512_advanced();
    blake2b_advanced();
    blake2b_64_advanced();
}

fn sha256_advanced () {
    // Keypair using SHA256 that can sign up to 20 bytes (160 bits) and has a secret key size of 128 bytes
        // `n` = 20 bytes (320 Keypairs)
        // `d` = 128 (Secret Key Size In Bytes)
    let keypair = LamportKeyPair::generate_advanced(Algorithms::OS_SHA256,20,128);

    // Signing 20 bytes (`n`)
    let signature = keypair.sign("1784CD73CE017D560DF5ADE56408A868E5133F16");

    // Verify The Signature
    let is_verified: bool = signature.verify();

    // Assert The Signature Is Valid
    assert_eq!(is_verified, true);
}

fn sha512_advanced () {
    // Keypair using SHA256 that can sign up to 20 bytes (160 bits) and has a secret key size of 128 bytes
        // `n` = 16 bytes (256 Keypairs)
        // `d` = 64 (Secret Key Size In Bytes)
    let keypair = LamportKeyPair::generate_advanced(Algorithms::OS_SHA512,16,64);

    // Signing 16 bytes (`n`)
    let signature = keypair.sign("F247FEE0C97480CDCC906634B875D5E7");

    // Verify The Signature
    let is_verified: bool = signature.verify();

    // Assert The Signature Is Valid
    assert_eq!(is_verified, true);
}

fn blake2b_advanced () {
    // Keypair using SHA256 that can sign up to 20 bytes (160 bits) and has a secret key size of 128 bytes
        // `n` = 128 bytes (2048 Keypairs)
        // `d` = 32 (Secret Key Size In Bytes)
    let keypair = LamportKeyPair::generate_advanced(Algorithms::BLAKE2B,128,32);

    // Signing 128 bytes (`n`)
    let signature = keypair.sign("27B0973188BDB127119A09F09570DC2F795F6D2A4D4752E7EB3F1B2B11BBB889AC59DE2A47CBEF50BCCC8E4BB5876B4BA31D303FB2AB85E338F2E7BA5742AE69D57087FA16D4A94C2808AF1326FA512018B0270CEB1320D59947EB7B20C65EDB20F3BF200308F7C5B0CB7C89A9019F0D9F4A5690DEC048EC7167D1C4F9374EB9");

    // Verify The Signature
    let is_verified: bool = signature.verify();

    // Assert The Signature Is Valid
    assert_eq!(is_verified, true);
}

fn blake2b_64_advanced () {
    // Keypair using SHA256 that can sign up to 20 bytes (160 bits) and has a secret key size of 128 bytes
        // `n` = 4 bytes (64 Keypairs)
        // `d` = 48 (Secret Key Size In Bytes)
    let keypair = LamportKeyPair::generate_advanced(Algorithms::BLAKE2B_64,4,48);

    // Signing 4 bytes from a CRC32 Checksum (`n`)
    let signature = keypair.sign("069CB9F3");

    // Verify The Signature
    let is_verified: bool = signature.verify();

    // Assert The Signature Is Valid
    assert_eq!(is_verified, true);
}