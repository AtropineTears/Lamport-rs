use leslie_lamport::{LamportKeyPair,Algorithms,LamportSignature};

fn main(){
    sha256_advanced();
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

    assert_eq!(is_verified, true);
}

fn sha512_advanced () {
    // Keypair using SHA256 that can sign up to 20 bytes (160 bits) and has a secret key size of 128 bytes
        // `n` = 16 bytes (256 Keypairs)
        // `d` = 64 (Secret Key Size In Bytes)
    let keypair = LamportKeyPair::generate_advanced(Algorithms::OS_SHA512,16,64);

    // Signing 20 bytes (`n`)
    let signature = keypair.sign("1784CD73CE017D560DF5ADE56408A868E5133F16");

    // Verify The Signature
    let is_verified: bool = signature.verify();

    assert_eq!(is_verified, true);
}