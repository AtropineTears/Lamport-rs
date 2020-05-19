use leslie_lamport::{LamportKeyPair,Algorithms};

// All Generation Using Normal Generation
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