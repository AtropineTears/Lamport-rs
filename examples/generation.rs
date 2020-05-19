#[allow(unused_imports)]
use leslie_lamport::{LamportKeyPair,LamportSignature,Algorithms};

fn main(){
    // Generation, Signing, and Verification with all Hash Functions
    sha256();
    sha512();
    blake2b();
}

fn sha256(){
    // Generate "LamportKeypair" Struct from the Operating Systems Crypto API using SHA256 For The Public Keys
    let keypair = LamportKeyPair::generate(Algorithms::OS_SHA256);
    
    // Generate "LamportSignature" Struct from 512-bit Hexadecimal Input
    let signature = keypair.sign("b7dba1bc67c531bffb14fbd7f6948540dba10981765a0538575bed2b6bf553d43f35c287635ef7c4cb2c379f71218edaf70d5d73844910684103b99916e428c2");

    // Validates "LamportSignature" Struct using Public Key, Hashing Algorithm, and Signature
    let is_verified: bool = signature.verify();

    // Asserts The "LamportSignature" verifies to true
    assert_eq!(is_verified,true);
}

fn sha512(){
    // Generate "LamportKeypair" Struct from the Operating Systems Crypto API using SHA512 For The Public Keys
    let keypair = LamportKeyPair::generate(Algorithms::OS_SHA512);
    
    // Generate "LamportSignature" Struct from 512-bit Hexadecimal Input
    let signature = keypair.sign("b7dba1bc67c531bffb14fbd7f6948540dba10981765a0538575bed2b6bf553d43f35c287635ef7c4cb2c379f71218edaf70d5d73844910684103b99916e428c2");

    // Validates "LamportSignature" Struct using Public Key, Hashing Algorithm, and Signature
    let is_verified: bool = signature.verify();

    // Asserts The "LamportSignature" verifies to true
    assert_eq!(is_verified,true);
}

fn blake2b(){
    // Generate "LamportKeypair" Struct from Blake2b Rust Library (32-byte digest) For The Public Keys
    let keypair = LamportKeyPair::generate(Algorithms::BLAKE2B);

    // Generate "LamportSignature" Struct from 512-bit Hexadecimal Input
    let signature = keypair.sign("b7dba1bc67c531bffb14fbd7f6948540dba10981765a0538575bed2b6bf553d43f35c287635ef7c4cb2c379f71218edaf70d5d73844910684103b99916e428c2");

    // Validates "LamportSignature" Struct using Public Key, Hashing Algorithm, and Signature
    let is_verified: bool = signature.verify();

    // Asserts The "LamportSignature" verifies to true
    assert_eq!(is_verified,true);
}