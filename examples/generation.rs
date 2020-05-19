use leslie_lamport::{LamportKeyPair,LamportSignature,Algorithms};

fn main(){
    // Generate Keypair from OS SHA256
    let keypair = LamportKeyPair::generate(Algorithms::OS_SHA256);
    
    // Generate Signature from 512-bit Hexadecimal Input
    let signature = keypair.sign("b7dba1bc67c531bffb14fbd7f6948540dba10981765a0538575bed2b6bf553d43f35c287635ef7c4cb2c379f71218edaf70d5d73844910684103b99916e428c2");

    // Check If It Is Verified
    let is_verified: bool = sig.verify();

    // Print Verification
    println!("Is Verified: {}",is_verified);

    assert_eq!(is_verified,true);
}

fn blake2b(){
    // Generate "LamportKeypair" Struct from Blake2b Rust Library (32 byte digest) using 32-byte private keys
    let keypair = LamportKeyPair::generate(Algorithms::BLAKE2B);

    // Generate "LamportSignature" Struct from 512-bit Hexadecimal Input
    let signature = keypair.sign("b7dba1bc67c531bffb14fbd7f6948540dba10981765a0538575bed2b6bf553d43f35c287635ef7c4cb2c379f71218edaf70d5d73844910684103b99916e428c2");

    // Validates "LamportSignature" Struct using Public Key, Hashing Algorithm, and Signature
    let is_verified = signature.verify();

    // Asserts The "LamportSignature" is Verified
    assert_eq!(is_verified,true);
}