# Leslie_Lamport

[![Crates.io](https://img.shields.io/crates/v/leslie_lamport?style=flat-square)](https://crates.io/crates/leslie_lamport)
![Crates.io](https://img.shields.io/crates/l/leslie_lamport?style=flat-square)

A Library For The Post-Quantum Digital Signature Scheme **Lamport Signatures** created by Leslie Lamport in 1979.

## Read About Lamport Signatures

* [Hash-Based Signatures Part I: One-Time Signatures (OTS)](https://cryptoservices.github.io/quantum/2015/12/04/one-time-signatures.html)

* [Stackoverflow - Can someone explain very simplified how the Winternitz OTS/Lamport OTS works?](https://iota.stackexchange.com/questions/645/can-someone-explain-very-simplified-how-the-winternitz-ots-lamport-ots-works)

## How To Generate Keys

```rust
use leslie_lamport::{LamportKeyPair,LamportSignature,Algorithms};

fn main(){
    // Generate Keypair using Operating System SHA256
    let keypair = LamportKeyPair::generate(Algorithms::OS_SHA256);
    
    // Generate Keypair using Operating System SHA512
    let keypair_sha512 = LamportKeyPair::generate(Algorithms::OS_SHA512);
    
    // Generate Keypair using Rust Library For Blake2b
    let keypair_blake2b = LamportKeyPair::generate(Algorithms::BLAKE2B);
}
```

## How To Sign

```rust
use leslie_lamport::{LamportKeyPair,LamportSignature,Algorithms};

fn main(){
    // Generate Keypair
    let keypair = LamportKeyPair::generate(Algorithms::OS_SHA256);
    
    // Generate Signature For 512 bit input
    let sig = keypair.sign("b7dba1bc67c531bffb14fbd7f6948540dba10981765a0538575bed2b6bf553d43f35c287635ef7c4cb2c379f71218edaf70d5d73844910684103b99916e428c2");

    // Check If It Is Verified
    let is_verified: bool = sig.verify();

    // Print Verification
    println!("Is Verified: {}",is_verified)
}
```

## License

Licensed under:

* Apache License, Version 2.0

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
