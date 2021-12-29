# Lamport-rs

[![Crates.io](https://img.shields.io/crates/v/leslie_lamport?style=flat-square)](https://crates.io/crates/leslie_lamport)
[![Build Status](https://travis-ci.org/0xAtropine/Leslie-Lamport.svg?branch=master)](https://travis-ci.org/0xAtropine/Leslie-Lamport)
![Crates.io](https://img.shields.io/crates/l/leslie_lamport?style=flat-square)

A Library For The Post-Quantum Digital Signature Scheme **Lamport Signatures** created by Leslie Lamport in 1979.

## Read About Lamport Signatures

* [Hash-Based Signatures Part I: One-Time Signatures (OTS)](https://cryptoservices.github.io/quantum/2015/12/04/one-time-signatures.html)

* [Stackoverflow - Can someone explain very simplified how the Winternitz OTS/Lamport OTS works?](https://iota.stackexchange.com/questions/645/can-someone-explain-very-simplified-how-the-winternitz-ots-lamport-ots-works)

## How To Generate Keys

Default Generation creates **1024 keypairs** that can sign up to **64 bytes** and has a **secret key size of 32 bytes**. These are the default parameters that simple generation has:

* `n` = 64

* `d` = 32 | `d` ∈ 32,48,64,128

The `hash` is chosen by the user.

```rust
use leslie_lamport::{LamportKeyPair,LamportSignature,Algorithms};

fn main(){
    // Generate Keypair using Operating System SHA256
    let keypair = LamportKeyPair::generate(Algorithms::OS_SHA256);
    
    // Generate Keypair using Operating System SHA512
    let keypair_sha512 = LamportKeyPair::generate(Algorithms::OS_SHA512);
    
    // Generate Keypair using Rust Library For Blake2b
    let keypair_blake2b = LamportKeyPair::generate(Algorithms::BLAKE2B);

    // Generates Keypaur using Rust Library For Blake2b (64 bytes)
    let keypair_blake2b_64 = LamportKeyPair::generate(Algorithms::BLAKE2B_64);
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

## Parameters

### `hash`

`hash` is the **hash function** you would like to use. There are four options:

* OS_SHA256
    * 32 bytes (256 bits)
    * Uses Operating System through `crypto-hash` crate

* OS_SHA512
    * 64 bytes (512 bits)
    * Uses Operating System through `crypto-hash` crate

* BLAKE2B
    * 32 bytes (256 bits)
    * Uses Rust Library

* BLAKE2B_64
    * 64 bytes (512 bits)
    * Uses Rust Library

### `d`

> `d` ∈ 32,48,64,128 | The default is 32 bytes

`d` is the **size of the secret key** in bytes. The secret key is generated using the `getrandom` crate which uses the operating system to generate randomness.

### `n`

> Number of Keypairs: `(8*n)*2` | The default is 64 bytes

`n` **represents the number of keypairs generated and the number of bytes you will be able to sign**.

1024 keypairs will sign 512 bits.


## `crypto-hash` crate

The [crypto-hash](https://github.com/malept/crypto-hash) crate uses the operating system to generate hashes. It does this through:

* CryptoAPI (Windows)

* CommonCrypto (OS X)

* OpenSSL (Linux,BSD)

It depends on:

* winapi

* commoncrypto

* openssl

* hex

## `getrandom` crate

The `getrandom` crate generates randomness using the operating system.

## License

Licensed under:

* Apache License, Version 2.0

* MIT License

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
