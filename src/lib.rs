#[allow(unreachable_patterns)]

/// random.rs file using `getrandom` crate for `d` which is a member of {32,48,64,128}.
pub mod random;

// Serialization
use serde::{Serialize, Deserialize};

// Hashing Algorithms
use crypto_hash::{Algorithm, hex_digest};
use blake2_rfc::blake2b::Blake2b;

// Hexadecimal
use hex;


// hash = The Hash Function Chosen To Generate The Public Key and Verify The Signature
// n = The Number of Bytes To Sign (and number of keypairs generated)
// d = Secret Key Size in Bytes as a member of the set {32,48,64,128}

// For Developers:
// * The message being signed can only be in hexadecimal and a string
// * The message is decoded from hex into bytes before signing/verifying
// * You can sign a message that is shorter than the public key without receiving errors (only a warning). However, verifying the public key against itself in the signature will invalidate the public key.
// * The Hash Functions take as input a hexadecimal string and decodes them



/// # Hashing Algorithms
/// This Lists the Algorithms available to Hash the Secret Key from, Generate, and Verify The Signature Against the Public Key.
/// - OS_SHA256 (Operating System **SHA256** using `crypto-hash`)
/// - OS_SHA512 (Operating System **SHA512** using `crypto-hash`)
/// - BLAKE2B (Rust Library For **Blake2b** using `blake2-rfc`)
/// - BLAKE2B_64 (Rust Library For **Blake2b** using `blake2-rfc` with a digest of 64 bytes)
#[allow(non_camel_case_types)]
#[derive(Copy,Debug,Clone,PartialEq,PartialOrd,Hash,Serialize,Deserialize)]
pub enum Algorithms {
    OS_SHA256,
    OS_SHA512,
    BLAKE2B,
    BLAKE2B_64,
}

/// # Lamport Keypair
/// This Struct Represents a **LamportKeyPair**:
/// 
/// - `hash` | The Hash Function Chosen To Generate The Public Key and Verify The Signature
/// - `n` | The Number of Bytes That Can Be Signed (and Keypairs Generated)
/// - `d` | The Secret Key Size In Bytes as a member of the set {32,48,64,128}
/// 
/// The two most common generation functions are:
/// - `generate(hash)`
/// - `generate_advanced(hash,n,d)`
/// 
/// By default, `generate()` has as parameters:
/// 
/// - `n` = `64` | Generates 1024 keypairs that can sign up to 64 bytes (512 bits)
/// - `d` = `32` | Generates a Secret Key Size of 32 bytes (256 bits)
/// 
/// ## Generation and Signing
/// 
/// **Note: You can only sign hexadecimal strings.**
/// 
/// ```
/// use leslie_lamport::{LamportKeyPair,Algorithms};
/// 
/// // Basic Generation Using SHA256
/// let keypair = LamportKeyPair::generate(Algorithms::OS_SHA256);
/// 
/// // Advanced Generation of 256 keypairs to sign 16 bytes, Secret Key Size of 64, and using BLAKE2B
/// let keypair_advanced = LamportKeyPair::generate_advanced(Algorithms::BLAKE2B,16,64);
/// 
/// // Signing 16 bytes using LamportKeyPair to Generate a LamportSignature
/// let signature = keypair_advanced.sign("15DCED7133EFF6837E7B51768EA7F134");
/// 
/// ```
/// 
/// This struct also derives **Serialize** and **Deserialize** from **serde**.
#[derive(Debug,Clone,PartialEq,PartialOrd,Hash,Serialize,Deserialize)]
pub struct LamportKeyPair {
    pub hash: Algorithms,
    pub sk: Vec<String>,
    pub pk: Vec<String>,
}

/// # Lamport Signature
/// 
/// **NOTE: The message being signed must be in Hexadecimal**
/// 
/// After Signing with the `LamportKeyPair` struct, you can keep the `LamportSignature` struct **Public**. Your `LamportKeyPair` will now be useless for signing as it's a **One-Time Signature**.
/// 
/// This Struct Contains:
/// - The Hashing Algorithm as `Enum Algorithms`
/// - The Public Key as a `Vector<Strings>`
/// - The Input String as a `String`
/// - The Signature as a `Vector<Strings>`
/// 
/// ## Example Usage
/// Its only function is for **Verification Purposes**.
/// 
/// ```
/// use leslie_lamport::{LamportKeyPair,Algorithms,LamportSignature};
/// 
/// // Generate Keypair
/// let keypair = LamportKeyPair::generate(Algorithms::OS_SHA256);
/// 
/// // Generates a "LamportSignature" Struct for a One-Time Signature For a 512-bit Hexadecimal String
/// let signature = keypair.sign("A55FE31CB83313443F38356A065F9E6386BE591C30490ECC6994B0C152D46D80ABC010DF01257FFEC437402967995D5C34EAD950E0C62C3BCAFF34BCEFB3BDF7");
/// 
/// // Verify Signature
/// let is_verified: bool = signature.verify();
/// 
/// ```
#[derive(Debug,Clone,PartialEq,PartialOrd,Hash,Serialize,Deserialize)]
pub struct LamportSignature {
    pub hash: Algorithms,
    pub pk: Vec<String>,
    // Input must be in hexadecimal
    pub input: String,
    pub signature: Vec<String>,
}

impl LamportKeyPair {
    /// # Lamport Keypair Generation
    /// By default, 1024 keys of 32 bytes (`d`) are generated which allows the signing of 512 bits (`n`).
    /// 
    /// The Secret Key (`d`) can be changed to 32,48,64,or 128 in the `generate_advanced()` function
    /// 
    /// The Hashing Algorithm can be changed to:
    /// - OS_SHA256 (Uses OS)
    /// - OS_SHA512 (Uses OS)
    /// - BLAKE2B (Uses Rust Library)
    /// - BLAKE2B_64 (Uses Rust Library)
    /// 
    /// ## Example Code
    /// 
    /// ```
    /// use leslie_lamport::{LamportKeyPair,Algorithms};
    /// 
    /// fn main(){
    /// 
    ///     let keypair = LamportKeyPair::generate(Algorithms::OS_SHA256);
    /// 
    ///     let keypair_sha512 = LamportKeyPair::generate(Algorithms::OS_SHA512);
    /// 
    ///     let keypair_blake2b = LamportKeyPair::generate(Algorithms::BLAKE2B);
    /// 
    ///     let keypair_blake2b_64 = LamportKeyPair::generate(Algorithms::BLAKE2B_64);
    /// 
    /// }
    /// ```
    /// 
    /// ## Signing
    /// ```
    /// use leslie_lamport::{LamportKeyPair, LamportSignature, Algorithms};
    /// 
    /// fn main(){
    ///     // Generate Lamport Keypairs
    ///     let keypair = LamportKeyPair::generate(Algorithms::OS_SHA256);
    ///     
    ///     // Generate Lamport Signature
    ///     let sig = keypair.sign("b7dba1bc67c531bffb14fbd7f6948540dba10981765a0538575bed2b6bf553d43f35c287635ef7c4cb2c379f71218edaf70d5d73844910684103b99916e428c2");
    ///     
    ///     // Verify Signature
    ///     let is_verified: bool = sig.verify();
    /// }    
    /// ```
    pub fn generate(hash: Algorithms) -> LamportKeyPair {
        // (n, d)
            // n: bytes to be signed so keypairs generated
            // d: size of private keys where d is a member of 32,48,64
        let sk = LamportKeyPair::generate_sk(64,32);
        let pk = LamportKeyPair::generate_pk(sk.clone(), hash);

        LamportKeyPair {
            hash: hash,
            sk: sk,
            pk: pk,
        }
    }
    /// # Generate-Advanced
    /// 
    /// This function is for the users who want more control over the generation of their **LamportKeyPair**. It controls the Number of Keypairs
    /// 
    /// - `hash ∈ {OS_SHA256,OS_SHA512,BLAKE2B,BLAKE2B_64}`
    ///     - Chooses The Hashing Function That Is Used To Generate The **Public Key** and Used For **Verification**
    ///     - **OS_SHA256** and **OS_SHA512** use the Operating Systems Crypto API using `crypto-hash`
    ///     - **BlAKE2B** and **BLAKE2B_64** use the Rust Library `Blake2-rfc`
    /// - `n`
    ///     - **Default:** 64 (512 bits)
    ///     - The **Number of Bytes That Can Be Signed** with the Keypair Generated
    ///     - Calculates the Number of Keypairs using `n * 8 * 2`
    /// - `d ∈ {32,48,64,128}`
    ///     - **Default:** 32 (256 bits)
    ///     - The Size of a **Private Key** and **Signature** in Bytes
    ///     - Larger values of `d` are more Secure
    /// 
    /// ## Example
    /// 
    /// ```
    /// use leslie_lamport::{LamportKeyPair,Algorithms,LamportSignature};
    /// 
    /// fn main(){
    /// 
    ///     // hash | Using the SHA256 Hashing Algorithm
    ///     // n | Generates a Keypair For Signing 32 bytes (256 bits)
    ///     // d | Secret Key Size of 64 bytes (512 bits)
    ///     // Params | (hash, n , d)
    ///     let keypair = LamportKeyPair::generate_advanced(Algorithms::OS_SHA256,32,64);
    /// 
    ///     // Signs 32 bytes with 512 keypairs (`n`)
    ///     let sig = keypair.sign("843868CD905B2AC82D4D692B5E00633CE986C289F728F46826CA48C47E16FBA6");
    /// 
    /// }
    /// ```
    pub fn generate_advanced(hash: Algorithms,n: usize,d: usize) -> LamportKeyPair {
        if d == 32usize || d == 48usize || d == 64usize || d == 128usize {
            let sk = LamportKeyPair::generate_sk(n,d);
            let pk = LamportKeyPair::generate_pk(sk.clone(), hash);
            
            LamportKeyPair {
                hash: hash,
                sk: sk,
                pk: pk,
            }
        }
        else {
            panic!("Invalid Parameter for `d`. `d` should be a member of the set [32,48,64,128]")
        }
    }
    
    /// Internal Generation For Secret Key
    /// 
    /// For Developers:
    /// * The Secret Key is encoded in hexadecimal
    fn generate_sk(n: usize,d: usize) -> Vec<String> {
        // Initialize Empty Vector That Will Be Of Size n
        let mut sk_vec = Vec::new();

        // Bytes * 2 for secret key
        let len: usize = n * 2 * 8;


        // Checks whether d is 32, 48, 64, or 128. Defaults to 32 if an invalid number is chosen.
        if d == 32 { 
            for _ in 0..len {
                sk_vec.push(hex::encode(random::random_32()));
            }
        }
        else if d == 48 {
            for _ in 0..len {
                sk_vec.push(hex::encode(random::random_48().to_vec()));
            }
        }
        else if d == 64 {
            for _ in 0..len {
                sk_vec.push(hex::encode(random::random_64().to_vec()));
            }
        }
        else if d == 128 {
            for _ in 0..len {
                sk_vec.push(hex::encode(random::random_128().to_vec()));
            }
        }
        else {
            for _ in 0..len {
                sk_vec.push(hex::encode(random::random_32()));
            }
        }
        return sk_vec
    }
    /// Internal Generation For Public Key
    /// 
    /// For Developers:
    /// * The Secret Key is in hexadecimal and when passed to the hash function, is decoded into bytes
    fn generate_pk(sk_vec: Vec<String>,hash: Algorithms) -> Vec<String> {
        // Initialize Public Key Vector
        let mut pk_vec = Vec::new();

        for sk in &sk_vec {
            match hash {
                Algorithms::OS_SHA256 => pk_vec.push(os_hash_sha256(sk.to_string())),
                Algorithms::OS_SHA512 => pk_vec.push(os_hash_sha512(sk.to_string())),
                Algorithms::BLAKE2B => pk_vec.push(hash_blake2b(sk.to_string())),
                Algorithms::BLAKE2B_64 => pk_vec.push(hash_blake2b_64(sk.to_string())),
            }
        }
        return pk_vec
    }
    /// A Function To Sign A **Hexadecimal String** of `n` bytes (which is converted to Binary Format)
    /// 
    /// The Function Also Checks The Given Amount of Public Keys and Checks Whether The Input Is Too Large or Too Small.
    /// 
    /// - If Too Large:
    ///     - It Panics
    /// - If The Number Of Public Keys Cannot be Divided by `8` & `2` (so not in byte form):
    ///     - It Panics
    /// - If Too Small:
    ///     - A Notice is Printed
    /// For Developers:
    /// * The Hexadecimal String is converted to bytes before signing
    pub fn sign(&self, input: &str) -> LamportSignature {
        // Convert Bytes as Hexadecimal
        let bytes = hex::decode(input).unwrap();

        // Gets Bytes Length
        let bytes_len: usize = bytes.len();

        // Get `n`, or number of bytes that can be signed with the given public key (`n` / 8 / 2)
        let pk_bytes: usize = self.pk.len() / 16usize;
        
        // TODO| Fix this so this is size of public key
        if bytes_len == pk_bytes {
            // Perfect
        }
        else if bytes_len > pk_bytes {
            // TODO: Add a slightly less invasive panic
            panic!("[Error] There are More Bytes than can be Signed with the Given Amount of Public Keys");
        }
        // TODO| Fix messages
        else if bytes_len < pk_bytes {
            println!("[Notice] Signing Less Than Number Of Public Keys")
        }
        else {
            panic!("[Error] An Error Has Occured In Signing. The Public Key may not be in Number of Bytes, or Divisible by 8 and 2.")
        }
        
        // Initialize String
        let mut bin_string = String::new();

        for byte in bytes {
            bin_string.push_str(&format!("{:08b}",byte));
        }
        
        // Counter For Lamport Key
        let mut counter: usize = 0;

        // Signature Vector
        let mut signature: Vec<String> = Vec::new();

        // Cloning Secret Key May Not Be Best Idea
        for num in bin_string.chars() {
            // x
            if num == '0' {
                signature.push(self.sk[counter].clone());
            }
            // y
            else if num == '1' {
                signature.push(self.sk[counter + 1usize].clone());
            }
            counter = counter + 2usize;
        }
        LamportSignature {
            hash: self.hash.clone(),
            pk: self.pk.clone(),
            input: input.to_string(),
            signature: signature,
        }
    }

}

impl LamportSignature {
    // The `message_as_bytes` function returns the input message (in hexadecimal) to its corresponding bytes.
    pub fn message_as_bytes(&self) -> Vec<u8> {
        let bytes = hex::decode(&self.input).unwrap();
        return bytes
    }
    /// The `verify_public_key` function verifies that the public key in the struct is the same as the one passed through to the parameters and that it is of the same size.
    /// 
    /// The Public Key MUST be a `vector of Strings`
    /// 
    /// For Developer: Maybe remove the check for public key vectors to be the same size as you can always generate a larger public key and only use part of it.
    pub fn verify_public_key(&self, pk: Vec<String>) -> bool {
        if self.pk == pk && self.pk.len() == pk.len() {
            return true
        }
        else {
            return false
        }
    }
    /// The Verify Function that returns a `boolean` value when verifying whether the signature matches the public key and input
    /// 
    /// It must:
    /// - The **Number of Public Keys** must be divisible by `8` and then `2` to retrieve `n`
    /// - THe **Number of Signatures** must be at most half of the Public Keys
    /// - The **Input** Must Be At Most The Size Of `n` in Bytes And Be In **Hexadecimal** (which is converted to binary)
    /// 
    /// For Developers:
    /// * The message is converted from hexadecimal to bytes before verifying
    pub fn verify(&self) -> bool {
        // Get Bytes From Hexadecimal Input
        let bytes = hex::decode(&self.input).unwrap();

        // Get Bytes Length
        let bytes_len: usize = bytes.len();

        // Get `n` (n / 8 / 2)
        let pk_bytes = self.pk.len() / 16usize;
        
        // Check Bytes Against Public Key
        if bytes_len == pk_bytes {
            // Perfect
        }
        else if bytes_len > pk_bytes {
            panic!("[Error] Failure To Verify As Number of Public Keys is Too Small For Given Input");
        }
        else if bytes_len < pk_bytes {
            println!("[Notice] There are More Public Keys Than Needed For The Given Input");
        }
        else {
            panic!("[Error] An Error Has Occured In Verifying. The Public Key may not be in Number of Bytes, or Divisible by 8 and 2.")
        }
        
        // Initialize String
        let mut bin_string = String::new();

        // Change Format To Binary
        for byte in bytes {
            bin_string.push_str(&format!("{:08b}",byte));
        }

        #[allow(unreachable_patterns)]
        let hash_choice = match self.hash {
            Algorithms::OS_SHA256 => 1usize,
            Algorithms::OS_SHA512 => 2usize,
            Algorithms::BLAKE2B => 3usize,
            Algorithms::BLAKE2B_64 => 4usize,
            _ => 0usize,
        };
        
        // General Check To See If Hash Function Is Not Specified. If 0usize, then panic.
        if hash_choice != 1usize && hash_choice != 2usize && hash_choice != 3usize && hash_choice != 4usize {
            panic!("[Error] Cannot Determine Hash Function For Verification")
        }

        let mut counter: usize = 0;
        let mut counter_pk: usize = 0;

        for num in bin_string.chars() {
            // x
            if num == '0' {
                if hash_choice == 1 {
                    if os_hash_sha256(self.signature[counter].clone()) == self.pk[counter_pk] {

                    }
                    else {
                        return false
                    }
                }
                else if hash_choice == 2 {
                    if os_hash_sha512(self.signature[counter].clone()) == self.pk[counter_pk] {

                    }
                    else {
                        return false
                    }
                }
                else if hash_choice == 3 {
                    if hash_blake2b(self.signature[counter].clone()) == self.pk[counter_pk] {

                    }
                    else {
                        return false
                    }
                }
                else if hash_choice == 4 {
                    if hash_blake2b_64(self.signature[counter].clone()) == self.pk[counter_pk] {

                    }
                    else {
                        return false
                    }
                }
                else {
                    panic!("An Error Has Occured In Verifying")
                }
            }
            // y
            else if num == '1' {
                if hash_choice == 1 {
                    if os_hash_sha256(self.signature[counter].clone()) == self.pk[counter_pk + 1usize] {

                    }
                    else {
                        return false
                    }
                }
                else if hash_choice == 2 {
                    if os_hash_sha512(self.signature[counter].clone()) == self.pk[counter_pk + 1usize] {

                    }
                    else {
                        return false
                    }
                }
                else if hash_choice == 3 {
                    if hash_blake2b(self.signature[counter].clone()) == self.pk[counter_pk + 1usize] {

                    }
                    else {
                        return false
                    }
                }
                else if hash_choice == 4 {
                    if hash_blake2b_64(self.signature[counter].clone()) == self.pk[counter_pk + 1usize] {

                    }
                    else {
                        return false
                    }
                }
                else {
                    panic!("An Error Has Occured In Verifying")
                }
            }
            counter = counter + 1usize;
            counter_pk = counter_pk + 2usize;
        }
        return true
    }
}

// For Developers:
// * The input to each hash function is in hexadecimal and requires hexadecimal decoding

/// Private Hash Blake2b (32byte Digest)
fn hash_blake2b(input: String) -> String {
    let mut context = Blake2b::new(32);
    context.update(&hex::decode(input).unwrap());
    let hash = hex::encode(context.finalize().as_bytes());
    return hash
}
/// Private Hash Blake2b (64byte Digest)
fn hash_blake2b_64(input: String) -> String {
    let mut context = Blake2b::new(64);
    context.update(&hex::decode(input).unwrap());
    let hash = hex::encode(context.finalize().as_bytes());
    return hash
}
/// Private Hash OS_SHA256 (32byte Digest)
fn os_hash_sha256(input: String) -> String {
    return hex_digest(Algorithm::SHA256, &hex::decode(input).unwrap());
}
/// Private Hash OS_SHA512 (64byte Digest)
fn os_hash_sha512(input: String) -> String {
    return hex_digest(Algorithm::SHA512, &hex::decode(input).unwrap());
}