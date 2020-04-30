mod random;

use serde::{Serialize, Deserialize};

use crypto_hash::{Algorithm, hex_digest};
use blake2_rfc::blake2b::Blake2b;
use hex;


// n = Digest Size (32,48,64) to sign | How Many Bits Can We Sign
// d = Digest Size of Private Key
// pk_d = Digest Size of Public Key


/// # Hashing Algorithms
/// This lists the algorithms available to hash the secret key from.
/// - OS_SHA256 (Operating System SHA256)
/// - OS_SHA512 (Operating System SHA512)
/// - BLAKE2B (Rust Library For Blake2b)
#[derive(Copy,Debug,Clone,PartialEq,PartialOrd,Hash,Serialize,Deserialize)]
pub enum Algorithms {
    OS_SHA256,
    OS_SHA512,
    BLAKE2B,
}

/// # Lamport Keypair
/// This struct represents a lamport keypair that ranges from secret keys of sizes:
/// - 32 (256 bits)
/// - 48 (384 bits)
/// - 64 (512 bits)
#[derive(Debug,Clone,PartialEq,PartialOrd,Hash,Serialize,Deserialize)]
pub struct LamportKeyPair {
    hash: Algorithms,
    sk: Vec<String>,
    pk: Vec<String>,
}

/// # Lamport Signature
/// This struct contains:
/// - The Hashing Algorithm
/// - The Public Key
/// - The Input String
/// - The Signature
/// Its only function is for verification purposes
#[derive(Debug,Clone,PartialEq,PartialOrd,Hash,Serialize,Deserialize)]
pub struct LamportSignature {
    hash: Algorithms,
    pk: Vec<String>,
    input: String,
    signature: Vec<String>,
}

impl LamportKeyPair {
    /// # Lamport Keypair Generation
    /// By default, 1024 keys of 32 bytes are generated which allows the signing of 512 bits.
    /// 
    /// The Secret Key (d) can be changed to 32,48, or 64 in the code itself.
    /// 
    /// The Hashing Algorithm can be changed to:
    /// - OS_SHA256 (Uses OS)
    /// - OS_SHA512 (Uses OS)
    /// - BLAKE2B (Uses Rust Library)
    /// 
    /// ## Example Code
    /// 
    /// ```
    /// use leslie_lamport::*;
    /// 
    /// fn main(){
    ///     let keypair = LamportKeyPair::generate(Algorithms::OS_SHA256);
    /// }
    /// ```
    pub fn generate(hash: Algorithms) -> LamportKeyPair {
        // (n, d)
        let sk = LamportKeyPair::generate_sk(64,32);
        let pk = LamportKeyPair::generate_pk(sk.clone(), hash);

        LamportKeyPair {
            hash: hash,
            sk: sk,
            pk: pk,
        }
    }
    
    /// # Generate Secret Key
    fn generate_sk(n: usize,d: usize) -> Vec<String> {
        // Initialize Empty Vector That Will Be Of Size n
        let mut sk_vec = Vec::new();

        // Bytes * 2 for secret key
        let len: usize = n * 2 * 8;


        // Checks whether d is 32, 48, or 64. Defaults to 32 if an invalid number is chosen.
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
        else {
            for _ in 0..len {
                sk_vec.push(hex::encode(random::random_32()));
            }
        }

        return sk_vec
    }
    fn generate_pk(sk_vec: Vec<String>,hash: Algorithms) -> Vec<String> {
        // Initialize Public Key Vector
        let mut pk_vec = Vec::new();

        for sk in &sk_vec {
            match hash {
                Algorithms::OS_SHA256 => pk_vec.push(os_hash_sha256(sk.to_string())),
                Algorithms::OS_SHA512 => pk_vec.push(os_hash_sha512(sk.to_string())),
                Algorithms::BLAKE2B => pk_vec.push(hash_blake2b(sk.to_string())),
            }
        }
        return pk_vec
    }
    /// # Signature
    /// **The Input String Must Be Hexadecimal**
    /// 
    /// Signs up to a 512 bit String when n = 64
    pub fn sign(&self, input: &str) -> LamportSignature {
        // Convert Bytes as Hexadecimal
        let bytes = hex::decode(input).unwrap();
        
        if bytes.len() > 64 {
            // TODO: Add a slightly less invasive panic
            panic!("More Than 64 Bytes Provided");
        }
        
        // Initialize String
        let mut bin_string = "".to_string();

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
    pub fn verify(&self) -> bool {
        let bytes = hex::decode(&self.input).unwrap();
        
        if bytes.len() > 64 {
            // TODO: Add a slightly less invasive panic
            panic!("More Than 64 Bytes Provided");
        }
        
        // Initialize String
        let mut bin_string = "".to_string();

        for byte in bytes {
            bin_string.push_str(&format!("{:08b}",byte));
        }

        let mut hash_choice = 0;

        match &self.hash {
            Algorithms::OS_SHA256 => hash_choice = 1,
            Algorithms::OS_SHA512 => hash_choice = 2,
            Algorithms::BLAKE2B => hash_choice = 3,
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


fn hash_blake2b(input: String) -> String {
    let mut context = Blake2b::new(32);
    context.update(&hex::decode(input).unwrap());
    let hash = hex::encode(context.finalize().as_bytes());
    return hash
}
fn os_hash_sha256(input: String) -> String {
    return hex_digest(Algorithm::SHA256, &hex::decode(input).unwrap());
}
fn os_hash_sha512(input: String) -> String {
    return hex_digest(Algorithm::SHA512, &hex::decode(input).unwrap());
}

#[test]
fn generate(){
    let keypair = LamportKeyPair::generate(Algorithms::OS_SHA256);
    println!("Hash: {:?}", keypair.hash);
    let sig = keypair.sign("b7dba1bc67c531bffb14fbd7f6948540dba10981765a0538575bed2b6bf553d43f35c287635ef7c4cb2c379f71218edaf70d5d73844910684103b99916e428c2");
    let x: bool = sig.verify();

    println!("Is It Right: {}",x)
}

#[test]
fn generate_wrong(){
    let keypair = LamportKeyPair::generate(Algorithms::OS_SHA256);
    println!("Hash: {:?}", keypair.hash);
    let mut sig = keypair.sign("b7dba1bc67c531bffb14fbd7f6948540dba10981765a0538575bed2b6bf553d43f35c287635ef7c4cb2c379f71218edaf70d5d73844910684103b99916e428c2");
    sig.input = "b7dba1bc67c531bffb14fbd7f6948540dba10981765a0538575bed2b6bf553d43f35c287635ef7c4cb2c379f71218edaf70d5d73844910684103b99916e428c3".to_string();
    let x: bool = sig.verify();

    println!("Is It Right: {}",x);
}

#[test]
fn generate_sha512(){
    let keypair = LamportKeyPair::generate(Algorithms::OS_SHA512);
    println!("SHA512: {}", keypair.pk[1023]);

    let sig = keypair.sign("b7dba1bc67c531bffb14fbd7f6948540dba10981765a0538575bed2b6bf553d43f35c287635ef7c4cb2c379f71218edaf70d5d73844910684103b99916e428c2");
    let verified = sig.verify();

    println!("SHA512 is verified: {}",verified);

}

#[test]
fn generate_blake2b(){
    let _keypair = LamportKeyPair::generate(Algorithms::BLAKE2B);
}




#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
