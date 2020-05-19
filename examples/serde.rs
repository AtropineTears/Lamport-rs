#[allow(unused_variables)]
#[allow(unused_imports)]
use leslie_lamport::{LamportKeyPair,LamportSignature,Algorithms};
use serde_yaml;

use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

fn main(){
    // Serializes Both Keypair and Signature
    let (priv_keypair, signature) = serialize();
    
    // Write To File
    write_to_file(priv_keypair, "keypairs.yml");
    write_to_file(signature, "signature.yml");

    // Read Files
    let keypair_serialized = read_file("keypairs.yml");
    let signature_serialized = read_file("signature.yml");

    // Deserialize Both Of Them
        // Deserialized Keypair
    let deserialized_keypair: LamportKeyPair = serde_yaml::from_str(&keypair_serialized).unwrap();
        // Deserialized Signature
    let deserialized_signature: LamportSignature = serde_yaml::from_str(&signature_serialized).unwrap();

    // New Signature Using Deserialized Keypair
    let new_signature = deserialized_keypair.sign("0B680979525170254706FEBEE610F335C41723E9C525B380DF91E51790E57C21573055CFB5B517678A53D5BB4BB6F446ADA7613411B1C4787247FBB85848751D");

    
    // Verify Deserialized Signature
    let is_verified: bool = deserialized_signature.verify();
    let is_verified_2: bool = new_signature.verify();


    // Print Out Results
    println!("\nIs Verified: {}",is_verified);
    println!("\nIs Verified (2): {}",is_verified_2);

    // Assert Results Were True
    assert_eq!(is_verified, true);
    assert_eq!(is_verified_2, true);
}

fn serialize() -> (String,String) {
    // Generate "LamportKeyPair" Struct
    let keypairs = LamportKeyPair::generate(Algorithms::OS_SHA256);
    
    // Generate "LamportSignature" Struct
    let sig = keypairs.sign("b7dba1bc67c531bffb14fbd7f6948540dba10981765a0538575bed2b6bf553d43f35c287635ef7c4cb2c379f71218edaf70d5d73844910684103b99916e428c2");

    // Serializes To YAML String
        // Serializes Keypair
    let keypair_yaml = serde_yaml::to_string(&keypairs).unwrap();
        // Serializes Signature
    let signature_yaml = serde_yaml::to_string(&sig).unwrap();

    // Returns As YAML Strings
    return (keypair_yaml, signature_yaml)

}

fn write_to_file(yaml: String, pathname: &str) {
    let path = Path::new(pathname);
    let display = path.display();


    let mut file = match File::create(&path) {
        Err(_) => panic!("couldn't create {}:", display),
        Ok(file) => file,
    };

    match file.write_all(yaml.as_bytes()) {
        Err(_) => panic!("couldn't write to {}", display),
        Ok(_) => println!("successfully wrote to {}", display),
    }
}

fn read_file(pathname: &str) -> String {
    // Create a path to the desired file
    let path = Path::new(pathname);
    let display = path.display();

    // Open the path in read-only mode, returns `io::Result<File>`
    let mut file = match File::open(&path) {
        // The `description` method of `io::Error` returns a string that
        // describes the error
        Err(_) => panic!("couldn't open {}", display),
        Ok(file) => file,
    };

    // Read the file contents into a string, returns `io::Result<usize>`
    let mut s = String::new();
    match file.read_to_string(&mut s) {
        Err(_) => panic!("couldn't read {}:", display),
        Ok(_) => println!("Read {}", display),
    }
    return s
}