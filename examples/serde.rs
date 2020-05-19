#[allow(unused_variables)]
#[allow(unused_imports)]
use leslie_lamport::{LamportKeyPair,LamportSignature,Algorithms};
use serde_yaml;

fn main(){
    serialize();
}

fn serialize(){
    // Generate "LamportKeyPair" Struct
    let keypairs = LamportKeyPair::generate(Algorithms::OS_SHA256);
    
    // Generate "LamportSignature" Struct
    let sig = keypairs.sign("b7dba1bc67c531bffb14fbd7f6948540dba10981765a0538575bed2b6bf553d43f35c287635ef7c4cb2c379f71218edaf70d5d73844910684103b99916e428c2");

    let _serialized_keypair = serde_yaml::to_string(&keypairs).unwrap();
    let _serialized_signature = serde_yaml::to_string(&sig).unwrap();

}