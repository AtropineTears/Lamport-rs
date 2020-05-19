#[allow(unused_imports)]
use leslie_lamport::{LamportKeyPair,LamportSignature,Algorithms};

fn main(){
    serialize();
}


fn serialize(){
    // Generate "LamportKeypair" Struct
    let keypair = LamportKeyPair::generate(Algorithms::OS_SHA256);
    
    // Generate "LamportSignature" Struct
    let signature = keypair.sign("b7dba1bc67c531bffb14fbd7f6948540dba10981765a0538575bed2b6bf553d43f35c287635ef7c4cb2c379f71218edaf70d5d73844910684103b99916e428c2");

    // Serializes "LamportKeypair" and "LamportSignature" | Keep "LamportKeypair" Private
    let serialized_keypair = serde_yaml::to_string(&keypair);
    let serialized_signature = serde_yaml::to_string(&signature);

}