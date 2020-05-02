use leslie_lamport::{LamportKeyPair,LamportSignature,Algorithms};

fn main(){
    // Generate Keypair
    let keypair = LamportKeyPair::generate(Algorithms::OS_SHA256);
    
    // Generate Signature
    let sig = keypair.sign("b7dba1bc67c531bffb14fbd7f6948540dba10981765a0538575bed2b6bf553d43f35c287635ef7c4cb2c379f71218edaf70d5d73844910684103b99916e428c2");

    // Serialize To YAML
    let serialized_yaml = serde_yaml::to_string(&keypair);

}