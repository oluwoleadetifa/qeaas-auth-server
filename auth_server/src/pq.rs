use oqs::kem;

pub fn generate_kyber_keypair() -> (Vec<u8>, Vec<u8>) {
    let kem = kem::Kem::new(kem::Algorithm::Kyber768).unwrap();
    let (pk, sk) = kem.keypair().unwrap();
    (pk.into_vec(), sk.into_vec())
}
