use auth_server::pq::PqContext; // if your crate name differs, update this.

#[test]
fn pq_sign_verify_roundtrip() {
    let pq = PqContext::new().unwrap();

    // Simulate a client keypair
    let sig = oqs::sig::Sig::new(oqs::sig::Algorithm::Dilithium5).unwrap();
    let (client_pk, client_sk) = sig.keypair().unwrap();

    let msg = b"hello-qeaas";
    let client_sig = sig.sign(msg, &client_sk).unwrap();

    let ok = pq.verify_with_client_pk_bytes(client_pk.as_ref(), msg, client_sig.as_ref()).unwrap();
    assert!(ok);
}

#[test]
fn pq_kem_encaps_decaps_roundtrip() {
    let pq = PqContext::new().unwrap();

    // Simulate a client kem keypair
    let kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber1024).unwrap();
    let (client_pk, client_sk) = kem.keypair().unwrap();

    let (ct_bytes, ss_server) = pq.encapsulate_to_client_kem_pk_bytes(client_pk.as_ref()).unwrap();

    // Client decapsulates
    let ct_ref = kem.ciphertext_from_bytes(&ct_bytes).unwrap();
    let ss_client = kem.decapsulate(&client_sk, ct_ref).unwrap();

    assert_eq!(ss_server, ss_client.as_ref());
}
