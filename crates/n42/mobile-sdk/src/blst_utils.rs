use blst::min_pk::SecretKey;
use rand::RngCore;

pub fn generate_bls12_381_keypair() -> eyre::Result<(String, String)> {
    let mut rng = ::rand::thread_rng();
    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);

    let sk = SecretKey::key_gen(&ikm, &[])
        .map_err(|e| eyre::eyre!("SecretKey::key_gen() error {e:?}"))?;

    let pk = sk.sk_to_pk();

    let privkey_hex = hex::encode(sk.to_bytes());
    let pubkey_hex = hex::encode(pk.to_bytes());

    Ok((privkey_hex, pubkey_hex))
}
