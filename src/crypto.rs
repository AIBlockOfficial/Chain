pub use ring;

pub mod sign_ed25519 {
    pub use ring::signature::Ed25519KeyPair as SecretKey;
    use ring::signature::KeyPair;
    pub use ring::signature::Signature as SignatureBase;
    pub use ring::signature::UnparsedPublicKey;
    pub use ring::signature::{ED25519, ED25519_PUBLIC_KEY_LEN};
    use serde::{Deserialize, Serialize};
    use serde_big_array::BigArray;
    use std::convert::TryInto;

    pub type PublicKeyBase = <SecretKey as KeyPair>::PublicKey;

    // Constants copied from the ring library
    const SCALAR_LEN: usize = 32;
    const ELEM_LEN: usize = 32;
    const SIGNATURE_LEN: usize = ELEM_LEN + SCALAR_LEN;
    const ED25519_SIGNATURE_LEN: usize = SIGNATURE_LEN;

    #[derive(Clone, Copy, Debug, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Signature(#[serde(with = "BigArray")] [u8; ED25519_SIGNATURE_LEN]);

    impl AsRef<[u8]> for Signature {
        fn as_ref(&self) -> &[u8] {
            self.0.as_ref()
        }
    }

    #[derive(Clone, Copy, Debug, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
    pub struct PublicKey(#[serde(with = "BigArray")] [u8; ED25519_PUBLIC_KEY_LEN]);

    impl AsRef<[u8]> for PublicKey {
        fn as_ref(&self) -> &[u8] {
            self.0.as_ref()
        }
    }

    pub fn verify_detached(sig: &Signature, m: &[u8], pk: &PublicKey) -> bool {
        let upk = UnparsedPublicKey::new(&ED25519, pk);
        upk.verify(m, sig.as_ref()).is_ok()
    }

    pub fn sign_detached(m: &[u8], sk: &SecretKey) -> Signature {
        Signature(sk.sign(m).as_ref().try_into().unwrap())
    }

    pub fn gen_keypair() -> (PublicKey, SecretKey) {
        let rand = ring::rand::SystemRandom::new();
        let pkcs8 = SecretKey::generate_pkcs8(&rand).unwrap();
        let secret = SecretKey::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public = PublicKey(secret.public_key().as_ref().try_into().unwrap());
        (public, secret)
    }
}
