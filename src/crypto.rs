pub use ring;

pub mod sign_ed25519 {
    pub use ring::signature::Ed25519KeyPair as SecretKeyBase;
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
    pub const ED25519_SIGNATURE_LEN: usize = SIGNATURE_LEN;

    /// Signature data
    #[derive(Clone, Copy, Debug, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Signature(#[serde(with = "BigArray")] [u8; ED25519_SIGNATURE_LEN]);

    impl Signature {
        pub fn from_slice(slice: &[u8]) -> Option<Self> {
            Some(Self(slice.try_into().ok()?))
        }
    }

    impl AsRef<[u8]> for Signature {
        fn as_ref(&self) -> &[u8] {
            self.0.as_ref()
        }
    }

    /// Public key data
    #[derive(Clone, Copy, Debug, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
    pub struct PublicKey(#[serde(with = "BigArray")] [u8; ED25519_PUBLIC_KEY_LEN]);

    impl PublicKey {
        pub fn from_slice(slice: &[u8]) -> Option<Self> {
            Some(Self(slice.try_into().ok()?))
        }
    }

    impl AsRef<[u8]> for PublicKey {
        fn as_ref(&self) -> &[u8] {
            self.0.as_ref()
        }
    }

    /// PKCS8 encoded secret key pair
    #[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SecretKey(Vec<u8>);

    impl SecretKey {
        pub fn from_slice(slice: &[u8]) -> Option<Self> {
            Some(Self(slice.to_vec()))
        }
    }

    impl AsRef<[u8]> for SecretKey {
        fn as_ref(&self) -> &[u8] {
            self.0.as_ref()
        }
    }

    pub fn verify_detached(sig: &Signature, m: &[u8], pk: &PublicKey) -> bool {
        let upk = UnparsedPublicKey::new(&ED25519, pk);
        upk.verify(m, sig.as_ref()).is_ok()
    }

    pub fn sign_detached(m: &[u8], sk: &SecretKey) -> Signature {
        let secret = SecretKeyBase::from_pkcs8(sk.as_ref()).unwrap();
        Signature(secret.sign(m).as_ref().try_into().unwrap())
    }

    pub fn verify_append(sm: &[u8], pk: &PublicKey) -> bool {
        if sm.len() > ED25519_SIGNATURE_LEN {
            let start = sm.len() - ED25519_SIGNATURE_LEN;
            let sig = Signature(sm[start..].try_into().unwrap());
            let msg = &sm[..start];
            verify_detached(&sig, msg, pk)
        } else {
            false
        }
    }

    pub fn sign_append(m: &[u8], sk: &SecretKey) -> Vec<u8> {
        let sig = sign_detached(m, sk);
        let mut sm = m.to_vec();
        sm.extend_from_slice(sig.as_ref());
        sm
    }

    pub fn gen_keypair() -> (PublicKey, SecretKey) {
        let rand = ring::rand::SystemRandom::new();
        let pkcs8 = SecretKeyBase::generate_pkcs8(&rand).unwrap();
        let secret = SecretKeyBase::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public = PublicKey(secret.public_key().as_ref().try_into().unwrap());
        let secret = SecretKey::from_slice(pkcs8.as_ref()).unwrap();
        (public, secret)
    }
}
