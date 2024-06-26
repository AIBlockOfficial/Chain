pub use ring;
use std::convert::TryInto;
use tracing::warn;

pub mod sign_ed25519 {
    use super::deserialize_slice;
    pub use ring::signature::Ed25519KeyPair as SecretKeyBase;
    use ring::signature::KeyPair;
    pub use ring::signature::Signature as SignatureBase;
    pub use ring::signature::UnparsedPublicKey;
    pub use ring::signature::{ED25519, ED25519_PUBLIC_KEY_LEN};
    use serde::{Deserialize, Serialize};
    use std::convert::TryInto;
    use tracing::warn;

    pub type PublicKeyBase = <SecretKey as KeyPair>::PublicKey;

    // Constants copied from the ring library
    const SCALAR_LEN: usize = 32;
    const ELEM_LEN: usize = 32;
    const SIGNATURE_LEN: usize = ELEM_LEN + SCALAR_LEN;
    pub const ED25519_SIGNATURE_LEN: usize = SIGNATURE_LEN;

    /// Signature data
    /// We used sodiumoxide serialization before (treated it as slice with 64 bit length prefix).
    #[derive(Clone, Copy, Debug, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Signature(
        #[serde(serialize_with = "<[_]>::serialize")]
        #[serde(deserialize_with = "deserialize_slice")]
        [u8; ED25519_SIGNATURE_LEN],
    );

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
    /// We used sodiumoxide serialization before (treated it as slice with 64 bit length prefix).
    #[derive(Clone, Copy, Debug, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
    pub struct PublicKey(
        #[serde(serialize_with = "<[_]>::serialize")]
        #[serde(deserialize_with = "deserialize_slice")]
        [u8; ED25519_PUBLIC_KEY_LEN],
    );

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
    /// We used sodiumoxide serialization before (treated it as slice with 64 bit length prefix).
    /// Slice and vector are serialized the same.
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

    pub fn verify_detached(sig: &Signature, msg: &[u8], pk: &PublicKey) -> bool {
        let upk = UnparsedPublicKey::new(&ED25519, pk);
        upk.verify(msg, sig.as_ref()).is_ok()
    }

    pub fn sign_detached(msg: &[u8], sk: &SecretKey) -> Signature {
        let secret = match SecretKeyBase::from_pkcs8(sk.as_ref()) {
            Ok(secret) => secret,
            Err(_) => {
                warn!("Invalid secret key");
                return Signature([0; ED25519_SIGNATURE_LEN]);
            }
        };

        let signature = match secret.sign(msg).as_ref().try_into() {
            Ok(signature) => signature,
            Err(_) => {
                warn!("Invalid signature");
                return Signature([0; ED25519_SIGNATURE_LEN]);
            }
        };
        Signature(signature)
    }

    pub fn verify_append(sm: &[u8], pk: &PublicKey) -> bool {
        if sm.len() > ED25519_SIGNATURE_LEN {
            let start = sm.len() - ED25519_SIGNATURE_LEN;
            let sig = Signature(match sm[start..].try_into() {
                Ok(sig) => sig,
                Err(_) => {
                    warn!("Invalid signature");
                    return false;
                }
            });
            let msg = &sm[..start];
            verify_detached(&sig, msg, pk)
        } else {
            false
        }
    }

    pub fn sign_append(msg: &[u8], sk: &SecretKey) -> Vec<u8> {
        let sig = sign_detached(msg, sk);
        let mut sm = msg.to_vec();
        sm.extend_from_slice(sig.as_ref());
        sm
    }

    pub fn gen_keypair() -> (PublicKey, SecretKey) {
        let rand = ring::rand::SystemRandom::new();
        let pkcs8 = match SecretKeyBase::generate_pkcs8(&rand) {
            Ok(pkcs8) => pkcs8,
            Err(_) => {
                warn!("Failed to generate secret key base for pkcs8");
                return (PublicKey([0; ED25519_PUBLIC_KEY_LEN]), SecretKey(vec![]));
            }
        };

        let secret = match SecretKeyBase::from_pkcs8(pkcs8.as_ref()) {
            Ok(secret) => secret,
            Err(_) => {
                warn!("Invalid secret key base");
                return (PublicKey([0; ED25519_PUBLIC_KEY_LEN]), SecretKey(vec![]));
            }
        };

        let pub_key_gen = match secret.public_key().as_ref().try_into() {
            Ok(pub_key_gen) => pub_key_gen,
            Err(_) => {
                warn!("Invalid public key generation");
                return (PublicKey([0; ED25519_PUBLIC_KEY_LEN]), SecretKey(vec![]));
            }
        };
        let public = PublicKey(pub_key_gen);
        let secret = match SecretKey::from_slice(pkcs8.as_ref()) {
            Some(secret) => secret,
            None => {
                warn!("Invalid secret key");
                return (PublicKey([0; ED25519_PUBLIC_KEY_LEN]), SecretKey(vec![]));
            }
        };

        (public, secret)
    }
}

pub mod secretbox_chacha20_poly1305 {
    // Use key and nonce separately like rust-tls does
    use super::{deserialize_slice, generate_random};
    pub use ring::aead::LessSafeKey as KeyBase;
    pub use ring::aead::Nonce as NonceBase;
    pub use ring::aead::NONCE_LEN;
    use ring::aead::{Aad, UnboundKey, CHACHA20_POLY1305};
    use serde::{Deserialize, Serialize};
    use std::convert::TryInto;

    pub const KEY_LEN: usize = 256 / 8;

    /// key data
    #[derive(Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Key(
        #[serde(serialize_with = "<[_]>::serialize")]
        #[serde(deserialize_with = "deserialize_slice")]
        [u8; KEY_LEN],
    );

    impl Key {
        pub fn from_slice(slice: &[u8]) -> Option<Self> {
            Some(Self(slice.try_into().ok()?))
        }
    }

    impl AsRef<[u8]> for Key {
        fn as_ref(&self) -> &[u8] {
            self.0.as_ref()
        }
    }

    /// Nonce data
    #[derive(Clone, Copy, Debug, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Nonce(
        #[serde(serialize_with = "<[_]>::serialize")]
        #[serde(deserialize_with = "deserialize_slice")]
        [u8; NONCE_LEN],
    );

    impl Nonce {
        pub fn from_slice(slice: &[u8]) -> Option<Self> {
            Some(Self(slice.try_into().ok()?))
        }
    }

    impl AsRef<[u8]> for Nonce {
        fn as_ref(&self) -> &[u8] {
            self.0.as_ref()
        }
    }

    pub fn seal(mut plain_text: Vec<u8>, nonce: &Nonce, key: &Key) -> Option<Vec<u8>> {
        let key = get_keybase(key)?;
        let nonce = get_noncebase(nonce);
        let aad = Aad::empty();
        let cipher_text = {
            key.seal_in_place_append_tag(nonce, aad, &mut plain_text)
                .ok()?;
            plain_text
        };
        Some(cipher_text)
    }

    pub fn open(mut cipher_text: Vec<u8>, nonce: &Nonce, key: &Key) -> Option<Vec<u8>> {
        let key = get_keybase(key)?;
        let nonce = get_noncebase(nonce);
        let aad = Aad::empty();
        let plain_text = {
            let len = key.open_in_place(nonce, aad, &mut cipher_text).ok()?.len();
            cipher_text.truncate(len);
            cipher_text
        };
        Some(plain_text)
    }

    fn get_keybase(key: &Key) -> Option<KeyBase> {
        let key = UnboundKey::new(&CHACHA20_POLY1305, key.as_ref()).ok()?;
        Some(KeyBase::new(key))
    }

    fn get_noncebase(nonce: &Nonce) -> NonceBase {
        NonceBase::assume_unique_for_key(nonce.0)
    }

    pub fn gen_key() -> Key {
        Key(generate_random())
    }

    pub fn gen_nonce() -> Nonce {
        Nonce(generate_random())
    }
}

pub mod pbkdf2 {
    use super::{deserialize_slice, generate_random};
    use ring::pbkdf2::{derive, PBKDF2_HMAC_SHA256};
    use serde::{Deserialize, Serialize};
    use std::convert::TryInto;
    use std::num::NonZeroU32;
    use tracing::warn;

    pub const SALT_LEN: usize = 256 / 8;
    pub const OPSLIMIT_INTERACTIVE: u32 = 100_000;

    #[derive(Clone, Copy, Debug, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Salt(
        #[serde(serialize_with = "<[_]>::serialize")]
        #[serde(deserialize_with = "deserialize_slice")]
        [u8; SALT_LEN],
    );

    impl Salt {
        pub fn from_slice(slice: &[u8]) -> Option<Self> {
            Some(Self(slice.try_into().ok()?))
        }
    }

    impl AsRef<[u8]> for Salt {
        fn as_ref(&self) -> &[u8] {
            self.0.as_ref()
        }
    }

    pub fn derive_key(key: &mut [u8], passwd: &[u8], salt: &Salt, iterations: u32) {
        let iterations = match NonZeroU32::new(iterations) {
            Some(iterations) => iterations,
            None => {
                warn!("Invalid iterations in key derivation");
                return;
            }
        };
        derive(PBKDF2_HMAC_SHA256, iterations, salt.as_ref(), passwd, key);
    }

    pub fn gen_salt() -> Salt {
        Salt(generate_random())
    }
}

pub mod sha3_256 {
    pub use sha3::digest::Output;
    pub use sha3::Digest;
    pub use sha3::Sha3_256;

    pub fn digest(data: &[u8]) -> Output<Sha3_256> {
        Sha3_256::digest(data)
    }

    pub fn digest_all<'a>(data: impl Iterator<Item = &'a [u8]>) -> Output<Sha3_256> {
        let mut hasher = Sha3_256::new();
        data.for_each(|v| hasher.update(v));
        hasher.finalize()
    }
}

fn deserialize_slice<'de, D: serde::Deserializer<'de>, const N: usize>(
    deserializer: D,
) -> Result<[u8; N], D::Error> {
    let value: &[u8] = serde::Deserialize::deserialize(deserializer)?;
    value
        .try_into()
        .map_err(|_| serde::de::Error::custom("Invalid array in deserialization".to_string()))
}

pub fn generate_random<const N: usize>() -> [u8; N] {
    let mut value: [u8; N] = [0; N];

    use ring::rand::SecureRandom;
    let rand = ring::rand::SystemRandom::new();
    match rand.fill(&mut value) {
        Ok(_) => (),
        Err(_) => warn!("Failed to generate random bytes"),
    };

    value
}
