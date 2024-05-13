pub use ring;
use tracing::warn;

pub mod sign_ed25519 {
    use super::{byte_slice_codec, byte_vec_codec};
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
        #[serde(with = "byte_slice_codec")]
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
        #[serde(with = "byte_slice_codec")]
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
    pub struct SecretKey(
        #[serde(with = "byte_vec_codec")]
        Vec<u8>,
    );

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

    /// Generates a completely random keypair
    pub fn gen_keypair() -> (PublicKey, SecretKey) {
        gen_keypair_rand(&ring::rand::SystemRandom::new())
    }

    /// Generates a keypair using the given random number generator
    pub fn gen_keypair_rand(rand: &dyn ring::rand::SecureRandom) -> (PublicKey, SecretKey) {
        let pkcs8 = match SecretKeyBase::generate_pkcs8(rand) {
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
    use super::{byte_slice_codec, generate_random};
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
        #[serde(with = "byte_slice_codec")]
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
        #[serde(with = "byte_slice_codec")]
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
    use super::{generate_random, byte_slice_codec};
    use ring::pbkdf2::{derive, PBKDF2_HMAC_SHA256};
    use serde::{Deserialize, Serialize};
    use std::convert::TryInto;
    use std::num::NonZeroU32;
    use tracing::warn;

    pub const SALT_LEN: usize = 256 / 8;
    pub const OPSLIMIT_INTERACTIVE: u32 = 100_000;

    #[derive(Clone, Copy, Debug, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Salt(
        #[serde(with = "byte_slice_codec")]
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

/// A serializer+deserializer for fixed-size byte arrays.
mod byte_slice_codec {
    use std::convert::TryInto;
    use serde::de::Error;

    pub fn serialize<S: serde::Serializer, const N: usize>(
        values: &[u8; N],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        super::byte_vec_codec::serialize(values, serializer)
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>, const N: usize>(
        deserializer: D,
    ) -> Result<[u8; N], D::Error> {
        let vec = super::byte_vec_codec::deserialize(deserializer)?;
        let bytes : [u8; N] = vec.try_into()
            .map_err(|vec: Vec<u8>|
                <D::Error>::custom(format!("Invalid array in deserialization: length {}", vec.len())))?;
        Ok(bytes)
    }
}

/// A serializer+deserializer for variable-length byte arrays.
/// This intelligently selects the output representation depending on whether the data is being
/// serialized for a human-readable format (i.e. JSON) or not.
mod byte_vec_codec {
    use core::fmt;
    use serde::Serialize;
    use serde::de::{SeqAccess, Visitor};

    pub fn serialize<S: serde::Serializer>(
        values: &[u8],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            // We're serializing for a human-readable format, serialize the bytes as a hex string
            serde::Serializer::serialize_str(serializer, &hex::encode(values))
        } else {
            // We're serializing for a binary format, serialize the bytes as an array of bytes
            values.serialize(serializer)
        }
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        if deserializer.is_human_readable() {
            // We're deserializing a human-readable format, we'll accept two different
            // representations:
            // - A hexadecimal string
            // - An array of byte literals (this format should never be produced by the serializer
            //   for human-readable formats, but it was in the past, so we'll still support reading
            //   it for backwards-compatibility).

            struct HexStringOrBytes();

            impl<'de> Visitor<'de> for HexStringOrBytes {
                type Value = Vec<u8>;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("hex string or byte array")
                }

                fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> where E: serde::de::Error {
                    hex::decode(value).map_err(E::custom)
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error> where A: SeqAccess<'de> {
                    let mut vec = Vec::new();
                    while let Some(elt) = seq.next_element::<u8>()? {
                        vec.push(elt);
                    }
                    Ok(vec)
                }
            }

            deserializer.deserialize_any(HexStringOrBytes())
        } else {
            // We're deserializing a binary format, read a sequence of raw bytes
            let value: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
            Ok(value)
        }
    }
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

/*---- TESTS ----*/

#[cfg(test)]
mod tests {
    use crate::crypto::pbkdf2::Salt;
    use crate::crypto::secretbox_chacha20_poly1305::*;
    use crate::crypto::sign_ed25519::*;

    #[test]
    fn test_ed25519_signature_serialize() {
        let sig_hex = "6954e926b9b8af8f37d84fd42b1d0f928b5fe5bc124674e98c19395cf3df39930cbb530b658adce33cbd6df68239304bc973647b9a814720a62c65a8b49d6206";
        let sig_bytes = hex::decode(sig_hex).unwrap();
        let sig = Signature::from_slice(&sig_bytes).unwrap();

        // Convert to/from binary
        let sig_bin = bincode::serialize(&sig).unwrap();
        assert_eq!(hex::encode(&sig_bin), "40000000000000006954e926b9b8af8f37d84fd42b1d0f928b5fe5bc124674e98c19395cf3df39930cbb530b658adce33cbd6df68239304bc973647b9a814720a62c65a8b49d6206");
        assert_eq!(bincode::deserialize::<Signature>(&sig_bin).unwrap(), sig);

        // Convert to/from JSON
        let sig_ugly_json = serde_json::to_string(sig.as_ref()).unwrap();
        assert_eq!(sig_ugly_json, "[105,84,233,38,185,184,175,143,55,216,79,212,43,29,15,146,139,95,229,188,18,70,116,233,140,25,57,92,243,223,57,147,12,187,83,11,101,138,220,227,60,189,109,246,130,57,48,75,201,115,100,123,154,129,71,32,166,44,101,168,180,157,98,6]");
        assert_eq!(serde_json::from_str::<Signature>(&sig_ugly_json).unwrap(), sig);

        let sig_json = serde_json::to_string(&sig).unwrap();
        assert_eq!(sig_json, format!("\"{}\"", sig_hex));
        assert_eq!(serde_json::from_str::<Signature>(&sig_json).unwrap(), sig);
    }

    #[test]
    fn test_ed25519_pubkey_serialize() {
        let pubkey_hex = "0851f51b47d5000f5ff005a7d138f5ed91ca9ebe62ade8a3283467e55858f14a";
        let pubkey_bytes = hex::decode(pubkey_hex).unwrap();
        let pubkey = PublicKey::from_slice(&pubkey_bytes).unwrap();

        // Convert to/from binary
        let pubkey_bin = bincode::serialize(&pubkey).unwrap();
        assert_eq!(hex::encode(&pubkey_bin), "20000000000000000851f51b47d5000f5ff005a7d138f5ed91ca9ebe62ade8a3283467e55858f14a");
        assert_eq!(bincode::deserialize::<PublicKey>(&pubkey_bin).unwrap(), pubkey);

        // Convert to/from JSON
        let pubkey_ugly_json = serde_json::to_string(pubkey.as_ref()).unwrap();
        assert_eq!(pubkey_ugly_json, "[8,81,245,27,71,213,0,15,95,240,5,167,209,56,245,237,145,202,158,190,98,173,232,163,40,52,103,229,88,88,241,74]");
        assert_eq!(serde_json::from_str::<PublicKey>(&pubkey_ugly_json).unwrap(), pubkey);

        let pubkey_json = serde_json::to_string(&pubkey).unwrap();
        assert_eq!(pubkey_json, format!("\"{}\"", pubkey_hex));
        assert_eq!(serde_json::from_str::<PublicKey>(&pubkey_json).unwrap(), pubkey);
    }

    #[test]
    fn test_ed25519_secretkey_serialize() {
        let key_hex = "3053020101300506032b6570042204207777777777777777777777777777777777777777777777777777777777777777a123032100c853ad0f0cd2b619aea92ceec4fd56a24d6499d584ce79257e45cfd8139b60a7";
        let (_, key) = gen_keypair_rand(&ring::test::rand::FixedByteRandom{ byte: 0x77u8 });
        let key_bytes = key.as_ref().to_vec();

        assert_eq!(hex::encode(&key_bytes), key_hex);

        // Convert to/from binary
        let key_bin = bincode::serialize(&key).unwrap();
        assert_eq!(hex::encode(&key_bin), "55000000000000003053020101300506032b6570042204207777777777777777777777777777777777777777777777777777777777777777a123032100c853ad0f0cd2b619aea92ceec4fd56a24d6499d584ce79257e45cfd8139b60a7");
        assert_eq!(bincode::deserialize::<SecretKey>(&key_bin).unwrap(), key);

        // Convert to/from JSON
        let key_ugly_json = serde_json::to_string(key.as_ref()).unwrap();
        assert_eq!(key_ugly_json, "[48,83,2,1,1,48,5,6,3,43,101,112,4,34,4,32,119,119,119,119,119,119,119,119,119,119,119,119,119,119,119,119,119,119,119,119,119,119,119,119,119,119,119,119,119,119,119,119,161,35,3,33,0,200,83,173,15,12,210,182,25,174,169,44,238,196,253,86,162,77,100,153,213,132,206,121,37,126,69,207,216,19,155,96,167]");
        assert_eq!(serde_json::from_str::<SecretKey>(&key_ugly_json).unwrap(), key);

        let key_json = serde_json::to_string(&key).unwrap();
        assert_eq!(key_json, format!("\"{}\"", key_hex));
        assert_eq!(serde_json::from_str::<SecretKey>(&key_json).unwrap(), key);
    }
    
    #[test]
    fn test_chacha20_poly1305_key_serialize() {
        let key_hex = "0851f51b47d5000f5ff005a7d138f5ed91ca9ebe62ade8a3283467e55858f14a";
        let key_bytes = hex::decode(key_hex).unwrap();
        let key = Key::from_slice(&key_bytes).unwrap();

        // Convert to/from binary
        let key_bin = bincode::serialize(&key).unwrap();
        assert_eq!(hex::encode(&key_bin), "20000000000000000851f51b47d5000f5ff005a7d138f5ed91ca9ebe62ade8a3283467e55858f14a");
        assert_eq!(bincode::deserialize::<Key>(&key_bin).unwrap(), key);

        // Convert to/from JSON
        let key_ugly_json = serde_json::to_string(key.as_ref()).unwrap();
        assert_eq!(key_ugly_json, "[8,81,245,27,71,213,0,15,95,240,5,167,209,56,245,237,145,202,158,190,98,173,232,163,40,52,103,229,88,88,241,74]");
        assert_eq!(serde_json::from_str::<Key>(&key_ugly_json).unwrap(), key);

        let key_json = serde_json::to_string(&key).unwrap();
        assert_eq!(key_json, format!("\"{}\"", key_hex));
        assert_eq!(serde_json::from_str::<Key>(&key_json).unwrap(), key);
    }
    
    #[test]
    fn test_chacha20_poly1305_nonce_serialize() {
        let nonce_hex = "0851f51b47d5000f5ff005a7";
        let nonce_bytes = hex::decode(nonce_hex).unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes).unwrap();

        // Convert to/from binary
        let nonce_bin = bincode::serialize(&nonce).unwrap();
        assert_eq!(hex::encode(&nonce_bin), "0c000000000000000851f51b47d5000f5ff005a7");
        assert_eq!(bincode::deserialize::<Nonce>(&nonce_bin).unwrap(), nonce);

        // Convert to/from JSON
        let nonce_ugly_json = serde_json::to_string(nonce.as_ref()).unwrap();
        assert_eq!(nonce_ugly_json, "[8,81,245,27,71,213,0,15,95,240,5,167]");
        assert_eq!(serde_json::from_str::<Nonce>(&nonce_ugly_json).unwrap(), nonce);

        let nonce_json = serde_json::to_string(&nonce).unwrap();
        assert_eq!(nonce_json, format!("\"{}\"", nonce_hex));
        assert_eq!(serde_json::from_str::<Nonce>(&nonce_json).unwrap(), nonce);
    }
    
    #[test]
    fn test_pbkdf2_salt_serialize() {
        let salt_hex = "0851f51b47d5000f5ff005a7d138f5ed91ca9ebe62ade8a3283467e55858f14a";
        let salt_bytes = hex::decode(salt_hex).unwrap();
        let salt = Salt::from_slice(&salt_bytes).unwrap();

        // Convert to/from binary
        let salt_bin = bincode::serialize(&salt).unwrap();
        assert_eq!(hex::encode(&salt_bin), "20000000000000000851f51b47d5000f5ff005a7d138f5ed91ca9ebe62ade8a3283467e55858f14a");
        assert_eq!(bincode::deserialize::<Salt>(&salt_bin).unwrap(), salt);

        // Convert to/from JSON
        let salt_ugly_json = serde_json::to_string(salt.as_ref()).unwrap();
        assert_eq!(salt_ugly_json, "[8,81,245,27,71,213,0,15,95,240,5,167,209,56,245,237,145,202,158,190,98,173,232,163,40,52,103,229,88,88,241,74]");
        assert_eq!(serde_json::from_str::<Salt>(&salt_ugly_json).unwrap(), salt);

        let salt_json = serde_json::to_string(&salt).unwrap();
        assert_eq!(salt_json, format!("\"{}\"", salt_hex));
        assert_eq!(serde_json::from_str::<Salt>(&salt_json).unwrap(), salt);
    }
}
