//! Cryptographic primitives, persistent `AirPlayIdentity`, and `PairingStore` for CarPlay.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use aes::cipher::{KeyIvInit, StreamCipher};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("ChaCha20-Poly1305 authentication failed")]
    AeadAuthFailed,
    #[error("invalid key or nonce length")]
    InvalidLength,
    #[error("Ed25519 signature verification failed")]
    SignatureInvalid,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Long-term Ed25519 accessory identity advertised in Bonjour (`pi`, `pk`) and used in `/pair-setup` & `/pair-verify`.
#[derive(Clone)]
pub struct AirPlayIdentity {
    pub pairing_id: String,
    signing_key: SigningKey,
}

#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    pairing_id: String,
    secret_hex: String,
}

impl AirPlayIdentity {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self {
            pairing_id: Uuid::new_v4().to_string().to_uppercase(),
            signing_key,
        }
    }

    pub fn load_or_create(path: impl AsRef<Path>) -> Result<Self, CryptoError> {
        let path = path.as_ref();
        if let Ok(text) = fs::read_to_string(path) {
            if let Ok(stored) = serde_json::from_str::<StoredIdentity>(&text) {
                if let Ok(bytes) = hex::decode(&stored.secret_hex) {
                    if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                        return Ok(Self {
                            pairing_id: stored.pairing_id,
                            signing_key: SigningKey::from_bytes(&arr),
                        });
                    }
                }
            }
        }
        let generated = Self::generate();
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let stored = StoredIdentity {
            pairing_id: generated.pairing_id.clone(),
            secret_hex: hex::encode(generated.signing_key.to_bytes()),
        };
        if let Ok(json) = serde_json::to_string_pretty(&stored) {
            let _ = fs::write(path, json);
        }
        Ok(generated)
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key_bytes())
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }
}

/// Thread-safe store for paired iPhone long-term Ed25519 public keys (persisted optionally to JSON).
#[derive(Clone, Default)]
pub struct PairingStore {
    peers: Arc<RwLock<HashMap<String, [u8; 32]>>>,
    backing_file: Option<PathBuf>,
}

impl PairingStore {
    pub fn in_memory() -> Self {
        Self::default()
    }

    pub fn persistent(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let mut initial = HashMap::new();
        if let Ok(text) = fs::read_to_string(&path) {
            if let Ok(raw) = serde_json::from_str::<HashMap<String, String>>(&text) {
                for (id, hex_pk) in raw {
                    if let Ok(bytes) = hex::decode(hex_pk) {
                        if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                            initial.insert(id, arr);
                        }
                    }
                }
            }
        }
        Self {
            peers: Arc::new(RwLock::new(initial)),
            backing_file: Some(path),
        }
    }

    pub fn save(&self, controller_id: String, ltpk: [u8; 32]) {
        let mut guard = self.peers.write().unwrap();
        guard.insert(controller_id, ltpk);
        if let Some(path) = &self.backing_file {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let hex_map: HashMap<&String, String> =
                guard.iter().map(|(k, v)| (k, hex::encode(v))).collect();
            if let Ok(json) = serde_json::to_string_pretty(&hex_map) {
                let _ = fs::write(path, json);
            }
        }
    }

    pub fn get(&self, controller_id: &str) -> Option<[u8; 32]> {
        self.peers.read().unwrap().get(controller_id).copied()
    }
}

pub fn x25519_generate() -> ([u8; 32], [u8; 32]) {
    let secret = X25519Secret::random_from_rng(OsRng);
    let public = X25519Public::from(&secret);
    (secret.to_bytes(), public.to_bytes())
}

pub fn x25519_shared(private_key: &[u8; 32], peer_public: &[u8]) -> Result<[u8; 32], CryptoError> {
    let peer_arr: [u8; 32] = peer_public
        .try_into()
        .map_err(|_| CryptoError::InvalidLength)?;
    let secret = X25519Secret::from(*private_key);
    let peer = X25519Public::from(peer_arr);
    Ok(secret.diffie_hellman(&peer).to_bytes())
}

pub fn ed25519_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(pk_arr) = <[u8; 32]>::try_from(public_key) else {
        return false;
    };
    let Ok(sig_arr) = <[u8; 64]>::try_from(signature) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk_arr) else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(message, &sig).is_ok()
}

pub fn hkdf_sha512(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha512>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("32 bytes is valid HKDF-SHA512 output length");
    okm
}

/// Builds a 12-byte HomeKit/AirPlay nonce with 4 zero bytes followed by an 8-byte ASCII label (`"PS-Msg05"`, `"PV-Msg02"`, etc.).
pub fn nonce_label(label: &[u8; 8]) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..12].copy_from_slice(label);
    n
}

/// Builds a 12-byte stream nonce with 4 zero bytes followed by an 8-byte little-endian frame/packet counter.
pub fn nonce64(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..12].copy_from_slice(&counter.to_le_bytes());
    n
}

pub fn chacha_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AeadAuthFailed)
}

pub fn chacha_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext_and_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext_and_tag,
                aad,
            },
        )
        .map_err(|_| CryptoError::AeadAuthFailed)
}

pub fn aes128_ctr(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    let mut cipher = Aes128Ctr::new(key.into(), iv.into());
    cipher.apply_keystream(&mut out);
    out
}

pub fn sha1_concat(parts: &[&[u8]]) -> [u8; 20] {
    let mut h = Sha1::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn sha256_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn sha512_concat(parts: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}
