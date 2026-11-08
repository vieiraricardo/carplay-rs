//! Local software P-256 ECDSA MFi v3 / BAA authenticator (matching `LocalMfiAuthenticationClient.kt`).

use std::fs;
use std::path::Path;

use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::DecodePrivateKey;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::{BaaCertificates, MfiAuthenticator, MfiCertificateType, MfiError};

/// Software P-256 ECDSA authenticator loading `identity.pk8` + `certificate.p7b` (or ephemeral test keys).
pub struct LocalP256MfiClient {
    signing_key: SigningKey,
    certificate: Vec<u8>,
    intermediate: Option<Vec<u8>>,
    cert_type: MfiCertificateType,
}

impl LocalP256MfiClient {
    pub fn from_pkcs8_der(
        pkcs8_der: &[u8],
        certificate_der: Vec<u8>,
        intermediate_der: Option<Vec<u8>>,
    ) -> Result<Self, MfiError> {
        let signing_key = SigningKey::from_pkcs8_der(pkcs8_der)
            .or_else(|_| {
                std::str::from_utf8(pkcs8_der)
                    .map_err(|_| p256::pkcs8::Error::KeyMalformed)
                    .and_then(SigningKey::from_pkcs8_pem)
            })
            .map_err(|e| MfiError::InvalidKey(format!("PKCS#8 P-256 decode failed: {e}")))?;
        let cert_type = if intermediate_der.is_some() {
            MfiCertificateType::Baa
        } else {
            MfiCertificateType::Mfi
        };
        Ok(Self {
            signing_key,
            certificate: certificate_der,
            intermediate: intermediate_der,
            cert_type,
        })
    }

    pub fn load_from_dir(dir: impl AsRef<Path>) -> Result<Self, MfiError> {
        let dir = dir.as_ref();
        let pk8 = fs::read(dir.join("identity.pk8"))
            .map_err(|e| MfiError::InvalidKey(format!("read identity.pk8: {e}")))?;
        let cert = fs::read(dir.join("certificate.p7b"))
            .or_else(|_| fs::read(dir.join("certificate.der")))
            .map_err(|e| MfiError::InvalidKey(format!("read certificate: {e}")))?;
        let inter = fs::read(dir.join("intermediate.der")).ok();
        Self::from_pkcs8_der(&pk8, cert, inter)
    }

    /// Generates an ephemeral P-256 identity with a synthetic DER certificate blob for local desktop simulation & tests.
    pub fn ephemeral_for_testing() -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);
        let pub_sec1 = verifying_key.to_encoded_point(false);
        // Embed uncompressed P-256 public key inside a synthetic DER-like test certificate container
        let mut synthetic_cert = b"CARPLAY-RS-TEST-MFI-CERT:".to_vec();
        synthetic_cert.extend_from_slice(pub_sec1.as_bytes());
        Self {
            signing_key,
            certificate: synthetic_cert,
            intermediate: None,
            cert_type: MfiCertificateType::Mfi,
        }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        *self.signing_key.verifying_key()
    }
}

impl MfiAuthenticator for LocalP256MfiClient {
    fn protocol_major(&self) -> Result<u8, MfiError> {
        Ok(3)
    }

    fn certificate_type(&self) -> MfiCertificateType {
        self.cert_type
    }

    fn read_certificate(&self) -> Result<Vec<u8>, MfiError> {
        Ok(self.certificate.clone())
    }

    fn baa_certificates(&self) -> Result<BaaCertificates, MfiError> {
        let intermediate = self
            .intermediate
            .clone()
            .ok_or(MfiError::UnsupportedOperation("not configured as BAA"))?;
        Ok(BaaCertificates {
            leaf: self.certificate.clone(),
            intermediate,
        })
    }

    fn sign_challenge(&self, challenge: &[u8]) -> Result<Vec<u8>, MfiError> {
        let digest: [u8; 32] = match self.cert_type {
            MfiCertificateType::Mfi => {
                // MFi v3 passes a pre-hashed 32-byte SHA-256 digest (do not hash twice!)
                if challenge.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(challenge);
                    arr
                } else {
                    Sha256::digest(challenge).into()
                }
            }
            MfiCertificateType::Baa => {
                // BAA passes raw `ownPub || peerPub` (64 bytes) and expects ECDSA-SHA256
                Sha256::digest(challenge).into()
            }
        };

        let sig: Signature = self
            .signing_key
            .sign_prehash(&digest)
            .map_err(|e| MfiError::InvalidKey(format!("P-256 sign failed: {e}")))?;

        // MFi v3 uses raw 64-byte IEEE P1363 `r || s`; BAA uses ASN.1 DER ECDSA
        match self.cert_type {
            MfiCertificateType::Mfi => Ok(sig.to_bytes().to_vec()),
            MfiCertificateType::Baa => Ok(sig.to_der().as_bytes().to_vec()),
        }
    }
}
