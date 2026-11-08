//! `carplay-mfi`: Apple MFi Coprocessor authentication providers (I2C hardware IC, CH341 USB-I2C,
//! Remote HTTP/BAA signing server, and Local P-256 ECDSA software provider).

pub mod i2c;
pub mod local;
pub mod remote;

use thiserror::Error;

pub use i2c::{I2cTransport, MfiI2cClient, MFI_I2C_ADDR_HIGH, MFI_I2C_ADDR_LOW};
pub use local::LocalP256MfiClient;
pub use remote::RemoteMfiClient;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfiCertificateType {
    /// Classic MFi Authentication Coprocessor (2.0C / 3.0) single PKCS#7/X.509 certificate blob.
    Mfi,
    /// Apple Basic Attestation / DeviceCheck (`baIC` OPACK leaf + intermediate chain).
    Baa,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaaCertificates {
    pub leaf: Vec<u8>,
    pub intermediate: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum MfiError {
    #[error("MFi transport error: {0}")]
    Transport(String),
    #[error("invalid MFi certificate length: {0}")]
    InvalidCertificateLength(usize),
    #[error("invalid MFi challenge length: {0}")]
    InvalidChallengeLength(usize),
    #[error("MFi coprocessor reported status 0x{status:02x}, error 0x{error_code:02x}")]
    CoprocessorError { status: u8, error_code: u8 },
    #[error("invalid local MFi key/certificate: {0}")]
    InvalidKey(String),
    #[error("unsupported MFi operation: {0}")]
    UnsupportedOperation(&'static str),
}

/// Unified trait used by both `carplay-iap2` (`0xAA00..0xAA03`) and `carplay-airplay` (`/auth-setup` MFiSAP).
pub trait MfiAuthenticator: Send + Sync {
    fn protocol_major(&self) -> Result<u8, MfiError>;
    fn certificate_type(&self) -> MfiCertificateType;
    fn read_certificate(&self) -> Result<Vec<u8>, MfiError>;

    fn baa_certificates(&self) -> Result<BaaCertificates, MfiError> {
        Err(MfiError::UnsupportedOperation(
            "BAA certificates not available on this MFi provider",
        ))
    }

    fn sign_challenge(&self, challenge: &[u8]) -> Result<Vec<u8>, MfiError>;

    fn reset(&self) -> Result<(), MfiError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use p256::ecdsa::Signature;

    struct MockMfiChip {
        cert: Vec<u8>,
        last_challenge: Vec<u8>,
        status: u8,
    }

    impl I2cTransport for MockMfiChip {
        fn read_register(
            &mut self,
            _slave_addr: u8,
            reg: u8,
            buf: &mut [u8],
        ) -> Result<(), MfiError> {
            match reg {
                0x02 => buf[0] = 3,
                0x10 => buf[0] = self.status,
                0x11 => buf.copy_from_slice(&64u16.to_be_bytes()),
                0x12 => {
                    for (i, b) in buf.iter_mut().enumerate() {
                        *b = self
                            .last_challenge
                            .get(i % self.last_challenge.len())
                            .copied()
                            .unwrap_or(0xAA)
                            ^ 0x5A;
                    }
                }
                0x30 => buf.copy_from_slice(&(self.cert.len() as u16).to_be_bytes()),
                r if r >= 0x31 => {
                    let page = (r - 0x31) as usize;
                    let start = page * 128;
                    buf.copy_from_slice(&self.cert[start..start + buf.len()]);
                }
                _ => buf.fill(0),
            }
            Ok(())
        }

        fn write_register(
            &mut self,
            _slave_addr: u8,
            reg: u8,
            data: &[u8],
        ) -> Result<(), MfiError> {
            match reg {
                0x21 => self.last_challenge = data.to_vec(),
                0x10 if data == [0x01] => self.status = 0x10, // Ready
                _ => {}
            }
            Ok(())
        }
    }

    #[test]
    fn i2c_paged_certificate_and_challenge_signing() {
        let cert: Vec<u8> = (0..300).map(|i| (i & 0xFF) as u8).collect();
        let mock = MockMfiChip {
            cert: cert.clone(),
            last_challenge: Vec::new(),
            status: 0x00,
        };
        let client = MfiI2cClient::new(mock, MFI_I2C_ADDR_LOW);
        assert_eq!(client.protocol_major().unwrap(), 3);
        assert_eq!(client.read_certificate().unwrap(), cert);
        let sig = client.sign_challenge(&[0x11; 32]).unwrap();
        assert_eq!(sig.len(), 64);
        assert_eq!(sig[0], 0x11 ^ 0x5A);
    }

    #[test]
    fn local_p256_signs_valid_raw_ecdsa_digest() {
        let local = LocalP256MfiClient::ephemeral_for_testing();
        let digest = [0x42u8; 32];
        let raw_sig = local.sign_challenge(&digest).unwrap();
        assert_eq!(raw_sig.len(), 64);
        let sig = Signature::from_slice(&raw_sig).unwrap();
        local
            .verifying_key()
            .verify_prehash(&digest, &sig)
            .expect("ECDSA prehash signature must verify");
    }
}
