//! Remote HTTP/HTTPS MFi & BAA signing client (`/mfi/certificate`, `/mfi/sign`, `/mfi/reset`).

use std::sync::Mutex;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{BaaCertificates, MfiAuthenticator, MfiCertificateType, MfiError};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertResponse {
    certificate: Option<String>,
    leaf_certificate: Option<String>,
    intermediate_certificate: Option<String>,
    protocol_major: Option<u8>,
    certificate_type: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SignRequest<'a> {
    challenge: &'a str,
    request_id: String,
}

#[derive(Debug, Deserialize)]
struct SignResponse {
    signature: String,
}

/// Remote MFi / BAA authentication client compatible with DiPlay's remote signing server protocol.
pub struct RemoteMfiClient {
    base_url: String,
    bearer_token: Option<String>,
    agent: ureq::Agent,
    cert_type: MfiCertificateType,
    cached_mfi_cert: Mutex<Option<Vec<u8>>>,
    cached_baa_certs: Mutex<Option<BaaCertificates>>,
    cached_major: Mutex<Option<u8>>,
}

impl RemoteMfiClient {
    pub fn new(
        base_url: impl Into<String>,
        bearer_token: Option<String>,
        cert_type: MfiCertificateType,
    ) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(5))
            .timeout_read(Duration::from_secs(10))
            .timeout_write(Duration::from_secs(10))
            .build();
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            bearer_token,
            agent,
            cert_type,
            cached_mfi_cert: Mutex::new(None),
            cached_baa_certs: Mutex::new(None),
            cached_major: Mutex::new(None),
        }
    }

    fn apply_auth(&self, req: ureq::Request) -> ureq::Request {
        if let Some(tok) = &self.bearer_token {
            req.set("Authorization", &format!("Bearer {tok}"))
        } else {
            req
        }
    }

    fn fetch_cert_bundle(&self) -> Result<CertResponse, MfiError> {
        let url = format!("{}/mfi/certificate", self.base_url);
        let resp = self
            .apply_auth(self.agent.get(&url))
            .call()
            .map_err(|e| MfiError::Transport(format!("GET {url}: {e}")))?;
        resp.into_json::<CertResponse>()
            .map_err(|e| MfiError::Transport(format!("invalid /mfi/certificate JSON: {e}")))
    }
}

impl MfiAuthenticator for RemoteMfiClient {
    fn protocol_major(&self) -> Result<u8, MfiError> {
        if let Some(m) = *self.cached_major.lock().unwrap() {
            return Ok(m);
        }
        let bundle = self.fetch_cert_bundle()?;
        let major = bundle.protocol_major.unwrap_or(3);
        *self.cached_major.lock().unwrap() = Some(major);
        Ok(major)
    }

    fn certificate_type(&self) -> MfiCertificateType {
        self.cert_type
    }

    fn read_certificate(&self) -> Result<Vec<u8>, MfiError> {
        if let Some(cert) = self.cached_mfi_cert.lock().unwrap().clone() {
            return Ok(cert);
        }
        let bundle = self.fetch_cert_bundle()?;
        if let Some(m) = bundle.protocol_major {
            *self.cached_major.lock().unwrap() = Some(m);
        }
        let b64 = bundle
            .certificate
            .or(bundle.leaf_certificate)
            .ok_or_else(|| MfiError::Transport("missing certificate field".into()))?;
        let raw = B64
            .decode(b64.trim())
            .map_err(|e| MfiError::Transport(format!("base64 decode cert: {e}")))?;
        *self.cached_mfi_cert.lock().unwrap() = Some(raw.clone());
        Ok(raw)
    }

    fn baa_certificates(&self) -> Result<BaaCertificates, MfiError> {
        if let Some(certs) = self.cached_baa_certs.lock().unwrap().clone() {
            return Ok(certs);
        }
        let bundle = self.fetch_cert_bundle()?;
        let _ = bundle.certificate_type;
        let leaf_b64 = bundle
            .leaf_certificate
            .or(bundle.certificate)
            .ok_or_else(|| MfiError::Transport("missing BAA leafCertificate".into()))?;
        let inter_b64 = bundle
            .intermediate_certificate
            .ok_or_else(|| MfiError::Transport("missing BAA intermediateCertificate".into()))?;
        let certs = BaaCertificates {
            leaf: B64
                .decode(leaf_b64.trim())
                .map_err(|e| MfiError::Transport(format!("decode leaf cert: {e}")))?,
            intermediate: B64
                .decode(inter_b64.trim())
                .map_err(|e| MfiError::Transport(format!("decode intermediate cert: {e}")))?,
        };
        *self.cached_baa_certs.lock().unwrap() = Some(certs.clone());
        Ok(certs)
    }

    fn sign_challenge(&self, challenge: &[u8]) -> Result<Vec<u8>, MfiError> {
        let url = format!("{}/mfi/sign", self.base_url);
        let encoded = B64.encode(challenge);
        let payload = SignRequest {
            challenge: &encoded,
            request_id: Uuid::new_v4().to_string(),
        };
        let resp = self
            .apply_auth(self.agent.post(&url))
            .send_json(&payload)
            .map_err(|e| MfiError::Transport(format!("POST {url}: {e}")))?;
        let parsed: SignResponse = resp
            .into_json()
            .map_err(|e| MfiError::Transport(format!("invalid /mfi/sign JSON: {e}")))?;
        B64.decode(parsed.signature.trim())
            .map_err(|e| MfiError::Transport(format!("base64 decode signature: {e}")))
    }

    fn reset(&self) -> Result<(), MfiError> {
        let url = format!("{}/mfi/reset", self.base_url);
        let _ = self.apply_auth(self.agent.post(&url)).call();
        Ok(())
    }
}
