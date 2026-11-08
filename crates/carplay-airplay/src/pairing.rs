//! CarPlay `/pair-setup`, `/pair-verify`, `/auth-setup` (MFiSAP), and `ControlCipher` stream encryption.

use carplay_mfi::{MfiAuthenticator, MfiCertificateType};

use crate::crypto::{
    aes128_ctr, chacha_open, chacha_seal, ed25519_verify, hkdf_sha512, nonce64, nonce_label,
    sha1_concat, sha256_concat, x25519_generate, x25519_shared, AirPlayIdentity, CryptoError,
    PairingStore,
};
use crate::srp6a::Srp6aServerSession;
use crate::tlv8::{
    self, TLV_ENCRYPTED_DATA, TLV_ERROR, TLV_IDENTIFIER, TLV_PROOF, TLV_PUBLIC_KEY, TLV_SALT,
    TLV_SIGNATURE, TLV_STATE,
};

const SETUP_USERNAME: &str = "Pair-Setup";
const SETUP_CODE: &str = "3939";
const ERROR_AUTHENTICATION: u8 = 2;

/// CarPlay `/pair-setup` responder (unauthenticated SRP-6a PIN `"3939"` + Ed25519 long-term key exchange).
pub struct PairSetup {
    identity: AirPlayIdentity,
    pairings: PairingStore,
    srp: Option<Srp6aServerSession>,
    session_key: Option<[u8; 64]>,
    pub complete: bool,
}

impl PairSetup {
    pub fn new(identity: AirPlayIdentity, pairings: PairingStore) -> Self {
        Self {
            identity,
            pairings,
            srp: None,
            session_key: None,
            complete: false,
        }
    }

    pub fn handle(&mut self, body: &[u8]) -> Vec<u8> {
        let Ok(tlv) = tlv8::decode(body) else {
            return Self::err_tlv(0);
        };
        let state = tlv.get(&TLV_STATE).and_then(|b| b.first()).copied().unwrap_or(0);
        match state {
            1 => self.m2(),
            3 => self.m4(&tlv).unwrap_or_else(|| Self::err_tlv(4)),
            5 => self.m6(&tlv).unwrap_or_else(|| Self::err_tlv(6)),
            s => Self::err_tlv(s),
        }
    }

    fn m2(&mut self) -> Vec<u8> {
        let session = Srp6aServerSession::start(SETUP_USERNAME, SETUP_CODE);
        let resp = tlv8::encode(&[
            (TLV_STATE, &[2]),
            (TLV_PUBLIC_KEY, &session.public_key_b),
            (TLV_SALT, &session.salt),
        ]);
        self.srp = Some(session);
        resp
    }

    fn m4(&mut self, tlv: &indexmap::IndexMap<u8, Vec<u8>>) -> Option<Vec<u8>> {
        let pub_a = tlv.get(&TLV_PUBLIC_KEY)?;
        let proof = tlv.get(&TLV_PROOF)?;
        let res = self.srp.as_ref()?.verify(pub_a, proof)?;
        self.session_key = Some(res.session_key);
        Some(tlv8::encode(&[
            (TLV_STATE, &[4]),
            (TLV_PROOF, &res.server_proof),
        ]))
    }

    fn m6(&mut self, tlv: &indexmap::IndexMap<u8, Vec<u8>>) -> Option<Vec<u8>> {
        let encrypted = tlv.get(&TLV_ENCRYPTED_DATA)?;
        let key = self.session_key?;
        let enc_key = hkdf_sha512(
            &key,
            b"Pair-Setup-Encrypt-Salt",
            b"Pair-Setup-Encrypt-Info",
        );
        let plain = chacha_open(&enc_key, &nonce_label(b"PS-Msg05"), encrypted, &[]).ok()?;
        let sub = tlv8::decode(&plain).ok()?;

        let controller_id = sub.get(&TLV_IDENTIFIER)?;
        let controller_ltpk = sub.get(&TLV_PUBLIC_KEY)?;
        let controller_sig = sub.get(&TLV_SIGNATURE)?;

        let controller_sign_key = hkdf_sha512(
            &key,
            b"Pair-Setup-Controller-Sign-Salt",
            b"Pair-Setup-Controller-Sign-Info",
        );
        let mut controller_sign_data = Vec::new();
        controller_sign_data.extend_from_slice(&controller_sign_key);
        controller_sign_data.extend_from_slice(controller_id);
        controller_sign_data.extend_from_slice(controller_ltpk);
        if !ed25519_verify(controller_ltpk, &controller_sign_data, controller_sig) {
            return None;
        }

        let ltpk_arr: [u8; 32] = controller_ltpk.as_slice().try_into().ok()?;
        let id_str = String::from_utf8_lossy(controller_id).into_owned();
        self.pairings.save(id_str, ltpk_arr);

        let accessory_id = self.identity.pairing_id.as_bytes();
        let accessory_pk = self.identity.public_key_bytes();
        let accessory_sign_key = hkdf_sha512(
            &key,
            b"Pair-Setup-Accessory-Sign-Salt",
            b"Pair-Setup-Accessory-Sign-Info",
        );
        let mut accessory_sign_data = Vec::new();
        accessory_sign_data.extend_from_slice(&accessory_sign_key);
        accessory_sign_data.extend_from_slice(accessory_id);
        accessory_sign_data.extend_from_slice(&accessory_pk);
        let accessory_sig = self.identity.sign(&accessory_sign_data);

        let sub_resp = tlv8::encode(&[
            (TLV_IDENTIFIER, accessory_id),
            (TLV_PUBLIC_KEY, &accessory_pk),
            (TLV_SIGNATURE, &accessory_sig),
        ]);
        let sealed = chacha_seal(&enc_key, &nonce_label(b"PS-Msg06"), &sub_resp, &[]).ok()?;
        self.complete = true;
        Some(tlv8::encode(&[
            (TLV_STATE, &[6]),
            (TLV_ENCRYPTED_DATA, &sealed),
        ]))
    }

    fn err_tlv(state: u8) -> Vec<u8> {
        tlv8::encode(&[(TLV_STATE, &[state]), (TLV_ERROR, &[ERROR_AUTHENTICATION])])
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ControlKeys {
    pub read_key: [u8; 32],
    pub write_key: [u8; 32],
}

/// CarPlay `/pair-verify` responder (ephemeral X25519 + Ed25519 verification -> `ControlCipher` keys).
pub struct PairVerify {
    identity: AirPlayIdentity,
    pairings: PairingStore,
    ephemeral_pub: Option<[u8; 32]>,
    client_ephemeral_pub: Option<[u8; 32]>,
    shared_secret: Option<[u8; 32]>,
    encryption_key: Option<[u8; 32]>,
    control_keys: Option<ControlKeys>,
    verified_controller: Option<String>,
}

impl PairVerify {
    pub fn new(identity: AirPlayIdentity, pairings: PairingStore) -> Self {
        Self {
            identity,
            pairings,
            ephemeral_pub: None,
            client_ephemeral_pub: None,
            shared_secret: None,
            encryption_key: None,
            control_keys: None,
            verified_controller: None,
        }
    }

    pub fn shared_secret(&self) -> Option<[u8; 32]> {
        self.shared_secret
    }

    pub fn control_keys(&self) -> Option<ControlKeys> {
        self.control_keys
    }

    pub fn verified_controller(&self) -> Option<&str> {
        self.verified_controller.as_deref()
    }

    pub fn handle(&mut self, body: &[u8]) -> Vec<u8> {
        let Ok(tlv) = tlv8::decode(body) else {
            return Self::err_tlv(0);
        };
        let state = tlv.get(&TLV_STATE).and_then(|b| b.first()).copied().unwrap_or(0);
        match state {
            1 => self.m2(&tlv).unwrap_or_else(|| Self::err_tlv(2)),
            3 => self.m4(&tlv).unwrap_or_else(|| Self::err_tlv(4)),
            s => Self::err_tlv(s),
        }
    }

    fn m2(&mut self, tlv: &indexmap::IndexMap<u8, Vec<u8>>) -> Option<Vec<u8>> {
        let client_pub_raw = tlv.get(&TLV_PUBLIC_KEY)?;
        let client_pub: [u8; 32] = client_pub_raw.as_slice().try_into().ok()?;
        let (own_priv, own_pub) = x25519_generate();
        let shared = x25519_shared(&own_priv, &client_pub).ok()?;
        let enc_key = hkdf_sha512(
            &shared,
            b"Pair-Verify-Encrypt-Salt",
            b"Pair-Verify-Encrypt-Info",
        );

        let accessory_id = self.identity.pairing_id.as_bytes();
        let mut sign_data = Vec::with_capacity(32 + accessory_id.len() + 32);
        sign_data.extend_from_slice(&own_pub);
        sign_data.extend_from_slice(accessory_id);
        sign_data.extend_from_slice(&client_pub);
        let sig = self.identity.sign(&sign_data);

        let sub = tlv8::encode(&[(TLV_IDENTIFIER, accessory_id), (TLV_SIGNATURE, &sig)]);
        let sealed = chacha_seal(&enc_key, &nonce_label(b"PV-Msg02"), &sub, &[]).ok()?;

        self.ephemeral_pub = Some(own_pub);
        self.client_ephemeral_pub = Some(client_pub);
        self.shared_secret = Some(shared);
        self.encryption_key = Some(enc_key);

        Some(tlv8::encode(&[
            (TLV_STATE, &[2]),
            (TLV_PUBLIC_KEY, &own_pub),
            (TLV_ENCRYPTED_DATA, &sealed),
        ]))
    }

    fn m4(&mut self, tlv: &indexmap::IndexMap<u8, Vec<u8>>) -> Option<Vec<u8>> {
        let encrypted = tlv.get(&TLV_ENCRYPTED_DATA)?;
        let enc_key = self.encryption_key?;
        let shared = self.shared_secret?;
        let own_pub = self.ephemeral_pub?;
        let client_pub = self.client_ephemeral_pub?;

        let plain = chacha_open(&enc_key, &nonce_label(b"PV-Msg03"), encrypted, &[]).ok()?;
        let sub = tlv8::decode(&plain).ok()?;
        let controller_id = sub.get(&TLV_IDENTIFIER)?;
        let controller_sig = sub.get(&TLV_SIGNATURE)?;
        let id_str = String::from_utf8_lossy(controller_id).into_owned();
        let controller_ltpk = self.pairings.get(&id_str)?;

        let mut sig_data = Vec::with_capacity(32 + controller_id.len() + 32);
        sig_data.extend_from_slice(&client_pub);
        sig_data.extend_from_slice(controller_id);
        sig_data.extend_from_slice(&own_pub);
        if !ed25519_verify(&controller_ltpk, &sig_data, controller_sig) {
            return None;
        }

        // Accessory reads what Controller writes ("Control-Write-Encryption-Key") and vice versa
        let read_key = hkdf_sha512(&shared, b"Control-Salt", b"Control-Write-Encryption-Key");
        let write_key = hkdf_sha512(&shared, b"Control-Salt", b"Control-Read-Encryption-Key");
        self.control_keys = Some(ControlKeys {
            read_key,
            write_key,
        });
        self.verified_controller = Some(id_str);
        Some(tlv8::encode(&[(TLV_STATE, &[4])]))
    }

    fn err_tlv(state: u8) -> Vec<u8> {
        tlv8::encode(&[(TLV_STATE, &[state]), (TLV_ERROR, &[ERROR_AUTHENTICATION])])
    }
}

/// CarPlay `/auth-setup` MFiSAP responder proving MFi / BAA licensing over the encrypted control channel.
pub struct MfiSapAuthSetup;

impl MfiSapAuthSetup {
    pub fn handle(body: &[u8], mfi: &dyn MfiAuthenticator) -> Option<Vec<u8>> {
        if body.len() != 33 || body[0] != 0x01 {
            return None;
        }
        let peer_pub = &body[1..33];
        let (own_priv, own_pub) = x25519_generate();
        let shared = x25519_shared(&own_priv, peer_pub).ok()?;
        if shared.iter().all(|&b| b == 0) {
            return None;
        }

        let key_full = sha1_concat(&[b"AES-KEY", &shared]);
        let iv_full = sha1_concat(&[b"AES-IV", &shared]);
        let mut aes_key = [0u8; 16];
        let mut aes_iv = [0u8; 16];
        aes_key.copy_from_slice(&key_full[..16]);
        aes_iv.copy_from_slice(&iv_full[..16]);

        match mfi.certificate_type() {
            MfiCertificateType::Mfi => {
                let cert = mfi.read_certificate().ok()?;
                let major = mfi.protocol_major().unwrap_or(3);
                let digest: Vec<u8> = if major == 2 {
                    sha1_concat(&[&own_pub, peer_pub]).to_vec()
                } else {
                    sha256_concat(&[&own_pub, peer_pub]).to_vec()
                };
                let sig = mfi.sign_challenge(&digest).ok()?;
                let enc_sig = aes128_ctr(&aes_key, &aes_iv, &sig);

                let mut out = Vec::with_capacity(32 + 4 + cert.len() + 4 + enc_sig.len());
                out.extend_from_slice(&own_pub);
                out.extend_from_slice(&(cert.len() as u32).to_be_bytes());
                out.extend_from_slice(&cert);
                out.extend_from_slice(&(enc_sig.len() as u32).to_be_bytes());
                out.extend_from_slice(&enc_sig);
                Some(out)
            }
            MfiCertificateType::Baa => {
                let certs = mfi.baa_certificates().ok()?;
                let mut challenge = Vec::with_capacity(64);
                challenge.extend_from_slice(&own_pub);
                challenge.extend_from_slice(peer_pub);
                let sig = mfi.sign_challenge(&challenge).ok()?;
                let enc_sig = aes128_ctr(&aes_key, &aes_iv, &sig);
                let baic = encode_baa_opack(&certs.intermediate);

                let mut out =
                    Vec::with_capacity(32 + 4 + certs.leaf.len() + 4 + enc_sig.len() + 4 + baic.len());
                out.extend_from_slice(&own_pub);
                out.extend_from_slice(&(certs.leaf.len() as u32).to_be_bytes());
                out.extend_from_slice(&certs.leaf);
                out.extend_from_slice(&(enc_sig.len() as u32).to_be_bytes());
                out.extend_from_slice(&enc_sig);
                out.extend_from_slice(&(baic.len() as u32).to_be_bytes());
                out.extend_from_slice(&baic);
                Some(out)
            }
        }
    }
}

fn encode_baa_opack(intermediate: &[u8]) -> Vec<u8> {
    let n = intermediate.len();
    let mut out = vec![0xE1, 0x44, b'b', b'a', b'I', b'C'];
    if n <= 0x20 {
        out.push(0x70 + (n as u8));
    } else if n <= 0xFF {
        out.push(0x91);
        out.push(n as u8);
    } else if n <= 0xFFFF {
        out.push(0x92);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else {
        out.push(0x93);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    }
    out.extend_from_slice(intermediate);
    out
}

/// Framed ChaCha20-Poly1305 stream cipher (`[u16le len][ciphertext][16B tag]`, AAD = 2-byte length header).
pub struct ControlCipher {
    read_key: [u8; 32],
    write_key: [u8; 32],
    read_counter: u64,
    write_counter: u64,
}

pub struct DecryptedChunk {
    pub plaintext: Vec<u8>,
    pub rest: Vec<u8>,
}

impl ControlCipher {
    const MAX_BLOCK: usize = 0x4000;
    const TAG_LEN: usize = 16;

    pub fn new(read_key: [u8; 32], write_key: [u8; 32]) -> Self {
        Self {
            read_key,
            write_key,
            read_counter: 0,
            write_counter: 0,
        }
    }

    pub fn encrypt(&mut self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut out = Vec::new();
        for chunk in data.chunks(Self::MAX_BLOCK) {
            let hdr = (chunk.len() as u16).to_le_bytes();
            let nonce = nonce64(self.write_counter);
            self.write_counter += 1;
            let sealed = chacha_seal(&self.write_key, &nonce, chunk, &hdr)?;
            out.extend_from_slice(&hdr);
            out.extend_from_slice(&sealed);
        }
        Ok(out)
    }

    pub fn decrypt(&mut self, encrypted_stream: &[u8]) -> Result<DecryptedChunk, CryptoError> {
        let mut plaintext = Vec::new();
        let mut offset = 0usize;
        while encrypted_stream.len() - offset >= 2 {
            let len = u16::from_le_bytes([encrypted_stream[offset], encrypted_stream[offset + 1]])
                as usize;
            let frame_len = 2 + len + Self::TAG_LEN;
            if encrypted_stream.len() - offset < frame_len {
                break;
            }
            let aad = &encrypted_stream[offset..offset + 2];
            let sealed = &encrypted_stream[offset + 2..offset + frame_len];
            let nonce = nonce64(self.read_counter);
            self.read_counter += 1;
            let chunk = chacha_open(&self.read_key, &nonce, sealed, aad)?;
            plaintext.extend_from_slice(&chunk);
            offset += frame_len;
        }
        Ok(DecryptedChunk {
            plaintext,
            rest: encrypted_stream[offset..].to_vec(),
        })
    }
}
