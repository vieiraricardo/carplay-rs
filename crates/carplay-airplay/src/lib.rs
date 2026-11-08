//! `carplay-airplay`: Complete AirPlay / CarPlay RTSP control server, SRP-6a `/pair-setup`,
//! X25519+Ed25519 `/pair-verify`, `/auth-setup` (MFiSAP), `bplist00` `/info` & `SETUP`,
//! encrypted H.264/H.265 `ScreenStream`, RTP `AudioStream`, `IapTunnel`, HID input, and Bonjour mDNS.

pub mod bonjour;
#[macro_use]
pub mod bplist;
pub mod crypto;
pub mod hid;
pub mod info_plist;
pub mod ntp_clock;
pub mod pairing;
pub mod rtsp;
pub mod session;
pub mod srp6a;
pub mod streams;
pub mod tlv8;

pub use bonjour::{send_carplay_connect_probe, CarPlayBonjour};
pub use bplist::PlistValue;
pub use crypto::{AirPlayIdentity, PairingStore};
pub use hid::{AirPlayContact, AirPlayKnobState, TouchSlotAssigner};
pub use info_plist::{AirPlayConfig, AirPlayDisplayConfig, build_info_plist};
pub use ntp_clock::NtpClock;
pub use pairing::{ControlCipher, MfiSapAuthSetup, PairSetup, PairVerify};
pub use session::{
    AirPlayControlHandle, AirPlayServer, MediaSink, STREAM_ALT_AUDIO, STREAM_ALT_SCREEN,
    STREAM_DATA_TUNNEL, STREAM_MAIN_AUDIO, STREAM_MAIN_HIGH_AUDIO, STREAM_MAIN_SCREEN,
};
pub use streams::{AudioCodecKind, AudioFormat, AudioStreamId, ScreenCodec, VideoCodec};

#[cfg(test)]
mod tests {
    use super::*;
    use carplay_mfi::LocalP256MfiClient;
    use crypto::{chacha_open, chacha_seal, hkdf_sha512, nonce64, nonce_label, sha1_concat, x25519_generate, x25519_shared};
    use srp6a::Srp6aClientSession;
    use tlv8::{
        TLV_ENCRYPTED_DATA, TLV_IDENTIFIER, TLV_PROOF, TLV_PUBLIC_KEY, TLV_SALT, TLV_SIGNATURE,
        TLV_STATE,
    };

    #[test]
    fn tlv8_fragments_and_coalesces_large_items() {
        let big = vec![0xABu8; 600];
        let encoded = tlv8::encode(&[(TLV_STATE, &[2]), (TLV_PUBLIC_KEY, &big), (TLV_SALT, &[1, 2, 3])]);
        let decoded = tlv8::decode(&encoded).unwrap();
        assert_eq!(decoded.get(&TLV_STATE).unwrap(), &[2]);
        assert_eq!(decoded.get(&TLV_PUBLIC_KEY).unwrap(), &big);
        assert_eq!(decoded.get(&TLV_SALT).unwrap(), &[1, 2, 3]);
    }

    #[test]
    fn bplist_roundtrips_carplay_info_dictionary() {
        let cfg = AirPlayConfig::default();
        let info = build_info_plist(&cfg);
        let wire = bplist::encode(&info);
        let decoded = bplist::decode(&wire).unwrap();
        let dict = decoded.as_dict().unwrap();
        assert_eq!(dict.get("name").unwrap().as_str(), Some("CarPlay-RS"));
        assert_eq!(
            dict.get("features").unwrap().as_u64(),
            Some(info_plist::CARPLAY_FEATURES)
        );
        let displays = dict.get("displays").unwrap().as_array().unwrap();
        assert_eq!(displays.len(), 1);
    }

    #[test]
    fn full_pair_setup_pair_verify_control_cipher_and_mfisap() {
        let accessory_id = AirPlayIdentity::generate();
        let controller_id = AirPlayIdentity::generate();
        let store = PairingStore::in_memory();

        // 1. /pair-setup (M1..M6)
        let mut ps = PairSetup::new(accessory_id.clone(), store.clone());
        let m2 = tlv8::decode(&ps.handle(&tlv8::encode(&[(TLV_STATE, &[1])]))).unwrap();
        assert_eq!(m2.get(&TLV_STATE).unwrap(), &[2]);

        let client_srp = Srp6aClientSession::respond_to_challenge(
            "Pair-Setup",
            "3939",
            m2.get(&TLV_SALT).unwrap(),
            m2.get(&TLV_PUBLIC_KEY).unwrap(),
        )
        .unwrap();

        let m4 = tlv8::decode(&ps.handle(&tlv8::encode(&[
            (TLV_STATE, &[3]),
            (TLV_PUBLIC_KEY, &client_srp.public_key_a),
            (TLV_PROOF, &client_srp.client_proof),
        ])))
        .unwrap();
        assert!(client_srp.verify_server_proof(m4.get(&TLV_PROOF).unwrap()));

        // Build M5 encrypted sub-TLV
        let enc_key = hkdf_sha512(
            &client_srp.session_key,
            b"Pair-Setup-Encrypt-Salt",
            b"Pair-Setup-Encrypt-Info",
        );
        let sign_key = hkdf_sha512(
            &client_srp.session_key,
            b"Pair-Setup-Controller-Sign-Salt",
            b"Pair-Setup-Controller-Sign-Info",
        );
        let mut sig_msg = Vec::new();
        sig_msg.extend_from_slice(&sign_key);
        sig_msg.extend_from_slice(controller_id.pairing_id.as_bytes());
        sig_msg.extend_from_slice(&controller_id.public_key_bytes());
        let sig = controller_id.sign(&sig_msg);
        let m5_sub = tlv8::encode(&[
            (TLV_IDENTIFIER, controller_id.pairing_id.as_bytes()),
            (TLV_PUBLIC_KEY, &controller_id.public_key_bytes()),
            (TLV_SIGNATURE, &sig),
        ]);
        let m5_enc = chacha_seal(&enc_key, &nonce_label(b"PS-Msg05"), &m5_sub, &[]).unwrap();
        let m6 = tlv8::decode(&ps.handle(&tlv8::encode(&[
            (TLV_STATE, &[5]),
            (TLV_ENCRYPTED_DATA, &m5_enc),
        ])))
        .unwrap();
        assert_eq!(m6.get(&TLV_STATE).unwrap(), &[6]);
        assert!(ps.complete);

        // 2. /pair-verify (M1..M4)
        let mut pv = PairVerify::new(accessory_id, store);
        let (c_eph_priv, c_eph_pub) = x25519_generate();
        let pv_m2 = tlv8::decode(&pv.handle(&tlv8::encode(&[
            (TLV_STATE, &[1]),
            (TLV_PUBLIC_KEY, &c_eph_pub),
        ])))
        .unwrap();
        let s_eph_pub: [u8; 32] = pv_m2.get(&TLV_PUBLIC_KEY).unwrap().as_slice().try_into().unwrap();
        let shared = x25519_shared(&c_eph_priv, &s_eph_pub).unwrap();
        let pv_enc_key = hkdf_sha512(
            &shared,
            b"Pair-Verify-Encrypt-Salt",
            b"Pair-Verify-Encrypt-Info",
        );

        let mut c_pv_msg = Vec::new();
        c_pv_msg.extend_from_slice(&c_eph_pub);
        c_pv_msg.extend_from_slice(controller_id.pairing_id.as_bytes());
        c_pv_msg.extend_from_slice(&s_eph_pub);
        let c_pv_sig = controller_id.sign(&c_pv_msg);
        let pv_m3_sub = tlv8::encode(&[
            (TLV_IDENTIFIER, controller_id.pairing_id.as_bytes()),
            (TLV_SIGNATURE, &c_pv_sig),
        ]);
        let pv_m3_enc =
            chacha_seal(&pv_enc_key, &nonce_label(b"PV-Msg03"), &pv_m3_sub, &[]).unwrap();
        let pv_m4 = tlv8::decode(&pv.handle(&tlv8::encode(&[
            (TLV_STATE, &[3]),
            (TLV_ENCRYPTED_DATA, &pv_m3_enc),
        ])))
        .unwrap();
        assert_eq!(pv_m4.get(&TLV_STATE).unwrap(), &[4]);

        // 3. ControlCipher bidirectional encryption check
        let server_keys = pv.control_keys().unwrap();
        let mut server_cipher = ControlCipher::new(server_keys.read_key, server_keys.write_key);
        let client_write = hkdf_sha512(&shared, b"Control-Salt", b"Control-Write-Encryption-Key");
        let client_read = hkdf_sha512(&shared, b"Control-Salt", b"Control-Read-Encryption-Key");
        let mut client_cipher = ControlCipher::new(client_read, client_write);

        let wire = client_cipher.encrypt(b"GET /info RTSP/1.0\r\nCSeq: 1\r\n\r\n").unwrap();
        let dec = server_cipher.decrypt(&wire).unwrap();
        assert_eq!(dec.plaintext, b"GET /info RTSP/1.0\r\nCSeq: 1\r\n\r\n");

        // 4. /auth-setup MFiSAP check
        let mfi = LocalP256MfiClient::ephemeral_for_testing();
        let (sap_priv, sap_pub) = x25519_generate();
        let mut sap_req = vec![0x01];
        sap_req.extend_from_slice(&sap_pub);
        let sap_resp = MfiSapAuthSetup::handle(&sap_req, &mfi).unwrap();
        let acc_sap_pub = &sap_resp[0..32];
        let sap_shared = x25519_shared(&sap_priv, acc_sap_pub).unwrap();
        assert_ne!(sap_shared, [0u8; 32]);
        let _ = sha1_concat(&[b"AES-KEY", &sap_shared]);
    }

    #[test]
    fn screen_codec_annex_b_and_avcc_conversion() {
        let sps = [0x67, 0x42, 0x00, 0x1f, 0xe9, 0x01, 0x40, 0x7b, 0x20];
        let pps = [0x68, 0xce, 0x06, 0xf2];
        let mut avcc_box = b"\x00\x00\x00\x20avcC".to_vec();
        avcc_box.extend_from_slice(&[0x01, sps[1], sps[2], sps[3], 0xFF, 0xE1]);
        avcc_box.extend_from_slice(&(sps.len() as u16).to_be_bytes());
        avcc_box.extend_from_slice(&sps);
        avcc_box.push(0x01);
        avcc_box.extend_from_slice(&(pps.len() as u16).to_be_bytes());
        avcc_box.extend_from_slice(&pps);

        let (codec, raw) = ScreenCodec::detect_config(&avcc_box);
        assert_eq!(codec, VideoCodec::H264);
        let annex_b = ScreenCodec::avcc_to_annex_b(&raw).unwrap();
        assert!(annex_b.starts_with(&[0, 0, 0, 1, 0x67]));

        // Length-prefixed NALU conversion
        let mut lp = Vec::new();
        lp.extend_from_slice(&3u32.to_be_bytes());
        lp.extend_from_slice(&[0x65, 0xAA, 0xBB]);
        lp.extend_from_slice(&2u32.to_be_bytes());
        lp.extend_from_slice(&[0x06, 0xCC]);
        assert_eq!(
            ScreenCodec::length_prefixed_to_annex_b(lp),
            vec![0, 0, 0, 1, 0x65, 0xAA, 0xBB, 0, 0, 0, 1, 0x06, 0xCC]
        );

        // Decryption roundtrip
        let key = [0x55u8; 32];
        let mut hdr = [0u8; 128];
        hdr[0..4].copy_from_slice(&20u32.to_le_bytes());
        let sealed = chacha_seal(&key, &nonce64(0), &[1, 2, 3, 4], &hdr).unwrap();
        let opened = ScreenCodec::decrypt_frame(&key, 0, &hdr, &sealed).unwrap();
        assert_eq!(opened, vec![1, 2, 3, 4]);
        let _ = chacha_open(&key, &nonce64(0), &sealed, &hdr).unwrap();
    }
}
