//! Built-in wire-level Simulated iPhone client for testing the entire encrypted CarPlay stack on macOS/Linux
//! without requiring a physical MFi chip or USB cable.
//!
//! Executes genuine `/pair-setup` (SRP-6a PIN `3939` + Ed25519), `/pair-verify` (X25519 + ChaCha20 `ControlCipher`),
//! `/auth-setup` (MFiSAP), `/info` (`bplist00`), `SETUP` (Timing + Event + H.264 Screen + RTP Audio),
//! real H.264 encoding via `openh264`, ChaCha20-Poly1305 media encryption, and reverse HID touch/knob reception.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use carplay_airplay::bplist::{self, PlistValue};
use carplay_airplay::crypto::{
    chacha_seal, hkdf_sha512, nonce64, nonce_label, x25519_generate, x25519_shared,
    AirPlayIdentity,
};
use carplay_airplay::hid::{decode_touch_report, KNOB_HID_UID, TOUCH_HID_UID};
use carplay_airplay::pairing::ControlCipher;
use carplay_airplay::plist_dict;
use carplay_airplay::rtsp;
use carplay_airplay::srp6a::Srp6aClientSession;
use carplay_airplay::streams::ScreenCodec;
use carplay_airplay::tlv8::{
    self, TLV_ENCRYPTED_DATA, TLV_IDENTIFIER, TLV_PROOF, TLV_PUBLIC_KEY, TLV_SALT, TLV_SIGNATURE,
    TLV_STATE,
};
use openh264::encoder::Encoder;
use openh264::formats::YUVBuffer;

use crate::font5x7::{draw_text, fill_circle, fill_rect};

#[derive(Debug, Clone)]
pub struct SimFeedbackState {
    pub last_touch_px: Option<(u16, u16, bool)>,
    pub selected_tile: usize,
    pub night_mode: bool,
    pub siri_active_until: Option<Instant>,
    pub hid_packets_received: u64,
}

impl Default for SimFeedbackState {
    fn default() -> Self {
        Self {
            last_touch_px: None,
            selected_tile: 0,
            night_mode: true,
            siri_active_until: None,
            hid_packets_received: 0,
        }
    }
}

pub struct SimulatedIphone {
    stop: Arc<AtomicBool>,
    pub state: Arc<Mutex<SimFeedbackState>>,
    thread: Option<JoinHandle<anyhow::Result<()>>>,
}

impl SimulatedIphone {
    pub fn spawn(
        server_addr: SocketAddr,
        width: usize,
        height: usize,
        max_frames: Option<u64>,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_bg = Arc::clone(&stop);
        let state = Arc::new(Mutex::new(SimFeedbackState::default()));
        let state_bg = Arc::clone(&state);

        let thread = thread::Builder::new()
            .name("simulated-iphone".into())
            .spawn(move || run_simulated_iphone(server_addr, width, height, max_frames, stop_bg, state_bg))
            .expect("spawn simulated-iphone");

        Self {
            stop,
            state,
            thread: Some(thread),
        }
    }

    pub fn stop_and_join(&mut self) -> anyhow::Result<()> {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.thread.take() {
            return h.join().unwrap_or_else(|_| Err(anyhow::anyhow!("sim thread panicked")));
        }
        Ok(())
    }

    pub fn join_finished(&mut self) -> anyhow::Result<()> {
        if let Some(h) = self.thread.take() {
            return h.join().unwrap_or_else(|_| Err(anyhow::anyhow!("sim thread panicked")));
        }
        Ok(())
    }
}

impl Drop for SimulatedIphone {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.thread.take() {
            let _ = h.join();
        }
    }
}

fn run_simulated_iphone(
    server_addr: SocketAddr,
    width: usize,
    height: usize,
    max_frames: Option<u64>,
    stop: Arc<AtomicBool>,
    feedback: Arc<Mutex<SimFeedbackState>>,
) -> anyhow::Result<()> {
    let mut ctrl = TcpStream::connect_timeout(&server_addr, Duration::from_secs(3))?;
    ctrl.set_nodelay(true)?;
    ctrl.set_read_timeout(Some(Duration::from_secs(3)))?;

    let iphone_identity = AirPlayIdentity::generate();
    let mut cseq = 0u32;

    // 1. /pair-setup M1 -> M2
    let m2_resp = send_plain_rtsp(
        &mut ctrl,
        &mut cseq,
        "POST",
        "/pair-setup",
        Some("application/pairing+tlv8"),
        &tlv8::encode(&[(TLV_STATE, &[1])]),
    )?;
    let m2 = tlv8::decode(&m2_resp.body)?;
    let srp = Srp6aClientSession::respond_to_challenge(
        "Pair-Setup",
        "3939",
        m2.get(&TLV_SALT).ok_or_else(|| anyhow::anyhow!("missing salt"))?,
        m2.get(&TLV_PUBLIC_KEY).ok_or_else(|| anyhow::anyhow!("missing pubB"))?,
    )
    .ok_or_else(|| anyhow::anyhow!("SRP client challenge failed"))?;

    // M3 -> M4
    let m4_resp = send_plain_rtsp(
        &mut ctrl,
        &mut cseq,
        "POST",
        "/pair-setup",
        Some("application/pairing+tlv8"),
        &tlv8::encode(&[
            (TLV_STATE, &[3]),
            (TLV_PUBLIC_KEY, &srp.public_key_a),
            (TLV_PROOF, &srp.client_proof),
        ]),
    )?;
    let m4 = tlv8::decode(&m4_resp.body)?;
    anyhow::ensure!(
        srp.verify_server_proof(m4.get(&TLV_PROOF).ok_or_else(|| anyhow::anyhow!("missing M4 proof"))?),
        "SRP server proof mismatch"
    );

    // M5 -> M6
    let ps_enc_key = hkdf_sha512(
        &srp.session_key,
        b"Pair-Setup-Encrypt-Salt",
        b"Pair-Setup-Encrypt-Info",
    );
    let ps_sign_key = hkdf_sha512(
        &srp.session_key,
        b"Pair-Setup-Controller-Sign-Salt",
        b"Pair-Setup-Controller-Sign-Info",
    );
    let mut m5_sig_msg = Vec::new();
    m5_sig_msg.extend_from_slice(&ps_sign_key);
    m5_sig_msg.extend_from_slice(iphone_identity.pairing_id.as_bytes());
    m5_sig_msg.extend_from_slice(&iphone_identity.public_key_bytes());
    let m5_sig = iphone_identity.sign(&m5_sig_msg);
    let m5_sub = tlv8::encode(&[
        (TLV_IDENTIFIER, iphone_identity.pairing_id.as_bytes()),
        (TLV_PUBLIC_KEY, &iphone_identity.public_key_bytes()),
        (TLV_SIGNATURE, &m5_sig),
    ]);
    let m5_sealed = chacha_seal(&ps_enc_key, &nonce_label(b"PS-Msg05"), &m5_sub, &[])?;
    let m6_resp = send_plain_rtsp(
        &mut ctrl,
        &mut cseq,
        "POST",
        "/pair-setup",
        Some("application/pairing+tlv8"),
        &tlv8::encode(&[(TLV_STATE, &[5]), (TLV_ENCRYPTED_DATA, &m5_sealed)]),
    )?;
    let m6 = tlv8::decode(&m6_resp.body)?;
    anyhow::ensure!(m6.get(&TLV_STATE).map(|v| v.as_slice()) == Some(&[6]), "M6 failed");

    // 2. /pair-verify M1 -> M2 -> M3 -> M4
    let (eph_priv, eph_pub) = x25519_generate();
    let pv2_resp = send_plain_rtsp(
        &mut ctrl,
        &mut cseq,
        "POST",
        "/pair-verify",
        Some("application/pairing+tlv8"),
        &tlv8::encode(&[(TLV_STATE, &[1]), (TLV_PUBLIC_KEY, &eph_pub)]),
    )?;
    let pv2 = tlv8::decode(&pv2_resp.body)?;
    let srv_eph_pub: [u8; 32] = pv2
        .get(&TLV_PUBLIC_KEY)
        .ok_or_else(|| anyhow::anyhow!("missing server ephemeral key"))?
        .as_slice()
        .try_into()?;
    let shared = x25519_shared(&eph_priv, &srv_eph_pub)?;
    let pv_enc_key = hkdf_sha512(
        &shared,
        b"Pair-Verify-Encrypt-Salt",
        b"Pair-Verify-Encrypt-Info",
    );

    let mut pv3_msg = Vec::new();
    pv3_msg.extend_from_slice(&eph_pub);
    pv3_msg.extend_from_slice(iphone_identity.pairing_id.as_bytes());
    pv3_msg.extend_from_slice(&srv_eph_pub);
    let pv3_sig = iphone_identity.sign(&pv3_msg);
    let pv3_sub = tlv8::encode(&[
        (TLV_IDENTIFIER, iphone_identity.pairing_id.as_bytes()),
        (TLV_SIGNATURE, &pv3_sig),
    ]);
    let pv3_sealed = chacha_seal(&pv_enc_key, &nonce_label(b"PV-Msg03"), &pv3_sub, &[])?;
    let pv4_resp = send_plain_rtsp(
        &mut ctrl,
        &mut cseq,
        "POST",
        "/pair-verify",
        Some("application/pairing+tlv8"),
        &tlv8::encode(&[(TLV_STATE, &[3]), (TLV_ENCRYPTED_DATA, &pv3_sealed)]),
    )?;
    let pv4 = tlv8::decode(&pv4_resp.body)?;
    anyhow::ensure!(pv4.get(&TLV_STATE).map(|v| v.as_slice()) == Some(&[4]), "PV4 failed");

    // Switch to encrypted ControlCipher!
    let client_write = hkdf_sha512(&shared, b"Control-Salt", b"Control-Write-Encryption-Key");
    let client_read = hkdf_sha512(&shared, b"Control-Salt", b"Control-Read-Encryption-Key");
    let mut cipher = ControlCipher::new(client_read, client_write);
    let mut enc_rx_rest = Vec::new();

    // 3. /auth-setup (MFiSAP)
    let (_, sap_pub) = x25519_generate();
    let mut sap_body = vec![0x01];
    sap_body.extend_from_slice(&sap_pub);
    let sap_resp = send_enc_rtsp(
        &mut ctrl,
        &mut cipher,
        &mut enc_rx_rest,
        &mut cseq,
        "POST",
        "/auth-setup",
        Some("application/octet-stream"),
        &sap_body,
    )?;
    anyhow::ensure!(sap_resp.path == "200" && sap_resp.body.len() > 40, "/auth-setup failed");

    // 4. GET /info
    let info_resp = send_enc_rtsp(
        &mut ctrl,
        &mut cipher,
        &mut enc_rx_rest,
        &mut cseq,
        "GET",
        "/info",
        None,
        &[],
    )?;
    let info_plist = bplist::decode(&info_resp.body)?;
    anyhow::ensure!(info_plist.as_dict().is_some(), "/info did not return bplist dict");

    // 5. Session SETUP -> connect reverse eventPort
    let timing_udp = UdpSocket::bind("127.0.0.1:0")?;
    let session_setup = plist_dict! {
        "name" => "iPhone 16 Pro (Simulador)",
        "model" => "iPhone17,1",
        "deviceID" => "DE:AD:BE:EF:00:01",
        "osVersion" => "26.0",
        "sourceVersion" => "820.12.1",
        "timingPort" => u64::from(timing_udp.local_addr()?.port()),
        "features" => PlistValue::Array(vec![
            PlistValue::from("iAPChannel"),
            PlistValue::from("viewAreas"),
        ]),
    };
    let setup1_resp = send_enc_rtsp(
        &mut ctrl,
        &mut cipher,
        &mut enc_rx_rest,
        &mut cseq,
        "SETUP",
        "rtsp://127.0.0.1/session",
        Some("application/x-apple-binary-plist"),
        &bplist::encode(&session_setup),
    )?;
    let setup1_dict = bplist::decode(&setup1_resp.body)?;
    let event_port = setup1_dict
        .as_dict()
        .and_then(|d| d.get("eventPort"))
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("missing eventPort in SETUP"))? as u16;

    // Connect reverse event channel & spawn listener for touch/knob/Siri/nightMode commands!
    let ev_stream = TcpStream::connect(SocketAddr::new(server_addr.ip(), event_port))?;
    ev_stream.set_nodelay(true)?;
    ev_stream.set_read_timeout(Some(Duration::from_millis(200)))?;
    spawn_iphone_event_reader(
        ev_stream,
        shared,
        width,
        height,
        Arc::clone(&stop),
        Arc::clone(&feedback),
    );

    // 6. Stream SETUP (Screen Type 110 + Audio Type 100) + RECORD
    let screen_conn_id: u64 = 0x1122_3344_5566_7788;
    let audio_conn_id: u64 = 0x99AA_BBCC_DDEE_FF00;
    let stream_setup = plist_dict! {
        "streams" => PlistValue::Array(vec![
            plist_dict! {
                "type" => 110u64,
                "streamConnectionID" => screen_conn_id,
            },
            plist_dict! {
                "type" => 100u64,
                "audioType" => "media",
                "audioFormat" => 0x8000u64, // 48 kHz stereo 16-bit LPCM
                "streamConnectionID" => audio_conn_id,
                "audioLatencyMs" => 40u64,
            },
        ]),
    };
    let setup2_resp = send_enc_rtsp(
        &mut ctrl,
        &mut cipher,
        &mut enc_rx_rest,
        &mut cseq,
        "SETUP",
        "rtsp://127.0.0.1/session",
        Some("application/x-apple-binary-plist"),
        &bplist::encode(&stream_setup),
    )?;
    let setup2_dict = bplist::decode(&setup2_resp.body)?;
    let streams_arr = setup2_dict
        .as_dict()
        .and_then(|d| d.get("streams"))
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("missing streams in SETUP response"))?;

    let mut screen_port = 0u16;
    let mut audio_port = 0u16;
    for s in streams_arr {
        if let Some(d) = s.as_dict() {
            match d.get("type").and_then(|v| v.as_u64()) {
                Some(110) => {
                    screen_port = d.get("dataPort").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                }
                Some(100) => {
                    audio_port = d.get("dataPort").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                }
                _ => {}
            }
        }
    }
    anyhow::ensure!(screen_port > 0 && audio_port > 0, "ports not allocated");

    let _ = send_enc_rtsp(
        &mut ctrl,
        &mut cipher,
        &mut enc_rx_rest,
        &mut cseq,
        "RECORD",
        "rtsp://127.0.0.1/session",
        None,
        &[],
    )?;

    // 7. Connect ScreenStream TCP & stream OpenH264-encoded encrypted CarPlay frames + UDP RTP audio!
    let mut screen_tcp = TcpStream::connect(SocketAddr::new(server_addr.ip(), screen_port))?;
    screen_tcp.set_nodelay(true)?;
    let audio_udp = UdpSocket::bind("127.0.0.1:0")?;
    let audio_target = SocketAddr::new(server_addr.ip(), audio_port);

    let screen_key = hkdf_sha512(
        &shared,
        format!("DataStream-Salt{screen_conn_id}").as_bytes(),
        b"DataStream-Output-Encryption-Key",
    );
    let audio_key = hkdf_sha512(
        &shared,
        format!("DataStream-Salt{audio_conn_id}").as_bytes(),
        b"DataStream-Output-Encryption-Key",
    );

    let mut h264_enc = Encoder::new()?;
    let mut rgb_canvas = vec![0u32; width * height];
    let mut yuv_vec = vec![0u8; width * height * 3 / 2];

    let mut frame_idx = 0u64;
    let mut audio_seq = 0u16;
    let mut audio_sample_ts = 0u32;
    let mut sent_config = false;

    while !stop.load(Ordering::Relaxed) {
        if let Some(limit) = max_frames {
            if frame_idx >= limit {
                break;
            }
        }
        let frame_start = Instant::now();

        // Render interactive CarPlay dashboard onto rgb_canvas
        {
            let st = feedback.lock().unwrap().clone();
            render_simulated_carplay_ui(&mut rgb_canvas, width, height, frame_idx, &st);
        }
        xrgb_to_i420(&rgb_canvas, width, height, &mut yuv_vec);
        let yuv_buf = YUVBuffer::from_vec(yuv_vec.clone(), width, height);
        let bitstream = h264_enc.encode(&yuv_buf)?;
        let annex_b = bitstream.to_vec();

        if !sent_config {
            if let Some(avcc) = extract_avcc_from_annex_b(&annex_b) {
                let mut cfg_body = b"\x00\x00\x00\x00avcC".to_vec();
                cfg_body.extend_from_slice(&avcc);
                let mut hdr = [0u8; ScreenCodec::HEADER_LEN];
                hdr[0..4].copy_from_slice(&(cfg_body.len() as u32).to_le_bytes());
                hdr[4] = ScreenCodec::OP_VIDEO_CONFIG;
                screen_tcp.write_all(&hdr)?;
                screen_tcp.write_all(&cfg_body)?;
                sent_config = true;
            }
        }

        let length_prefixed = annex_b_to_length_prefixed(&annex_b);
        let mut hdr = [0u8; ScreenCodec::HEADER_LEN];
        let sealed_len = length_prefixed.len() + 16;
        hdr[0..4].copy_from_slice(&(sealed_len as u32).to_le_bytes());
        hdr[4] = ScreenCodec::OP_VIDEO_FRAME;
        let sealed = chacha_seal(&screen_key, &nonce64(frame_idx), &length_prefixed, &hdr)?;
        screen_tcp.write_all(&hdr)?;
        screen_tcp.write_all(&sealed)?;
        screen_tcp.flush()?;

        // Send a gentle encrypted RTP chime packet on the first 15 frames (~300ms connection chime)
        if frame_idx < 15 {
            let samples_per_pkt = 960usize; // 20ms @ 48kHz stereo
            let mut pcm = Vec::with_capacity(samples_per_pkt * 4);
            for s in 0..samples_per_pkt {
                let t = (audio_sample_ts as usize + s) as f32 / 48_000.0;
                let freq = if frame_idx < 7 { 523.25 } else { 659.25 }; // C5 -> E5 CarPlay chime!
                let amp = (t * std::f32::consts::TAU * freq).sin() * 2200.0;
                let sample = amp as i16;
                pcm.extend_from_slice(&sample.to_be_bytes());
                pcm.extend_from_slice(&sample.to_be_bytes());
            }
            let mut rtp_hdr = [0u8; 12];
            rtp_hdr[0] = 0x80;
            rtp_hdr[1] = 96;
            rtp_hdr[2..4].copy_from_slice(&audio_seq.to_be_bytes());
            rtp_hdr[4..8].copy_from_slice(&audio_sample_ts.to_be_bytes());
            rtp_hdr[8..12].copy_from_slice(&0xCAFE_BABEu32.to_be_bytes());

            let nonce = nonce64(u64::from(audio_seq));
            let enc_audio = chacha_seal(&audio_key, &nonce, &pcm, &rtp_hdr[4..12])?;
            let mut wire = Vec::with_capacity(12 + enc_audio.len() + 8);
            wire.extend_from_slice(&rtp_hdr);
            wire.extend_from_slice(&enc_audio);
            wire.extend_from_slice(&nonce[4..12]);
            let _ = audio_udp.send_to(&wire, audio_target);

            audio_seq = audio_seq.wrapping_add(1);
            audio_sample_ts = audio_sample_ts.wrapping_add(samples_per_pkt as u32);
        }

        frame_idx += 1;
        let elapsed = frame_start.elapsed();
        if max_frames.is_none() && elapsed < Duration::from_millis(33) {
            thread::sleep(Duration::from_millis(33) - elapsed);
        }
    }

    Ok(())
}

fn spawn_iphone_event_reader(
    mut sock: TcpStream,
    shared: [u8; 32],
    width: usize,
    height: usize,
    stop: Arc<AtomicBool>,
    feedback: Arc<Mutex<SimFeedbackState>>,
) {
    thread::Builder::new()
        .name("sim-iphone-event-rx".into())
        .spawn(move || {
            let srv_write_key = hkdf_sha512(&shared, b"Events-Salt", b"Events-Write-Encryption-Key");
            let srv_read_key = hkdf_sha512(&shared, b"Events-Salt", b"Events-Read-Encryption-Key");
            let mut cipher = ControlCipher::new(srv_write_key, srv_read_key);
            let mut enc_buf = Vec::new();
            let mut plain_buf = Vec::new();
            let mut buf = [0u8; 4096];

            while !stop.load(Ordering::Relaxed) {
                match sock.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        enc_buf.extend_from_slice(&buf[..n]);
                        let Ok(dec) = cipher.decrypt(&enc_buf) else {
                            break;
                        };
                        enc_buf = dec.rest;
                        plain_buf.extend_from_slice(&dec.plaintext);
                        let batch = rtsp::parse_messages(&plain_buf);
                        plain_buf = batch.rest;

                        for req in batch.messages {
                            if let Ok(PlistValue::Dict(d)) = bplist::decode(&req.body) {
                                let mut st = feedback.lock().unwrap();
                                st.hid_packets_received += 1;
                                match d.get("type").and_then(|v| v.as_str()).unwrap_or("") {
                                    "hidSendReport" => {
                                        let uuid = d.get("uuid").and_then(|v| v.as_str()).unwrap_or("");
                                        if let Some(rep) = d.get("hidReport").and_then(|v| v.as_bytes()) {
                                            if uuid == format!("{TOUCH_HID_UID:x}") {
                                                let contacts = decode_touch_report(rep);
                                                if let Some(c) = contacts.first() {
                                                    let px = c.x as u16;
                                                    let py = c.y as u16;
                                                    st.last_touch_px = Some((px, py, c.down));
                                                    if c.down {
                                                        // Hit-test the 4 app tiles
                                                        let tile_w = (width - 140) / 4;
                                                        if usize::from(px) >= 110 && usize::from(py) >= 80 && usize::from(py) <= height - 80 {
                                                            let idx = ((usize::from(px) - 110) / tile_w.max(1)).min(3);
                                                            st.selected_tile = idx;
                                                        }
                                                    }
                                                }
                                            } else if uuid == format!("{KNOB_HID_UID:x}") && rep.len() >= 4 {
                                                let wheel = rep[3] as i8;
                                                if wheel > 0 {
                                                    st.selected_tile = (st.selected_tile + 1) % 4;
                                                } else if wheel < 0 {
                                                    st.selected_tile = (st.selected_tile + 3) % 4;
                                                }
                                                if (rep[0] & 0x02) != 0 {
                                                    st.selected_tile = 0; // Home
                                                }
                                            }
                                        }
                                    }
                                    "setNightMode" => {
                                        if let Some(nm) = d
                                            .get("params")
                                            .and_then(|p| p.as_dict())
                                            .and_then(|p| p.get("nightMode"))
                                            .and_then(|v| v.as_bool())
                                        {
                                            st.night_mode = nm;
                                        }
                                    }
                                    "requestSiri" => {
                                        st.siri_active_until =
                                            Some(Instant::now() + Duration::from_secs(3));
                                    }
                                    _ => {}
                                }
                            }
                            let reply = rtsp::build_response(&req, &rtsp::RtspResponse::ok());
                            if let Ok(enc_reply) = cipher.encrypt(&reply) {
                                let _ = sock.write_all(&enc_reply);
                            }
                        }
                    }
                    Err(ref e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        continue;
                    }
                    Err(_) => break,
                }
            }
        })
        .ok();
}

fn render_simulated_carplay_ui(
    fb: &mut [u32],
    w: usize,
    h: usize,
    frame_idx: u64,
    st: &SimFeedbackState,
) {
    let bg = if st.night_mode { 0x101622 } else { 0xDCE6F2 };
    let dock_bg = if st.night_mode { 0x1C2536 } else { 0xB8C7DC };
    let fg = if st.night_mode { 0xF4F7FC } else { 0x141A24 };
    fb.fill(bg);

    // Left CarPlay Dock
    fill_rect(fb, w, h, 0, 0, 88, h, dock_bg);
    draw_text(fb, w, h, 14, 22, 2, fg, "18:42");
    draw_text(fb, w, h, 14, 48, 1, 0x4CD964, "5G CARPLAY");
    fill_rect(fb, w, h, 20, h - 68, 48, 48, 0x2C7BE5);
    draw_text(fb, w, h, 30, h - 50, 2, 0xFFFFFF, "CP");

    // Header
    draw_text(
        fb,
        w,
        h,
        112,
        24,
        2,
        fg,
        "CARPLAY-RS ENCRYPTED H.264 LIVE STREAM",
    );

    let tiles = [
        ("MAPS", 0x2ECC71u32),
        ("MUSIC", 0xFA2D48u32),
        ("PHONE", 0x34C759u32),
        ("SETTINGS", 0x5856D6u32),
    ];
    let avail_w = w.saturating_sub(140);
    let tile_w = (avail_w / 4).saturating_sub(16);
    let tile_h = h.saturating_sub(180);

    for (i, (label, color)) in tiles.iter().enumerate() {
        let tx = 112 + i * (tile_w + 16);
        let ty = 76usize;
        if st.selected_tile == i {
            fill_rect(
                fb,
                w,
                h,
                tx.saturating_sub(5),
                ty.saturating_sub(5),
                tile_w + 10,
                tile_h + 10,
                0xFFFFFF,
            );
        }
        fill_rect(fb, w, h, tx, ty, tile_w, tile_h, *color);
        draw_text(fb, w, h, tx + 18, ty + tile_h / 2 - 8, 2, 0xFFFFFF, label);
    }

    // Animated radar / equalizer bar proving live 30/60fps H.264 encode->encrypt->decrypt->decode
    let pulse_x = 112 + ((frame_idx as usize * 8) % avail_w.max(1));
    fill_rect(fb, w, h, pulse_x, h - 72, 48, 10, 0x00D2FF);

    draw_text(
        fb,
        w,
        h,
        112,
        h - 44,
        2,
        fg,
        &format!(
            "FRAME {} | HID EVENTS {} | CLICK TILES OR USE KEYS H/N/S",
            frame_idx, st.hid_packets_received
        ),
    );

    if let Some(until) = st.siri_active_until {
        if Instant::now() < until {
            fill_circle(fb, w, h, (w / 2) as i32, (h - 90) as i32, 34, 0xAF52DE);
            draw_text(fb, w, h, w / 2 - 22, h - 96, 2, 0xFFFFFF, "SIRI");
        }
    }

    if let Some((tx, ty, down)) = st.last_touch_px {
        let ring_color = if down { 0xFFCC00 } else { 0x5AC8FA };
        fill_circle(fb, w, h, i32::from(tx), i32::from(ty), if down { 18 } else { 10 }, ring_color);
    }
}

fn xrgb_to_i420(xrgb: &[u32], width: usize, height: usize, out: &mut [u8]) {
    let y_size = width * height;
    let uv_size = (width / 2) * (height / 2);
    let (y_plane, uv) = out.split_at_mut(y_size);
    let (u_plane, v_plane) = uv.split_at_mut(uv_size);

    for r in 0..height {
        for c in 0..width {
            let px = xrgb[r * width + c];
            let red = ((px >> 16) & 0xFF) as i32;
            let green = ((px >> 8) & 0xFF) as i32;
            let blue = (px & 0xFF) as i32;
            let y = ((66 * red + 129 * green + 25 * blue + 128) >> 8) + 16;
            y_plane[r * width + c] = y.clamp(16, 235) as u8;
            if (r & 1) == 0 && (c & 1) == 0 {
                let u = ((-38 * red - 74 * green + 112 * blue + 128) >> 8) + 128;
                let v = ((112 * red - 94 * green - 18 * blue + 128) >> 8) + 128;
                let uv_idx = (r / 2) * (width / 2) + (c / 2);
                u_plane[uv_idx] = u.clamp(16, 240) as u8;
                v_plane[uv_idx] = v.clamp(16, 240) as u8;
            }
        }
    }
}

fn split_annex_b_nalus(annex_b: &[u8]) -> Vec<&[u8]> {
    let mut nalus = Vec::new();
    let mut starts = Vec::new();
    let mut i = 0usize;
    while i + 3 < annex_b.len() {
        if annex_b[i..i + 4] == [0, 0, 0, 1] {
            starts.push((i, 4usize));
            i += 4;
            continue;
        }
        if annex_b[i..i + 3] == [0, 0, 1] {
            starts.push((i, 3usize));
            i += 3;
            continue;
        }
        i += 1;
    }
    for idx in 0..starts.len() {
        let (pos, sc_len) = starts[idx];
        let end = starts.get(idx + 1).map(|s| s.0).unwrap_or(annex_b.len());
        if pos + sc_len < end {
            nalus.push(&annex_b[pos + sc_len..end]);
        }
    }
    nalus
}

fn extract_avcc_from_annex_b(annex_b: &[u8]) -> Option<Vec<u8>> {
    let mut sps: Option<&[u8]> = None;
    let mut pps: Option<&[u8]> = None;
    for nalu in split_annex_b_nalus(annex_b) {
        match nalu[0] & 0x1F {
            7 => sps = Some(nalu),
            8 => pps = Some(nalu),
            _ => {}
        }
    }
    let sps = sps?;
    let pps = pps?;
    if sps.len() < 4 {
        return None;
    }
    let mut avcc = vec![0x01, sps[1], sps[2], sps[3], 0xFF, 0xE1];
    avcc.extend_from_slice(&(sps.len() as u16).to_be_bytes());
    avcc.extend_from_slice(sps);
    avcc.push(0x01);
    avcc.extend_from_slice(&(pps.len() as u16).to_be_bytes());
    avcc.extend_from_slice(pps);
    Some(avcc)
}

fn annex_b_to_length_prefixed(annex_b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for nalu in split_annex_b_nalus(annex_b) {
        out.extend_from_slice(&(nalu.len() as u32).to_be_bytes());
        out.extend_from_slice(nalu);
    }
    out
}

fn send_plain_rtsp(
    stream: &mut TcpStream,
    cseq: &mut u32,
    method: &str,
    path: &str,
    ct: Option<&str>,
    body: &[u8],
) -> anyhow::Result<rtsp::RtspRequest> {
    *cseq += 1;
    let wire = rtsp::build_request(method, path, *cseq, ct, &[], body);
    stream.write_all(&wire)?;
    stream.flush()?;

    let mut acc = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk)?;
        anyhow::ensure!(n > 0, "EOF waiting for plaintext RTSP reply");
        acc.extend_from_slice(&chunk[..n]);
        let mut parsed = rtsp::parse_messages(&acc);
        if !parsed.messages.is_empty() {
            return Ok(parsed.messages.remove(0));
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn send_enc_rtsp(
    stream: &mut TcpStream,
    cipher: &mut ControlCipher,
    enc_rest: &mut Vec<u8>,
    cseq: &mut u32,
    method: &str,
    path: &str,
    ct: Option<&str>,
    body: &[u8],
) -> anyhow::Result<rtsp::RtspRequest> {
    *cseq += 1;
    let plain_req = rtsp::build_request(method, path, *cseq, ct, &[], body);
    let enc_req = cipher.encrypt(&plain_req)?;
    stream.write_all(&enc_req)?;
    stream.flush()?;

    let mut plain_acc = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk)?;
        anyhow::ensure!(n > 0, "EOF waiting for encrypted RTSP reply");
        enc_rest.extend_from_slice(&chunk[..n]);
        let dec = cipher.decrypt(enc_rest)?;
        *enc_rest = dec.rest;
        plain_acc.extend_from_slice(&dec.plaintext);
        let mut parsed = rtsp::parse_messages(&plain_acc);
        if !parsed.messages.is_empty() {
            return Ok(parsed.messages.remove(0));
        }
    }
}
