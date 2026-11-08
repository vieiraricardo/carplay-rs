//! CarPlay Media & DataStream receivers:
//! - `ScreenStream` (TCP stream type 110/111, 128B header, ChaCha20-Poly1305 decryption, `avcC`/`hvcC` -> Annex-B)
//! - `AudioStream` (UDP RTP+RTCP stream type 100/101/102, ChaCha20-Poly1305 per-datagram decryption)
//! - `IapTunnel` (TCP stream type 130, `DataStream-Salt<seed>` `APTransportPackage` `"comm"` iAP2 tunnel)

use std::io::{BufReader, Read};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::crypto::{chacha_open, nonce64, CryptoError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoCodec {
    H264,
    H265,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioCodecKind {
    Lpcm,
    AacLc,
    Opus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioFormat {
    pub codec: AudioCodecKind,
    pub sample_rate: u32,
    pub channels: u8,
    pub payload_type: u16,
    pub audio_type: String,
    pub rtp_clock_rate: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioStreamId {
    pub stream_type: u16,
    pub audio_type: String,
}

/// Pure codec utilities for CarPlay screen frames and `avcC`/`hvcC` configuration records.
pub struct ScreenCodec;

impl ScreenCodec {
    pub const HEADER_LEN: usize = 128;
    pub const OP_VIDEO_FRAME: u8 = 0;
    pub const OP_VIDEO_CONFIG: u8 = 1;
    pub const TAG_SIZE: usize = 16;

    /// Reads the sender timestamp (bytes `8..16`, little-endian NTP 32.32) converted to nanoseconds.
    pub fn sender_nanos(header: &[u8]) -> u64 {
        if header.len() < 16 {
            return 0;
        }
        let raw = u64::from_le_bytes(header[8..16].try_into().unwrap());
        let secs = raw >> 32;
        let frac = raw & 0xFFFF_FFFF;
        secs.saturating_mul(1_000_000_000)
            .saturating_add((frac.saturating_mul(1_000_000_000)) >> 32)
    }

    pub fn decrypt_frame(
        key: &[u8; 32],
        frame_counter: u64,
        header_128: &[u8],
        body: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        chacha_open(key, &nonce64(frame_counter), body, header_128)
    }

    /// Converts 4-byte big-endian length-prefixed NALUs into Annex-B (`00 00 00 01`) in place.
    /// Robust against multi-slice frames, SEI/AUD, and trailing padding bytes.
    pub fn length_prefixed_to_annex_b(mut payload: Vec<u8>) -> Vec<u8> {
        if payload.len() < 4 {
            return payload;
        }
        if payload.starts_with(&[0, 0, 0, 1]) || payload.starts_with(&[0, 0, 1]) {
            return payload;
        }
        let mut offset = 0usize;
        let mut nals = Vec::new();
        while offset + 4 <= payload.len() {
            let len = u32::from_be_bytes(payload[offset..offset + 4].try_into().unwrap()) as usize;
            if len == 0 || offset + 4 + len > payload.len() {
                break;
            }
            nals.push(offset);
            offset += 4 + len;
        }
        if !nals.is_empty() {
            for off in nals {
                payload[off..off + 4].copy_from_slice(&[0, 0, 0, 1]);
            }
            payload.truncate(offset);
        }
        payload
    }

    /// Detects `avcC` or `hvcC` box inside an `OP_VIDEO_CONFIG` body and extracts the raw codec config record.
    pub fn detect_config(payload: &[u8]) -> (VideoCodec, Vec<u8>) {
        if payload.len() >= 8 {
            for idx in 4..=payload.len() - 4 {
                match &payload[idx..idx + 4] {
                    b"hvcC" => return (VideoCodec::H265, payload[idx + 4..].to_vec()),
                    b"avcC" => return (VideoCodec::H264, payload[idx + 4..].to_vec()),
                    _ => {}
                }
            }
        }
        if Self::looks_like_avcc(payload) {
            (VideoCodec::H264, payload.to_vec())
        } else {
            (VideoCodec::H265, payload.to_vec())
        }
    }

    /// Converts an ISO BMFF `avcC` decoder configuration record into Annex-B SPS + PPS NALUs (`00 00 00 01 ...`).
    /// This allows Annex-B decoders (`openh264`, V4L2 `rkvdec`/`cedrus`, FFmpeg) to initialize directly!
    pub fn avcc_to_annex_b(avcc: &[u8]) -> Option<Vec<u8>> {
        if avcc.len() < 7 || avcc[0] != 1 {
            return None;
        }
        let num_sps = (avcc[5] & 0x1F) as usize;
        let mut pos = 6usize;
        let mut out = Vec::new();
        for _ in 0..num_sps {
            if pos + 2 > avcc.len() {
                return None;
            }
            let sps_len = u16::from_be_bytes([avcc[pos], avcc[pos + 1]]) as usize;
            pos += 2;
            if pos + sps_len > avcc.len() {
                return None;
            }
            out.extend_from_slice(&[0, 0, 0, 1]);
            out.extend_from_slice(&avcc[pos..pos + sps_len]);
            pos += sps_len;
        }
        if pos < avcc.len() {
            let num_pps = avcc[pos] as usize;
            pos += 1;
            for _ in 0..num_pps {
                if pos + 2 > avcc.len() {
                    return None;
                }
                let pps_len = u16::from_be_bytes([avcc[pos], avcc[pos + 1]]) as usize;
                pos += 2;
                if pos + pps_len > avcc.len() {
                    return None;
                }
                out.extend_from_slice(&[0, 0, 0, 1]);
                out.extend_from_slice(&avcc[pos..pos + pps_len]);
                pos += pps_len;
            }
        }
        Some(out)
    }

    fn looks_like_avcc(payload: &[u8]) -> bool {
        if payload.len() < 9 || (payload[5] & 0x1F) < 1 {
            return false;
        }
        let sps_len = u16::from_be_bytes([payload[6], payload[7]]) as usize;
        8 + sps_len <= payload.len() && (payload[8] & 0x1F) == 7
    }
}

/// TCP receiver for CarPlay Main/Cluster Screen Stream (`110` / `111`).
pub struct ScreenStream {
    closed: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ScreenStream {
    pub fn listen<FCodec, FConfig, FFrame>(
        key: [u8; 32],
        bind_addr: SocketAddr,
        mut on_codec: FCodec,
        mut on_config: FConfig,
        mut on_frame: FFrame,
    ) -> std::io::Result<(Self, u16)>
    where
        FCodec: FnMut(VideoCodec) + Send + 'static,
        FConfig: FnMut(&[u8], Option<&[u8]>) + Send + 'static,
        FFrame: FnMut(Vec<u8>, u64, Instant) + Send + 'static,
    {
        let mut addr = bind_addr;
        addr.set_port(0);
        let listener = TcpListener::bind(addr)?;
        let s = socket2::SockRef::from(&listener);
        let _ = s.set_recv_buffer_size(2 * 1024 * 1024);
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let closed = Arc::new(AtomicBool::new(false));
        let closed_bg = Arc::clone(&closed);

        let thread = thread::Builder::new()
            .name("carplay-screen-rx".into())
            .spawn(move || {
                let mut accepted = None;
                while !closed_bg.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((sock, _)) => {
                            let _ = sock.set_nonblocking(false);
                            let _ = sock.set_nodelay(true);
                            let _ = sock.set_read_timeout(Some(Duration::from_millis(500)));
                            // Set a large 2 MB TCP receive buffer so sudden high-motion bursts (dragging/swiping)
                            // never stall the TCP window or cause iOS's VideoToolbox to drop bitrate/resolution.
                            let s = socket2::SockRef::from(&sock);
                            let _ = s.set_recv_buffer_size(2 * 1024 * 1024);
                            accepted = Some(sock);
                            break;
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => return,
                    }
                }
                let Some(sock) = accepted else {
                    return;
                };
                let mut reader = BufReader::with_capacity(256 * 1024, sock);

                let mut frame_counter = 0u64;
                let mut header = [0u8; ScreenCodec::HEADER_LEN];
                let mut body = Vec::with_capacity(128 * 1024);
                while !closed_bg.load(Ordering::Relaxed) {
                    if !read_exact_interruptible(&mut reader, &mut header, &closed_bg) {
                        break;
                    }
                    let body_size =
                        u32::from_le_bytes(header[0..4].try_into().unwrap()) as usize;
                    if body_size > 8 * 1024 * 1024 {
                        break;
                    }
                    body.resize(body_size, 0);
                    if !read_exact_interruptible(&mut reader, &mut body, &closed_bg) {
                        break;
                    }
                    let arrival = Instant::now();
                    match header[4] {
                        ScreenCodec::OP_VIDEO_FRAME => {
                            if body.len() < ScreenCodec::TAG_SIZE {
                                continue;
                            }
                            let Ok(plain) =
                                ScreenCodec::decrypt_frame(&key, frame_counter, &header, &body)
                            else {
                                tracing::warn!("screen frame decrypt failure at counter={frame_counter}");
                                break;
                            };
                            frame_counter += 1;
                            let annex_b = ScreenCodec::length_prefixed_to_annex_b(plain);
                            let sender_ns = ScreenCodec::sender_nanos(&header);
                            on_frame(annex_b, sender_ns, arrival);
                        }
                        ScreenCodec::OP_VIDEO_CONFIG => {
                            let (codec, raw_cfg) = ScreenCodec::detect_config(&body);
                            let annex_b_sps_pps = if codec == VideoCodec::H264 {
                                ScreenCodec::avcc_to_annex_b(&raw_cfg)
                            } else {
                                None
                            };
                            on_codec(codec);
                            on_config(&raw_cfg, annex_b_sps_pps.as_deref());
                        }
                        _ => {}
                    }
                }
            })?;

        Ok((
            Self {
                closed,
                thread: Some(thread),
            },
            port,
        ))
    }

    pub fn stop(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for ScreenStream {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Maps negotiated `audioFormat` bitmasks from `SETUP` into concrete decode parameters.
pub fn audio_format_from_bits(bits: u64, payload_type: u16, audio_type: &str) -> AudioFormat {
    const AAC_LC_44K_STEREO: u64 = 0x40_0000;
    const AAC_LC_48K_STEREO: u64 = 0x80_0000;
    const OPUS_16K: u64 = 0x1000_0000;
    const OPUS_24K: u64 = 0x2000_0000;
    const OPUS_48K: u64 = 0x4000_0000;

    if (bits & (OPUS_16K | OPUS_24K | OPUS_48K)) != 0 {
        let clock = if (bits & OPUS_16K) != 0 {
            16_000
        } else if (bits & OPUS_24K) != 0 {
            24_000
        } else {
            48_000
        };
        return AudioFormat {
            codec: AudioCodecKind::Opus,
            sample_rate: 48_000,
            channels: 1,
            payload_type,
            audio_type: audio_type.to_string(),
            rtp_clock_rate: clock,
        };
    }

    if (bits & (AAC_LC_44K_STEREO | AAC_LC_48K_STEREO)) != 0 {
        let rate = if (bits & AAC_LC_48K_STEREO) != 0 {
            48_000
        } else {
            44_100
        };
        return AudioFormat {
            codec: AudioCodecKind::AacLc,
            sample_rate: rate,
            channels: 2,
            payload_type,
            audio_type: audio_type.to_string(),
            rtp_clock_rate: rate,
        };
    }

    let (rate, ch) = match bits {
        0x4 => (8_000, 1),
        0x8 => (8_000, 2),
        0x10 => (16_000, 1),
        0x20 => (16_000, 2),
        0x40 => (24_000, 1),
        0x80 => (24_000, 2),
        0x100 => (32_000, 1),
        0x200 => (32_000, 2),
        0x400 => (44_100, 1),
        0x800 => (44_100, 2),
        0x4000 => (48_000, 1),
        0x8000 => (48_000, 2),
        _ => (48_000, 2),
    };
    AudioFormat {
        codec: AudioCodecKind::Lpcm,
        sample_rate: rate,
        channels: ch,
        payload_type,
        audio_type: audio_type.to_string(),
        rtp_clock_rate: rate,
    }
}

/// Decrypts a single wire CarPlay audio UDP datagram (`[12B RTP][ciphertext][16B tag][8B nonce]`).
pub fn decrypt_audio_datagram(key: &[u8; 32], wire: &[u8]) -> Result<(Vec<u8>, u32), CryptoError> {
    const RTP_HEADER_LEN: usize = 12;
    const TAIL_LEN: usize = 16 + 8;
    if wire.len() < RTP_HEADER_LEN + TAIL_LEN {
        return Err(CryptoError::InvalidLength);
    }
    let aad = &wire[4..RTP_HEADER_LEN];
    let sealed_end = wire.len() - 8;
    let sealed = &wire[RTP_HEADER_LEN..sealed_end];
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&wire[sealed_end..]);
    let sample_ts = u32::from_be_bytes(wire[4..8].try_into().unwrap());
    let plain_payload = chacha_open(key, &nonce, sealed, aad)?;
    let mut rtp = Vec::with_capacity(RTP_HEADER_LEN + plain_payload.len());
    rtp.extend_from_slice(&wire[..RTP_HEADER_LEN]);
    rtp.extend_from_slice(&plain_payload);
    Ok((rtp, sample_ts))
}

/// UDP RTP + RTCP receiver for one CarPlay audio stream (`100` / `101` / `102`).
pub struct AudioStream {
    closed: Arc<AtomicBool>,
    data_thread: Option<JoinHandle<()>>,
    ctrl_thread: Option<JoinHandle<()>>,
}

impl AudioStream {
    pub fn listen<FRtp>(
        key: [u8; 32],
        bind_addr: SocketAddr,
        mut on_rtp: FRtp,
    ) -> std::io::Result<(Self, u16, u16)>
    where
        FRtp: FnMut(&[u8], u32, bool) + Send + 'static,
    {
        let mut addr = bind_addr;
        addr.set_port(0);
        let data_sock = UdpSocket::bind(addr)?;
        data_sock.set_read_timeout(Some(Duration::from_millis(250)))?;
        let ctrl_sock = UdpSocket::bind(addr)?;
        ctrl_sock.set_read_timeout(Some(Duration::from_millis(250)))?;

        let data_port = data_sock.local_addr()?.port();
        let ctrl_port = ctrl_sock.local_addr()?.port();
        let closed = Arc::new(AtomicBool::new(false));

        let c1 = Arc::clone(&closed);
        let data_thread = thread::Builder::new()
            .name("carplay-audio-rx".into())
            .spawn(move || {
                let mut buf = [0u8; 4096];
                let mut first = true;
                while !c1.load(Ordering::Relaxed) {
                    let Ok((n, _)) = data_sock.recv_from(&mut buf) else {
                        continue;
                    };
                    if let Ok((rtp, sample)) = decrypt_audio_datagram(&key, &buf[..n]) {
                        on_rtp(&rtp, sample, first);
                        first = false;
                    }
                }
            })?;

        let c2 = Arc::clone(&closed);
        let ctrl_thread = thread::Builder::new()
            .name("carplay-rtcp-rx".into())
            .spawn(move || {
                let mut buf = [0u8; 1024];
                while !c2.load(Ordering::Relaxed) {
                    let _ = ctrl_sock.recv_from(&mut buf);
                }
            })?;

        Ok((
            Self {
                closed,
                data_thread: Some(data_thread),
                ctrl_thread: Some(ctrl_thread),
            },
            data_port,
            ctrl_port,
        ))
    }

    pub fn stop(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
        if let Some(t) = self.data_thread.take() {
            let _ = t.join();
        }
        if let Some(t) = self.ctrl_thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for AudioStream {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Receive-only iAP2-over-CarPlay DataStream tunnel (`type = 130`, `UUID = E9459FD0-BCAD-4C45-820F-1E72447EF2F2`).
pub struct IapTunnel {
    closed: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl IapTunnel {
    pub const UUID: &'static str = "E9459FD0-BCAD-4C45-820F-1E72447EF2F2";
    const PACKAGE_HEADER_LEN: usize = 32;
    const MSG_TYPE_COMM: u32 = 0x636f6d6d; // "comm"

    pub fn listen<FIap>(
        read_key: [u8; 32],
        bind_addr: SocketAddr,
        mut on_iap_bytes: FIap,
    ) -> std::io::Result<(Self, u16)>
    where
        FIap: FnMut(&[u8]) + Send + 'static,
    {
        let mut addr = bind_addr;
        addr.set_port(0);
        let listener = TcpListener::bind(addr)?;
        let s = socket2::SockRef::from(&listener);
        let _ = s.set_recv_buffer_size(2 * 1024 * 1024);
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let closed = Arc::new(AtomicBool::new(false));
        let closed_bg = Arc::clone(&closed);

        let thread = thread::Builder::new()
            .name("carplay-iap-tunnel".into())
            .spawn(move || {
                let mut accepted = None;
                while !closed_bg.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((sock, _)) => {
                            let _ = sock.set_nonblocking(false);
                            let _ = sock.set_read_timeout(Some(Duration::from_millis(500)));
                            accepted = Some(sock);
                            break;
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => return,
                    }
                }
                let Some(mut sock) = accepted else {
                    return;
                };

                let mut read_counter = 0u64;
                let mut cipher_buf = Vec::new();
                let mut plain_buf = Vec::new();
                let mut chunk = [0u8; 8192];

                while !closed_bg.load(Ordering::Relaxed) {
                    match sock.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => {
                            cipher_buf.extend_from_slice(&chunk[..n]);
                            // Decrypt ControlCipher-framed chunks
                            let mut off = 0usize;
                            while cipher_buf.len() - off >= 2 {
                                let len =
                                    u16::from_le_bytes([cipher_buf[off], cipher_buf[off + 1]])
                                        as usize;
                                let frame_len = 2 + len + 16;
                                if cipher_buf.len() - off < frame_len {
                                    break;
                                }
                                let aad = &cipher_buf[off..off + 2];
                                let sealed = &cipher_buf[off + 2..off + frame_len];
                                let Ok(dec) = chacha_open(
                                    &read_key,
                                    &nonce64(read_counter),
                                    sealed,
                                    aad,
                                ) else {
                                    return;
                                };
                                read_counter += 1;
                                plain_buf.extend_from_slice(&dec);
                                off += frame_len;
                            }
                            cipher_buf.drain(..off);

                            // Parse 32-byte APTransportPackage headers
                            let mut pkg_off = 0usize;
                            while plain_buf.len() - pkg_off >= Self::PACKAGE_HEADER_LEN {
                                let pkg_size = u32::from_be_bytes(
                                    plain_buf[pkg_off..pkg_off + 4].try_into().unwrap(),
                                ) as usize;
                                if !(Self::PACKAGE_HEADER_LEN..=4 * 1024 * 1024).contains(&pkg_size)
                                {
                                    return;
                                }
                                if plain_buf.len() - pkg_off < pkg_size {
                                    break;
                                }
                                let msg_type = u32::from_be_bytes(
                                    plain_buf[pkg_off + 16..pkg_off + 20].try_into().unwrap(),
                                );
                                if msg_type == Self::MSG_TYPE_COMM {
                                    on_iap_bytes(
                                        &plain_buf[pkg_off + Self::PACKAGE_HEADER_LEN
                                            ..pkg_off + pkg_size],
                                    );
                                }
                                pkg_off += pkg_size;
                            }
                            plain_buf.drain(..pkg_off);
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
            })?;

        Ok((
            Self {
                closed,
                thread: Some(thread),
            },
            port,
        ))
    }

    pub fn stop(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for IapTunnel {
    fn drop(&mut self) {
        self.stop();
    }
}

fn read_exact_interruptible<R: Read>(
    sock: &mut R,
    mut buf: &mut [u8],
    closed: &AtomicBool,
) -> bool {
    while !buf.is_empty() {
        if closed.load(Ordering::Relaxed) {
            return false;
        }
        match sock.read(buf) {
            Ok(0) => return false,
            Ok(n) => buf = &mut buf[n..],
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::Interrupted =>
            {
                continue;
            }
            Err(_) => return false,
        }
    }
    true
}
