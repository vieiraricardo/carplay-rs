//! Full CarPlay RTSP/AirPlay control server (`AirPlayServer`), reverse `eventPort` channel,
//! media/tunnel stream lifecycle, and thread-safe `AirPlayControlHandle` for HID touch/knob/Siri commands.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use carplay_mfi::MfiAuthenticator;
use indexmap::IndexMap;

use crate::bplist::{self, PlistValue};
use crate::crypto::{hkdf_sha512, AirPlayIdentity, PairingStore};
use crate::hid::{
    encode_knob_report, encode_media_report, encode_telephony_report, encode_touch_report,
    AirPlayContact, AirPlayKnobState, TouchSlotAssigner, KNOB_HID_UID, MEDIA_HID_UID,
    TELEPHONY_HID_UID, TOUCH_HID_UID,
};
use crate::info_plist::{build_info_plist, AirPlayConfig, ALT_DISPLAY_UUID};
use crate::ntp_clock::NtpClock;
use crate::pairing::{ControlCipher, MfiSapAuthSetup, PairSetup, PairVerify};
use crate::plist_dict;
use crate::rtsp::{self, RtspRequest, RtspResponse};
use crate::streams::{
    audio_format_from_bits, AudioFormat, AudioStream, AudioStreamId, IapTunnel, ScreenStream,
    VideoCodec,
};

pub const STREAM_MAIN_SCREEN: u16 = 110;
pub const STREAM_ALT_SCREEN: u16 = 111;
pub const STREAM_MAIN_AUDIO: u16 = 100;
pub const STREAM_ALT_AUDIO: u16 = 101;
pub const STREAM_MAIN_HIGH_AUDIO: u16 = 102;
pub const STREAM_DATA_TUNNEL: u16 = 130;

const PLIST_MIME: &str = "application/x-apple-binary-plist";
const PAIRING_MIME: &str = "application/pairing+tlv8";
const OCTET_MIME: &str = "application/octet-stream";

/// Platform rendering & telemetry callbacks invoked by `AirPlayServer` as CarPlay streams arrive.
pub trait MediaSink: Send + Sync + 'static {
    fn on_session_started(&self, _peer: SocketAddr) {}
    fn on_device_info(&self, _name: &str, _model: &str, _device_id: &str) {}
    fn on_video_codec(&self, _stream_type: u16, _codec: VideoCodec) {}
    fn on_video_config(
        &self,
        _stream_type: u16,
        _raw_config: &[u8],
        _annex_b_sps_pps: Option<&[u8]>,
    ) {
    }
    fn on_video_frame(
        &self,
        _stream_type: u16,
        _annex_b_nalus: &[u8],
        _sender_nanos: u64,
        _arrival: Instant,
    ) {
    }
    fn on_audio_started(&self, _id: &AudioStreamId, _format: &AudioFormat, _first_sample: u32) {}
    fn on_audio_rtp(
        &self,
        _id: &AudioStreamId,
        _format: &AudioFormat,
        _rtp_packet: &[u8],
        _sample_ts: u32,
    ) {
    }
    fn on_audio_stopped(&self, _id: &AudioStreamId) {}
    fn on_audio_duck(&self, _ducked: bool) {}
    fn on_iap_message(&self, _bytes: &[u8]) {}
    fn on_command(&self, _cmd_type: &str, _params: &IndexMap<String, PlistValue>) {}
    fn on_session_ended(&self) {}
}

struct EventChannelWriter {
    stream: TcpStream,
    cipher: ControlCipher,
    cseq: u32,
}

struct ActiveControlState {
    config: AirPlayConfig,
    touch_slots: TouchSlotAssigner,
    event_writer: Option<EventChannelWriter>,
    pending_night_mode: Option<bool>,
}

/// Thread-safe handle used by the UI / `evdev` touch driver / steering wheel keys to send commands to the active iPhone.
#[derive(Clone)]
pub struct AirPlayControlHandle {
    inner: Arc<Mutex<ActiveControlState>>,
}

impl AirPlayControlHandle {
    pub fn new(config: AirPlayConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ActiveControlState {
                config,
                touch_slots: TouchSlotAssigner::new(),
                event_writer: None,
                pending_night_mode: None,
            })),
        }
    }

    pub fn is_event_ready(&self) -> bool {
        self.inner.lock().unwrap().event_writer.is_some()
    }

    /// Sends normalized (`0.0..=1.0`) touch contacts over the encrypted `eventPort` channel.
    pub fn send_touch(&self, normalized_contacts: &[AirPlayContact]) -> bool {
        let mut guard = self.inner.lock().unwrap();
        let w = f64::from(guard.config.main_display.width_pixels);
        let h = f64::from(guard.config.main_display.height_pixels);
        let assigned = guard.touch_slots.assign(normalized_contacts);
        let scaled: Vec<AirPlayContact> = assigned
            .into_iter()
            .map(|c| AirPlayContact {
                id: c.id,
                x: c.x * w,
                y: c.y * h,
                down: c.down,
            })
            .collect();
        let report = encode_touch_report(&scaled);
        Self::send_hid_locked(&mut guard, TOUCH_HID_UID, &report)
    }

    pub fn send_knob(&self, state: AirPlayKnobState, momentary: bool) -> bool {
        let mut guard = self.inner.lock().unwrap();
        let ok = Self::send_hid_locked(&mut guard, KNOB_HID_UID, &encode_knob_report(state));
        if momentary && ok {
            let _ = Self::send_hid_locked(
                &mut guard,
                KNOB_HID_UID,
                &encode_knob_report(AirPlayKnobState::default()),
            );
        }
        ok
    }

    pub fn send_media_button(&self, usage_index: u8) -> bool {
        let mut guard = self.inner.lock().unwrap();
        let ok =
            Self::send_hid_locked(&mut guard, MEDIA_HID_UID, &encode_media_report(usage_index));
        if ok {
            let _ = Self::send_hid_locked(&mut guard, MEDIA_HID_UID, &encode_media_report(0));
        }
        ok
    }

    pub fn send_telephony_button(&self, usage_index: u8) -> bool {
        let mut guard = self.inner.lock().unwrap();
        let ok = Self::send_hid_locked(
            &mut guard,
            TELEPHONY_HID_UID,
            &encode_telephony_report(usage_index),
        );
        if ok {
            let _ =
                Self::send_hid_locked(&mut guard, TELEPHONY_HID_UID, &encode_telephony_report(0));
        }
        ok
    }

    pub fn invoke_siri(&self) -> bool {
        let mut guard = self.inner.lock().unwrap();
        let ok1 = Self::send_command_locked(
            &mut guard,
            &plist_dict! {
                "type" => "requestSiri",
                "params" => plist_dict! { "siriAction" => 2u64 },
            },
        );
        let ok2 = Self::send_command_locked(
            &mut guard,
            &plist_dict! {
                "type" => "requestSiri",
                "params" => plist_dict! { "siriAction" => 3u64 },
            },
        );
        ok1 && ok2
    }

    pub fn set_night_mode(&self, night: bool) -> bool {
        let mut guard = self.inner.lock().unwrap();
        guard.pending_night_mode = Some(night);
        Self::flush_pending_night_mode_locked(&mut guard)
    }

    pub fn request_keyframe(&self, cluster: bool) -> bool {
        let mut guard = self.inner.lock().unwrap();
        let cmd = if cluster {
            plist_dict! {
                "type" => "forceKeyFrame",
                "params" => plist_dict! { "uuid" => ALT_DISPLAY_UUID },
            }
        } else {
            plist_dict! { "type" => "forceKeyFrame" }
        };
        Self::send_command_locked(&mut guard, &cmd)
    }

    pub fn send_iap_message(&self, csm_bytes: &[u8]) -> bool {
        let mut guard = self.inner.lock().unwrap();
        let cmd = plist_dict! {
            "type" => "iAPSendMessage",
            "params" => plist_dict! { "data" => csm_bytes.to_vec() },
        };
        Self::send_command_locked(&mut guard, &cmd)
    }

    fn send_hid_locked(guard: &mut ActiveControlState, uid: u32, report: &[u8]) -> bool {
        let cmd = plist_dict! {
            "type" => "hidSendReport",
            "uuid" => format!("{uid:x}"),
            "hidReport" => report.to_vec(),
        };
        Self::send_command_locked(guard, &cmd)
    }

    fn flush_pending_night_mode_locked(guard: &mut ActiveControlState) -> bool {
        let Some(night) = guard.pending_night_mode else {
            return true;
        };
        if guard.event_writer.is_none() {
            return false;
        }
        let cmd = plist_dict! {
            "type" => "setNightMode",
            "params" => plist_dict! { "nightMode" => night },
        };
        if Self::send_command_locked(guard, &cmd) {
            guard.pending_night_mode = None;
            true
        } else {
            false
        }
    }

    fn send_command_locked(guard: &mut ActiveControlState, cmd: &PlistValue) -> bool {
        let Some(writer) = guard.event_writer.as_mut() else {
            return false;
        };
        writer.cseq = writer.cseq.wrapping_add(1);
        let body = bplist::encode(cmd);
        let raw_req = rtsp::build_request(
            "POST",
            "/command",
            writer.cseq,
            Some(PLIST_MIME),
            &[],
            &body,
        );
        let Ok(encrypted) = writer.cipher.encrypt(&raw_req) else {
            return false;
        };
        if writer.stream.write_all(&encrypted).is_ok() && writer.stream.flush().is_ok() {
            true
        } else {
            guard.event_writer = None;
            false
        }
    }

    fn attach_event_writer(&self, writer: EventChannelWriter) {
        let mut guard = self.inner.lock().unwrap();
        guard.event_writer = Some(writer);
        Self::flush_pending_night_mode_locked(&mut guard);
    }

    fn clear_event_writer(&self) {
        self.inner.lock().unwrap().event_writer = None;
    }
}

struct ActiveAudioFeedback {
    stream_type: u16,
    rtp_clock_rate: u32,
    connection_id: u64,
    latency_ms: u32,
    first_sample: Arc<Mutex<Option<(u32, Instant)>>>,
}

/// CarPlay TCP RTSP/AirPlay server listening on port 7000 (or dynamic port `0`).
pub struct AirPlayServer {
    port: u16,
    running: Arc<AtomicBool>,
    control_handle: AirPlayControlHandle,
    accept_thread: Option<JoinHandle<()>>,
}

impl AirPlayServer {
    /// Binds a dual-stack IPv6 + IPv4 listener (`[::]:port` with `IPV6_V6ONLY = false`),
    /// accepting both USB CDC-NCM IPv6 link-local (`fe80::...`) and Wi-Fi/loopback IPv4 peers.
    pub fn bind_dual_stack(
        port: u16,
        config: AirPlayConfig,
        identity: AirPlayIdentity,
        pairings: PairingStore,
        mfi: Arc<dyn MfiAuthenticator>,
        sink: Arc<dyn MediaSink>,
    ) -> std::io::Result<Self> {
        let listener = bind_dual_stack_tcp(port)
            .or_else(|_| TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port))))?;
        Self::from_listener(listener, config, identity, pairings, mfi, sink)
    }

    pub fn bind(
        bind_addr: SocketAddr,
        config: AirPlayConfig,
        identity: AirPlayIdentity,
        pairings: PairingStore,
        mfi: Arc<dyn MfiAuthenticator>,
        sink: Arc<dyn MediaSink>,
    ) -> std::io::Result<Self> {
        let listener = if bind_addr.ip().is_unspecified() && bind_addr.is_ipv6() {
            bind_dual_stack_tcp(bind_addr.port()).or_else(|_| TcpListener::bind(bind_addr))?
        } else {
            TcpListener::bind(bind_addr)?
        };
        Self::from_listener(listener, config, identity, pairings, mfi, sink)
    }

    fn from_listener(
        listener: TcpListener,
        config: AirPlayConfig,
        identity: AirPlayIdentity,
        pairings: PairingStore,
        mfi: Arc<dyn MfiAuthenticator>,
        sink: Arc<dyn MediaSink>,
    ) -> std::io::Result<Self> {
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let running = Arc::new(AtomicBool::new(true));
        let running_bg = Arc::clone(&running);
        let control_handle = AirPlayControlHandle::new(config.clone());
        let handle_bg = control_handle.clone();

        let accept_thread = thread::Builder::new()
            .name("carplay-airplay-accept".into())
            .spawn(move || {
                while running_bg.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, peer)) => {
                            let _ = stream.set_nonblocking(false);
                            let _ = stream.set_nodelay(true);
                            let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                            let cfg = config.clone();
                            let id = identity.clone();
                            let ps = pairings.clone();
                            let mfi_c = Arc::clone(&mfi);
                            let sink_c = Arc::clone(&sink);
                            let h_c = handle_bg.clone();
                            let run_c = Arc::clone(&running_bg);
                            thread::Builder::new()
                                .name(format!("carplay-session-{peer}"))
                                .spawn(move || {
                                    run_session(stream, peer, cfg, id, ps, mfi_c, sink_c, h_c, run_c);
                                })
                                .ok();
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(15));
                        }
                        Err(_) => break,
                    }
                }
            })?;

        Ok(Self {
            port,
            running,
            control_handle,
            accept_thread: Some(accept_thread),
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn control_handle(&self) -> AirPlayControlHandle {
        self.control_handle.clone()
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(t) = self.accept_thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for AirPlayServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn bind_dual_stack_tcp(port: u16) -> std::io::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let sock = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    let _ = sock.set_only_v6(false);
    let _ = sock.set_reuse_address(true);
    let addr = SocketAddr::from(([0u16; 8], port));
    sock.bind(&addr.into())?;
    sock.listen(16)?;
    Ok(sock.into())
}

fn normalize_local_bind_addr(raw: std::io::Result<SocketAddr>) -> SocketAddr {
    match raw {
        Ok(mut addr) => {
            addr.set_port(0);
            if let IpAddr::V6(v6) = addr.ip() {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    return SocketAddr::new(IpAddr::V4(v4), 0);
                }
            }
            addr
        }
        Err(_) => "0.0.0.0:0".parse().unwrap(),
    }
}

#[allow(clippy::too_many_arguments)]
fn run_session(
    mut socket: TcpStream,
    peer: SocketAddr,
    config: AirPlayConfig,
    identity: AirPlayIdentity,
    pairings: PairingStore,
    mfi: Arc<dyn MfiAuthenticator>,
    sink: Arc<dyn MediaSink>,
    control_handle: AirPlayControlHandle,
    server_running: Arc<AtomicBool>,
) {
    sink.on_session_started(peer);
    let local_bind_addr = normalize_local_bind_addr(socket.local_addr());

    let mut pair_setup = PairSetup::new(identity.clone(), pairings.clone());
    let mut pair_verify = PairVerify::new(identity, pairings);
    let mut control_cipher: Option<ControlCipher> = None;

    let mut ntp = NtpClock::new();
    let mut keepalive_sock: Option<UdpSocket> = None;
    let mut screen_streams: HashMap<u16, ScreenStream> = HashMap::new();
    let mut audio_streams: HashMap<(u16, String), AudioStream> = HashMap::new();
    let mut audio_feedback: HashMap<(u16, String), ActiveAudioFeedback> = HashMap::new();
    let mut iap_tunnel: Option<IapTunnel> = None;
    let event_closed = Arc::new(AtomicBool::new(false));

    let mut enc_buf = Vec::new();
    let mut plain_buf = Vec::new();
    let mut read_chunk = [0u8; 16 * 1024];

    while server_running.load(Ordering::Relaxed) {
        match socket.read(&mut read_chunk) {
            Ok(0) => break,
            Ok(n) => {
                if let Some(cipher) = control_cipher.as_mut() {
                    enc_buf.extend_from_slice(&read_chunk[..n]);
                    let Ok(dec) = cipher.decrypt(&enc_buf) else {
                        tracing::warn!("AirPlay control decrypt failed from {peer}");
                        break;
                    };
                    enc_buf = dec.rest;
                    plain_buf.extend_from_slice(&dec.plaintext);
                } else {
                    plain_buf.extend_from_slice(&read_chunk[..n]);
                }

                let batch = rtsp::parse_messages(&plain_buf);
                plain_buf = batch.rest;

                for req in batch.messages {
                    let resp = dispatch_request(
                        &req,
                        peer,
                        local_bind_addr,
                        &config,
                        &mut pair_setup,
                        &mut pair_verify,
                        &*mfi,
                        &sink,
                        &control_handle,
                        &mut ntp,
                        &mut keepalive_sock,
                        &mut screen_streams,
                        &mut audio_streams,
                        &mut audio_feedback,
                        &mut iap_tunnel,
                        &event_closed,
                    );

                    let wire = rtsp::build_response(&req, &resp);
                    let out_bytes = if let Some(cipher) = control_cipher.as_mut() {
                        let Ok(enc) = cipher.encrypt(&wire) else {
                            break;
                        };
                        enc
                    } else {
                        wire
                    };

                    if socket.write_all(&out_bytes).is_err() || socket.flush().is_err() {
                        break;
                    }

                    // Activate ControlCipher immediately AFTER sending plaintext /pair-verify M4 response!
                    if control_cipher.is_none() {
                        if let Some(keys) = pair_verify.control_keys() {
                            control_cipher = Some(ControlCipher::new(keys.read_key, keys.write_key));
                            tracing::info!("AirPlay ControlCipher enabled for {peer}");
                        }
                    }
                }
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::Interrupted =>
            {
                continue;
            }
            Err(_) => break,
        }
    }

    event_closed.store(true, Ordering::SeqCst);
    control_handle.clear_event_writer();
    ntp.stop();
    drop(keepalive_sock);
    screen_streams.clear();
    audio_streams.clear();
    audio_feedback.clear();
    drop(iap_tunnel);
    sink.on_session_ended();
}

#[allow(clippy::too_many_arguments)]
fn dispatch_request(
    req: &RtspRequest,
    peer: SocketAddr,
    local_bind_addr: SocketAddr,
    config: &AirPlayConfig,
    pair_setup: &mut PairSetup,
    pair_verify: &mut PairVerify,
    mfi: &dyn MfiAuthenticator,
    sink: &Arc<dyn MediaSink>,
    control_handle: &AirPlayControlHandle,
    ntp: &mut NtpClock,
    keepalive_sock: &mut Option<UdpSocket>,
    screen_streams: &mut HashMap<u16, ScreenStream>,
    audio_streams: &mut HashMap<(u16, String), AudioStream>,
    audio_feedback: &mut HashMap<(u16, String), ActiveAudioFeedback>,
    iap_tunnel: &mut Option<IapTunnel>,
    event_closed: &Arc<AtomicBool>,
) -> RtspResponse {
    match req.method.as_str() {
        "SETUP" => {
            return handle_setup(
                req,
                peer,
                local_bind_addr,
                config,
                pair_verify.shared_secret(),
                sink,
                control_handle,
                ntp,
                keepalive_sock,
                screen_streams,
                audio_streams,
                audio_feedback,
                iap_tunnel,
                event_closed,
            );
        }
        "RECORD" | "SET_PARAMETER" | "GET_PARAMETER" | "OPTIONS" | "FLUSH" => {
            return RtspResponse::ok();
        }
        "TEARDOWN" => {
            if let Ok(PlistValue::Dict(dict)) = bplist::decode(&req.body) {
                if let Some(PlistValue::Array(streams)) = dict.get("streams") {
                    for s in streams {
                        if let Some(sd) = s.as_dict() {
                            if let Some(t) = sd.get("type").and_then(|v| v.as_u64()) {
                                let t16 = t as u16;
                                screen_streams.remove(&t16);
                                audio_streams.retain(|(st, at), _| {
                                    if *st == t16 {
                                        sink.on_audio_stopped(&AudioStreamId {
                                            stream_type: *st,
                                            audio_type: at.clone(),
                                        });
                                        false
                                    } else {
                                        true
                                    }
                                });
                                audio_feedback.retain(|(st, _), _| *st != t16);
                                if t16 == STREAM_DATA_TUNNEL {
                                    *iap_tunnel = None;
                                }
                            }
                        }
                    }
                    return RtspResponse::ok();
                }
            }
            screen_streams.clear();
            audio_streams.clear();
            audio_feedback.clear();
            *iap_tunnel = None;
            return RtspResponse::ok();
        }
        _ => {}
    }

    let path = req.path.to_ascii_lowercase();
    if path.ends_with("/pair-setup") {
        return RtspResponse::with_body(PAIRING_MIME, pair_setup.handle(&req.body));
    }
    if path.ends_with("/pair-verify") {
        return RtspResponse::with_body(PAIRING_MIME, pair_verify.handle(&req.body));
    }
    if path.ends_with("/auth-setup") {
        return match MfiSapAuthSetup::handle(&req.body, mfi) {
            Some(body) => RtspResponse::with_body(OCTET_MIME, body),
            None => RtspResponse::with_status(400),
        };
    }
    if path.ends_with("/info") {
        let info = build_info_plist(config);
        return RtspResponse::with_body(PLIST_MIME, bplist::encode(&info));
    }
    if req.method == "POST" && path.ends_with("/command") {
        if let Ok(PlistValue::Dict(body)) = bplist::decode(&req.body) {
            let cmd_type = body.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let empty = IndexMap::new();
            let params = body
                .get("params")
                .and_then(|v| v.as_dict())
                .unwrap_or(&empty);
            match cmd_type {
                "duckAudio" => sink.on_audio_duck(true),
                "unduckAudio" => sink.on_audio_duck(false),
                _ => {}
            }
            sink.on_command(cmd_type, params);
        }
        return RtspResponse::ok();
    }
    if req.method == "POST" && path.ends_with("/feedback") {
        if audio_feedback.is_empty() {
            return RtspResponse::ok();
        }
        let mut entries = Vec::new();
        for fb in audio_feedback.values() {
            let mut m = IndexMap::new();
            m.insert(
                "type".to_string(),
                PlistValue::Uint(u64::from(fb.stream_type)),
            );
            m.insert(
                "sampleRate".to_string(),
                PlistValue::Uint(u64::from(fb.rtp_clock_rate)),
            );
            if let Some((first_sample, origin)) = *fb.first_sample.lock().unwrap() {
                let elapsed_s =
                    (origin.elapsed().as_secs_f64() - f64::from(fb.latency_ms) / 1000.0).max(0.0);
                let sample_time = u64::from(first_sample)
                    .wrapping_add((elapsed_s * f64::from(fb.rtp_clock_rate)).round() as u64)
                    & 0xFFFF_FFFF;
                m.insert(
                    "streamConnectionID".to_string(),
                    PlistValue::Uint(fb.connection_id),
                );
                m.insert("timestamp".to_string(), PlistValue::Uint(ntp.synced_ntp64()));
                m.insert("sampleTime".to_string(), PlistValue::Uint(sample_time));
            }
            entries.push(PlistValue::Dict(m));
        }
        let resp_plist = plist_dict! { "streams" => PlistValue::Array(entries) };
        return RtspResponse::with_body(PLIST_MIME, bplist::encode(&resp_plist));
    }

    RtspResponse::ok()
}

#[allow(clippy::too_many_arguments)]
fn handle_setup(
    req: &RtspRequest,
    peer: SocketAddr,
    local_bind_addr: SocketAddr,
    config: &AirPlayConfig,
    shared_secret: Option<[u8; 32]>,
    sink: &Arc<dyn MediaSink>,
    control_handle: &AirPlayControlHandle,
    ntp: &mut NtpClock,
    keepalive_sock: &mut Option<UdpSocket>,
    screen_streams: &mut HashMap<u16, ScreenStream>,
    audio_streams: &mut HashMap<(u16, String), AudioStream>,
    audio_feedback: &mut HashMap<(u16, String), ActiveAudioFeedback>,
    iap_tunnel: &mut Option<IapTunnel>,
    event_closed: &Arc<AtomicBool>,
) -> RtspResponse {
    let Ok(PlistValue::Dict(dict)) = bplist::decode(&req.body) else {
        return RtspResponse::with_status(400);
    };

    // Second-phase SETUP: stream allocation (`streams` array)
    if let Some(PlistValue::Array(streams)) = dict.get("streams") {
        let Some(shared) = shared_secret else {
            return RtspResponse::with_status(400);
        };
        let mut resp_streams = Vec::new();
        for item in streams {
            let Some(sd) = item.as_dict() else {
                continue;
            };
            let Some(st_u64) = sd.get("type").and_then(|v| v.as_u64()) else {
                continue;
            };
            let st = st_u64 as u16;
            match st {
                STREAM_MAIN_SCREEN | STREAM_ALT_SCREEN => {
                    let conn_id = sd
                        .get("streamConnectionID")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    let key = hkdf_sha512(
                        &shared,
                        format!("DataStream-Salt{conn_id}").as_bytes(),
                        b"DataStream-Output-Encryption-Key",
                    );
                    let s1 = Arc::clone(sink);
                    let s2 = Arc::clone(sink);
                    let s3 = Arc::clone(sink);
                    if let Ok((stream_obj, port)) = ScreenStream::listen(
                        key,
                        local_bind_addr,
                        move |codec| s1.on_video_codec(st, codec),
                        move |raw, annex_b| s2.on_video_config(st, raw, annex_b),
                        move |nalus, sender_ns, arrival| {
                            s3.on_video_frame(st, &nalus, sender_ns, arrival)
                        },
                    ) {
                        screen_streams.insert(st, stream_obj);
                        resp_streams.push(plist_dict! {
                            "type" => u64::from(st),
                            "dataPort" => u64::from(port),
                        });
                    }
                }
                STREAM_MAIN_AUDIO | STREAM_ALT_AUDIO | STREAM_MAIN_HIGH_AUDIO => {
                    let audio_type = sd
                        .get("audioType")
                        .and_then(|v| v.as_str())
                        .unwrap_or("default")
                        .to_ascii_lowercase();
                    let conn_id = sd
                        .get("streamConnectionID")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    let fmt_bits = sd.get("audioFormat").and_then(|v| v.as_u64()).unwrap_or(0);
                    let latency_ms = sd
                        .get("audioLatencyMs")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32;
                    let fmt = audio_format_from_bits(fmt_bits, st, &audio_type);
                    let key = hkdf_sha512(
                        &shared,
                        format!("DataStream-Salt{conn_id}").as_bytes(),
                        b"DataStream-Output-Encryption-Key",
                    );

                    let first_sample = Arc::new(Mutex::new(None));
                    let first_bg = Arc::clone(&first_sample);
                    let sink_bg = Arc::clone(sink);
                    let stream_id = AudioStreamId {
                        stream_type: st,
                        audio_type: audio_type.clone(),
                    };
                    let fmt_bg = fmt.clone();

                    if let Ok((audio_obj, data_port, ctrl_port)) =
                        AudioStream::listen(key, local_bind_addr, move |rtp, sample_ts, is_first| {
                            if is_first {
                                *first_bg.lock().unwrap() = Some((sample_ts, Instant::now()));
                                sink_bg.on_audio_started(&stream_id, &fmt_bg, sample_ts);
                            }
                            sink_bg.on_audio_rtp(&stream_id, &fmt_bg, rtp, sample_ts);
                        })
                    {
                        audio_streams.insert((st, audio_type.clone()), audio_obj);
                        audio_feedback.insert(
                            (st, audio_type),
                            ActiveAudioFeedback {
                                stream_type: st,
                                rtp_clock_rate: fmt.rtp_clock_rate,
                                connection_id: conn_id,
                                latency_ms,
                                first_sample,
                            },
                        );
                        resp_streams.push(plist_dict! {
                            "type" => u64::from(st),
                            "dataPort" => u64::from(data_port),
                            "controlPort" => u64::from(ctrl_port),
                        });
                    }
                }
                STREAM_DATA_TUNNEL => {
                    let uuid = sd
                        .get("clientTypeUUID")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if uuid.eq_ignore_ascii_case(IapTunnel::UUID) {
                        let seed = sd.get("seed").and_then(|v| v.as_u64()).unwrap_or(0);
                        let key = hkdf_sha512(
                            &shared,
                            format!("DataStream-Salt{seed}").as_bytes(),
                            b"DataStream-Output-Encryption-Key",
                        );
                        let sink_bg = Arc::clone(sink);
                        if let Ok((tunnel_obj, port)) =
                            IapTunnel::listen(key, local_bind_addr, move |iap| {
                                sink_bg.on_iap_message(iap);
                            })
                        {
                            *iap_tunnel = Some(tunnel_obj);
                            let mut entry = IndexMap::new();
                            entry.insert("type".to_string(), PlistValue::Uint(u64::from(st)));
                            entry.insert("streamID".to_string(), PlistValue::Uint(1));
                            entry.insert("dataPort".to_string(), PlistValue::Uint(u64::from(port)));
                            if let Some(cid) = sd.get("streamConnectionID").and_then(|v| v.as_u64())
                            {
                                entry.insert(
                                    "streamConnectionID".to_string(),
                                    PlistValue::Uint(cid),
                                );
                            }
                            resp_streams.push(PlistValue::Dict(entry));
                        }
                    }
                }
                _ => {}
            }
        }
        let body = plist_dict! { "streams" => PlistValue::Array(resp_streams) };
        return RtspResponse::with_body(PLIST_MIME, bplist::encode(&body));
    }

    // First-phase SETUP: session initialization (`timingPort`, `eventPort`, `enabledFeatures`)
    let dev_name = dict.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let dev_model = dict.get("model").and_then(|v| v.as_str()).unwrap_or("");
    let dev_id = dict.get("deviceID").and_then(|v| v.as_str()).unwrap_or("");
    if !dev_name.is_empty() || !dev_model.is_empty() {
        sink.on_device_info(dev_name, dev_model, dev_id);
    }

    let peer_timing_port = dict
        .get("timingPort")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u16;
    let peer_timing = (peer_timing_port > 0).then(|| {
        let mut a = peer;
        a.set_port(peer_timing_port);
        if let IpAddr::V6(v6) = a.ip() {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return SocketAddr::new(IpAddr::V4(v4), peer_timing_port);
            }
        }
        a
    });
    let timing_port = ntp
        .bind_and_start(local_bind_addr, peer_timing)
        .unwrap_or(0);

    let event_port = match shared_secret {
        Some(shared) => spawn_event_server(
            local_bind_addr,
            shared,
            control_handle.clone(),
            Arc::clone(event_closed),
        )
        .unwrap_or(0),
        None => 0,
    };

    let mut resp = IndexMap::new();
    resp.insert(
        "timingPort".to_string(),
        PlistValue::Uint(u64::from(timing_port)),
    );
    resp.insert(
        "eventPort".to_string(),
        PlistValue::Uint(u64::from(event_port)),
    );

    if dict
        .get("keepAliveLowPower")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        if let Ok(ka) = UdpSocket::bind(local_bind_addr) {
            if let Ok(addr) = ka.local_addr() {
                resp.insert(
                    "keepAlivePort".to_string(),
                    PlistValue::Uint(u64::from(addr.port())),
                );
                *keepalive_sock = Some(ka);
            }
        }
    }

    let mut enabled_features = vec![
        PlistValue::from("iAPChannel"),
        PlistValue::from("viewAreas"),
    ];
    if config.hevc {
        enabled_features.insert(0, PlistValue::from("hevc"));
    }
    if config.cluster_display.is_some() {
        enabled_features.push(PlistValue::from("altScreen"));
    }
    resp.insert(
        "enabledFeatures".to_string(),
        PlistValue::Array(enabled_features),
    );

    RtspResponse::with_body(PLIST_MIME, bplist::encode(&PlistValue::Dict(resp)))
}

fn spawn_event_server(
    mut bind_addr: SocketAddr,
    shared: [u8; 32],
    control_handle: AirPlayControlHandle,
    closed: Arc<AtomicBool>,
) -> std::io::Result<u16> {
    bind_addr.set_port(0);
    let listener = TcpListener::bind(bind_addr)?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();

    thread::Builder::new()
        .name("carplay-event-channel".into())
        .spawn(move || {
            let mut accepted = None;
            while !closed.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((sock, _)) => {
                        let _ = sock.set_nonblocking(false);
                        let _ = sock.set_nodelay(true);
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
            let Some(mut rx_sock) = accepted else {
                return;
            };
            let Ok(tx_sock) = rx_sock.try_clone() else {
                return;
            };

            let write_key = hkdf_sha512(&shared, b"Events-Salt", b"Events-Write-Encryption-Key");
            let read_key = hkdf_sha512(&shared, b"Events-Salt", b"Events-Read-Encryption-Key");
            // Writer encrypts outgoing events with `write_key`; reader decrypts replies with `read_key`.
            let tx_cipher = ControlCipher::new([0u8; 32], write_key);
            let mut rx_cipher = ControlCipher::new(read_key, [0u8; 32]);

            control_handle.attach_event_writer(EventChannelWriter {
                stream: tx_sock,
                cipher: tx_cipher,
                cseq: 0,
            });

            let mut enc_buf = Vec::new();
            let mut plain_buf = Vec::new();
            let mut chunk = [0u8; 4096];
            while !closed.load(Ordering::Relaxed) {
                match rx_sock.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        enc_buf.extend_from_slice(&chunk[..n]);
                        let Ok(dec) = rx_cipher.decrypt(&enc_buf) else {
                            break;
                        };
                        enc_buf = dec.rest;
                        plain_buf.extend_from_slice(&dec.plaintext);
                        let parsed = rtsp::parse_messages(&plain_buf);
                        plain_buf = parsed.rest;
                    }
                    Err(ref e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut
                            || e.kind() == std::io::ErrorKind::Interrupted =>
                    {
                        continue;
                    }
                    Err(_) => break,
                }
            }
            control_handle.clear_event_writer();
        })?;

    Ok(port)
}
