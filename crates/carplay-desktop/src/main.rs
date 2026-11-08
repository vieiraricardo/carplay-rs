//! `carplay-desktop`: Interactive macOS / Linux desktop CarPlay receiver & protocol workbench.
//!
//! Features:
//! - Starts a dual-stack IPv6+IPv4 `AirPlayServer` (`[::]:7000`) for USB CDC-NCM (`fe80::...`) and Wi-Fi
//! - Automatically orchestrates Wired USB CarPlay via `/var/run/usbmuxd` -> `lockdownd` (TLS) -> `com.apple.carkit.service` -> iAP2
//! - Auto-detects CH341 USB-I2C MFi chips (`0x1A86:0x5512`), `./offline-mfi` (`--mfi-local-dir`), or `--mfi-server-url`
//! - Decodes incoming H.264 Annex-B video via `openh264` (`Flush::NoFlush` low-latency live mode) and plays LPCM audio via `cpal`
//! - Maps mouse click/drag -> CarPlay Multitouch HID (`0x2a2a2a2a`), scroll/keys -> Rotary Knob, Home, Back, Siri, Night Mode

mod font5x7;
mod sim_iphone;

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use carplay_airplay::{
    AirPlayConfig, AirPlayContact, AirPlayControlHandle, AirPlayDisplayConfig, AirPlayIdentity,
    AirPlayKnobState, AirPlayServer, AudioCodecKind, AudioFormat, AudioStreamId, CarPlayBonjour,
    MediaSink, PairingStore, VideoCodec,
};
use carplay_iap2::Iap2ControlError;
use carplay_mfi::{LocalP256MfiClient, MfiAuthenticator, MfiCertificateType, RemoteMfiClient};
use carplay_transport::{
    discover_ncm_interfaces, list_usb_devices, run_wired_carplay_once, scan_connected_iphones,
    select_wired_ipv6_addresses, try_open_ch341_mfi, CarKitError, WiredCarPlayStage,
    WiredSessionConfig, WirelessApConfig,
};
use clap::Parser;
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use minifb::{Key, KeyRepeat, MouseButton, MouseMode, Window, WindowOptions};
use openh264::decoder::{Decoder, DecoderConfig, Flush};
use openh264::OpenH264API;
use platform_embedded::{generate_fastboot_init_script, yuv420_to_xrgb8888, EmbeddedBoardPreset};

use crate::font5x7::{draw_text, fill_rect};
use crate::sim_iphone::SimulatedIphone;
#[cfg(target_os = "macos")]
mod vt_decoder;

#[derive(Debug, Parser)]
#[command(name = "carplay-desktop", about = "CarPlay-RS Receiver for macOS & Linux")]
struct Cli {
    /// TCP port for AirPlay/CarPlay server (7000 is standard CarPlay port; 0 picks a free port).
    #[arg(long, default_value_t = 7000)]
    port: u16,

    /// Display width in pixels.
    #[arg(long, default_value_t = 1280)]
    width: u16,

    /// Display height in pixels.
    #[arg(long, default_value_t = 720)]
    height: u16,

    /// Negotiated CarPlay video FPS (60 for smooth desktop/RK3566; use 30 on slower CPUs).
    #[arg(long, default_value_t = 60)]
    fps: u16,

    /// Automatically connect the built-in wire-level Simulated iPhone on startup.
    #[arg(long)]
    simulate_iphone: bool,

    /// Run a headless end-to-end encrypted CarPlay self-test (SRP-6a + PairVerify + MFiSAP + H.264 + RTP + HID) and exit.
    #[arg(long)]
    self_test: bool,

    /// Scan connected Apple USB devices via libusb + usbmuxd + NCM and print CarPlay capabilities.
    #[arg(long)]
    scan_usb: bool,

    /// Run a live headless USB CarPlay handshake probe (`usbmuxd` -> `lockdownd` TLS -> `carkit` -> iAP2) against a plugged-in iPhone.
    #[arg(long)]
    usb_probe: bool,

    /// Print embedded Linux Buildroot fast-boot init & 5GHz hostapd configuration for a target board (`radxa`, `orangepi`, `mangopi`).
    #[arg(long)]
    print_embedded_config: Option<String>,

    /// Optional Remote MFi/BAA signing server URL (`https://host/mfi/...`).
    #[arg(long)]
    mfi_server_url: Option<String>,

    /// Optional directory containing `identity.pk8` and `certificate.p7b` for local P-256 MFi.
    #[arg(long)]
    mfi_local_dir: Option<PathBuf>,

    /// Disable Bonjour/mDNS advertisement.
    #[arg(long)]
    no_mdns: bool,

    /// Optional Wi-Fi SSID for Wireless CarPlay onboarding over USB.
    #[arg(long)]
    wifi_ssid: Option<String>,

    /// Optional Wi-Fi WPA2 passphrase for Wireless CarPlay onboarding over USB.
    #[arg(long)]
    wifi_pass: Option<String>,

    /// Optional Wi-Fi channel for Wireless CarPlay onboarding (default: auto/0).
    #[arg(long)]
    wifi_channel: Option<u8>,

    /// Optional explicit Wi-Fi IP address of this receiver (auto-detected if omitted).
    #[arg(long)]
    wifi_ip: Option<String>,
}

#[derive(Debug, Clone)]
struct UsbUiStatus {
    headline: String,
    detail: String,
    color: u32,
}

impl Default for UsbUiStatus {
    fn default() -> Self {
        Self {
            headline: "USB: AGUARDANDO IPHONE NO CABO (MONITORAMENTO AUTOMATICO)".to_string(),
            detail: "PLUGUE O IPHONE DESBLOQUEADO OU PRESSIONE [U] PARA RECONECTAR".to_string(),
            color: 0x5AC8FA,
        }
    }
}

struct DecodedYuvRaw<'a> {
    y: &'a [u8],
    u: &'a [u8],
    v: &'a [u8],
    ys: usize,
    us: usize,
    vs: usize,
    dw: usize,
    dh: usize,
}

fn create_live_h264_decoder() -> Option<Decoder> {
    let cfg = DecoderConfig::new().flush_after_decode(Flush::NoFlush);
    let mut dec = Decoder::with_api_config(OpenH264API::from_source(), cfg).ok()?;
    // Use ERROR_CON_SLICE_COPY: when a slice is lost/delayed, cleanly copy macroblocks from
    // the reference frame without synthesizing broken motion vectors across frames (which
    // causes blurring/smearing during drags or abrupt screen changes).
    let mut ec_idc: i32 = openh264_sys2::ERROR_CON_SLICE_COPY as i32;
    unsafe {
        dec.raw_api().set_option(
            openh264_sys2::DECODER_OPTION_ERROR_CON_IDC,
            (&mut ec_idc as *mut i32).cast(),
        );
    }
    Some(dec)
}

fn decode_h264_frame<'a>(
    dec: &'a mut Decoder,
    annex_b: &[u8],
) -> Result<Option<DecodedYuvRaw<'a>>, String> {
    let mut dst = [std::ptr::null_mut::<u8>(); 3];
    let mut buffer_info = openh264_sys2::SBufferInfo::default();

    // Decode NAL units in the packet directly with DecodeFrame2.
    let raw = unsafe { dec.raw_api() };
    let state = unsafe {
        raw.decode_frame2(
            annex_b.as_ptr(),
            annex_b.len() as std::os::raw::c_int,
            dst.as_mut_ptr(),
            &mut buffer_info,
        )
    };

    // If buffer_info.iBufferStatus is 0 (e.g. multi-slice AU awaiting end-of-frame trigger),
    // trigger AU completion with NULL/0. If buffer_info is already 1, never call NULL/0.
    if buffer_info.iBufferStatus == 0 {
        let _ = unsafe {
            raw.decode_frame2(
                std::ptr::null(),
                0,
                dst.as_mut_ptr(),
                &mut buffer_info,
            )
        };
    }

    // Whenever buffer_info.iBufferStatus == 1, OpenH264 produced a valid decoded picture!
    // Non-fatal status bits (like dsDataErrorConcealed 0x20, dsFramePending 0x01, dsRefLost 0x02)
    // MUST NOT cause this frame to be dropped, otherwise reference frames break and cause smearing!
    if buffer_info.iBufferStatus == 1
        && !dst[0].is_null()
        && !dst[1].is_null()
        && !dst[2].is_null()
    {
        let info = unsafe { buffer_info.UsrData.sSystemBuffer };
        let dw = info.iWidth as usize;
        let dh = info.iHeight as usize;
        let ys = info.iStride[0] as usize;
        let us = info.iStride[1] as usize;
        let vs = info.iStride[1] as usize;

        if dw == 0 || dh == 0 || ys == 0 || us == 0 {
            return Ok(None);
        }

        let y_len = dh * ys;
        let u_len = (dh / 2) * us;
        let v_len = (dh / 2) * vs;

        let y = unsafe { std::slice::from_raw_parts(dst[0], y_len) };
        let u = unsafe { std::slice::from_raw_parts(dst[1], u_len) };
        let v = unsafe { std::slice::from_raw_parts(dst[2], v_len) };

        Ok(Some(DecodedYuvRaw {
            y,
            u,
            v,
            ys,
            us,
            vs,
            dw,
            dh,
        }))
    } else {
        const FATAL_ERRORS: i32 = (openh264_sys2::dsBitstreamError
            | openh264_sys2::dsRefListNullPtrs
            | openh264_sys2::dsOutOfMemory) as i32;
        if (state & FATAL_ERRORS) != 0 {
            return Err(format!("OpenH264 fatal bitstream error 0x{state:X}"));
        }
        Ok(None)
    }
}

struct DecoderWorkState {
    #[cfg(target_os = "macos")]
    vt_dec: Option<crate::vt_decoder::VtDecoder>,
    decoder: Option<Decoder>,
    scratch_xrgb: Vec<u32>,
    decode_scratch_rgba: Vec<u32>,
}

struct DesktopSharedVideo {
    pixels: Vec<u32>,
    width: usize,
    height: usize,
    peer_label: String,
}

struct DesktopMediaSink {
    dec_state: Mutex<DecoderWorkState>,
    video: Mutex<DesktopSharedVideo>,
    frame_dirty: AtomicBool,
    audio_ring: Arc<Mutex<VecDeque<(f32, f32)>>>,
    decoded_frames: AtomicU64,
    decode_errors: AtomicU64,
    last_decode_us: AtomicU64,
    audio_packets: AtomicU64,
    session_active: AtomicBool,
    last_keyframe_req: Mutex<Instant>,
    control_handle: OnceLock<AirPlayControlHandle>,
}

impl DesktopMediaSink {
    fn new(width: usize, height: usize, audio_ring: Arc<Mutex<VecDeque<(f32, f32)>>>) -> Self {
        Self {
            dec_state: Mutex::new(DecoderWorkState {
                #[cfg(target_os = "macos")]
                vt_dec: Some(crate::vt_decoder::VtDecoder::new(width, height)),
                decoder: create_live_h264_decoder(),
                scratch_xrgb: vec![0x0B0F19; width * height],
                decode_scratch_rgba: Vec::new(),
            }),
            video: Mutex::new(DesktopSharedVideo {
                pixels: vec![0x0B0F19; width * height],
                width,
                height,
                peer_label: "AGUARDANDO IPHONE (USB / WIFI / TECLA T)".to_string(),
            }),
            frame_dirty: AtomicBool::new(true),
            audio_ring,
            decoded_frames: AtomicU64::new(0),
            decode_errors: AtomicU64::new(0),
            last_decode_us: AtomicU64::new(0),
            audio_packets: AtomicU64::new(0),
            session_active: AtomicBool::new(false),
            last_keyframe_req: Mutex::new(Instant::now()),
            control_handle: OnceLock::new(),
        }
    }

    fn set_control_handle(&self, handle: AirPlayControlHandle) {
        let _ = self.control_handle.set(handle);
    }

    fn feed_h264(&self, annex_b: &[u8]) {
        let t0 = Instant::now();
        let mut guard = self.dec_state.lock().unwrap();

        #[cfg(target_os = "macos")]
        {
            if let Some(vt) = guard.vt_dec.as_mut() {
                if let Some(pixels) = vt.decode_frame(annex_b.to_vec()) {
                    {
                        let mut v = self.video.lock().unwrap();
                        v.pixels = pixels;
                    }
                    self.frame_dirty.store(true, Ordering::Release);
                    self.decoded_frames.fetch_add(1, Ordering::Relaxed);
                    self.last_decode_us
                        .store(t0.elapsed().as_micros() as u64, Ordering::Relaxed);
                    static LOGGED_VT: AtomicBool = AtomicBool::new(false);
                    if !LOGGED_VT.swap(true, Ordering::Relaxed) {
                        tracing::info!("Hardware Apple VideoToolbox H.264 High Profile decoder ativo!");
                    }
                    return;
                }
            }
        }

        let DecoderWorkState {
            decoder,
            scratch_xrgb,
            decode_scratch_rgba,
            ..
        } = &mut *guard;

        let Some(dec) = decoder.as_mut() else {
            return;
        };

        let dst_len = scratch_xrgb.len();
        match decode_h264_frame(dec, annex_b) {
            Ok(Some(yuv)) => {
                let dw = yuv.dw;
                let dh = yuv.dh;
                let ys = yuv.ys;
                let us = yuv.us;
                let vs = yuv.vs;

                // Fast path when video resolution matches window (zero intermediate copy!)
                let (dst_w, dst_h) = {
                    let v = self.video.lock().unwrap();
                    (v.width, v.height)
                };

                static LOGGED_RES: AtomicBool = AtomicBool::new(false);
                if !LOGGED_RES.swap(true, Ordering::Relaxed) {
                    tracing::info!(
                        "CarPlay video stream ativo: decoded={}x{} (strides: Y={}, U={}, V={}) -> window={}x{}",
                        dw, dh, ys, us, vs, dst_w, dst_h
                    );
                }

                if dw == dst_w && dh == dst_h && scratch_xrgb.len() == dst_len {
                    yuv420_to_xrgb8888(
                        yuv.y,
                        yuv.u,
                        yuv.v,
                        ys,
                        us,
                        vs,
                        dw,
                        dh,
                        scratch_xrgb,
                    );
                } else {
                    decode_scratch_rgba.resize(dw * dh, 0);
                    yuv420_to_xrgb8888(
                        yuv.y,
                        yuv.u,
                        yuv.v,
                        ys,
                        us,
                        vs,
                        dw,
                        dh,
                        decode_scratch_rgba,
                    );
                    for y in 0..dst_h {
                        let sy = (y * dh) / dst_h.max(1);
                        let src_row = &decode_scratch_rgba[sy * dw..(sy + 1) * dw];
                        let dst_row = &mut scratch_xrgb[y * dst_w..(y + 1) * dst_w];
                        for (x, out_px) in dst_row.iter_mut().enumerate() {
                            *out_px = src_row[(x * dw) / dst_w.max(1)];
                        }
                    }
                }

                // O(1) pointer swap under lock instead of 3.7 MB memcpy!
                {
                    let mut v = self.video.lock().unwrap();
                    std::mem::swap(&mut v.pixels, scratch_xrgb);
                }
                self.frame_dirty.store(true, Ordering::Release);
                self.decoded_frames.fetch_add(1, Ordering::Relaxed);
                self.last_decode_us
                    .store(t0.elapsed().as_micros() as u64, Ordering::Relaxed);
            }
            Ok(None) => {}
            Err(e) => {
                let errs = self.decode_errors.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::debug!("H.264 decode error #{errs}: {e}");
                // Rate-limit forceKeyFrame requests to at most once per 250ms to prevent flooding
                let should_req = {
                    let mut last = self.last_keyframe_req.lock().unwrap();
                    if last.elapsed() >= Duration::from_millis(250) {
                        *last = Instant::now();
                        true
                    } else {
                        false
                    }
                };
                if should_req {
                    if let Some(ctrl) = self.control_handle.get() {
                        let _ = ctrl.request_keyframe(false);
                    }
                }
            }
        }
    }
}

impl MediaSink for DesktopMediaSink {
    fn on_session_started(&self, peer: SocketAddr) {
        self.session_active.store(true, Ordering::SeqCst);
        // Reset H.264 decoder cleanly for the new session
        if let Ok(mut g) = self.dec_state.lock() {
            #[cfg(target_os = "macos")]
            {
                let (w, h) = {
                    let v = self.video.lock().unwrap();
                    (v.width, v.height)
                };
                g.vt_dec = Some(crate::vt_decoder::VtDecoder::new(w, h));
            }
            g.decoder = create_live_h264_decoder();
        }
        self.video.lock().unwrap().peer_label = format!("CONECTADO: {peer}");
        self.frame_dirty.store(true, Ordering::Release);
        tracing::info!("CarPlay session started from {peer}");
    }

    fn on_device_info(&self, name: &str, model: &str, _device_id: &str) {
        self.video.lock().unwrap().peer_label = format!("{name} ({model})");
        self.frame_dirty.store(true, Ordering::Release);
        tracing::info!("Peer device info: name={name} model={model}");
    }

    fn on_video_codec(&self, _stream_type: u16, codec: VideoCodec) {
        tracing::info!("Negotiated video codec: {codec:?}");
    }

    fn on_video_config(
        &self,
        _stream_type: u16,
        raw_config: &[u8],
        annex_b_sps_pps: Option<&[u8]>,
    ) {
        #[cfg(target_os = "macos")]
        {
            let mut guard = self.dec_state.lock().unwrap();
            if let Some(vt) = guard.vt_dec.as_mut() {
                let ok = vt.configure_avcc(raw_config);
                tracing::info!("VideoToolbox configure_avcc: {ok}");
            }
        }
        if let Some(sps_pps) = annex_b_sps_pps {
            self.feed_h264(sps_pps);
        }
    }

    fn on_video_frame(
        &self,
        _stream_type: u16,
        annex_b_nalus: &[u8],
        _sender_nanos: u64,
        _arrival: Instant,
    ) {
        self.feed_h264(annex_b_nalus);
    }

    fn on_audio_rtp(
        &self,
        _id: &AudioStreamId,
        format: &AudioFormat,
        rtp_packet: &[u8],
        _sample_ts: u32,
    ) {
        self.audio_packets.fetch_add(1, Ordering::Relaxed);
        if format.codec == AudioCodecKind::Lpcm && rtp_packet.len() > 12 {
            let pcm = &rtp_packet[12..];
            let mut ring = self.audio_ring.lock().unwrap();

            // Hard cap buffer to 1 second (48_000 stereo frames) to prevent latency runaway
            if ring.len() > 48_000 {
                let drain_count = ring.len() - 4800; // retain latest 100ms
                ring.drain(0..drain_count);
            }

            let is_stereo = format.channels >= 2;
            let src_rate = format.sample_rate.max(8000);

            if is_stereo && src_rate == 48_000 {
                // Fast path: native 48kHz stereo (AirPlay music / media)
                // In RTP L16 (RFC 3551), audio is ALWAYS Network Byte Order (Big-Endian)!
                for chunk in pcm.chunks_exact(4) {
                    let l = i16::from_be_bytes([chunk[0], chunk[1]]) as f32 / 32768.0;
                    let r = i16::from_be_bytes([chunk[2], chunk[3]]) as f32 / 32768.0;
                    ring.push_back((l, r));
                }
            } else if !is_stereo && src_rate == 48_000 {
                // 48kHz mono
                for chunk in pcm.chunks_exact(2) {
                    let s = i16::from_be_bytes([chunk[0], chunk[1]]) as f32 / 32768.0;
                    ring.push_back((s, s));
                }
            } else {
                // Variable sample rate (e.g. 16kHz telephony / 24kHz prompts / 44.1kHz)
                let mut in_frames = Vec::with_capacity(pcm.len() / (if is_stereo { 4 } else { 2 }));
                if is_stereo {
                    for chunk in pcm.chunks_exact(4) {
                        let l = i16::from_be_bytes([chunk[0], chunk[1]]) as f32 / 32768.0;
                        let r = i16::from_be_bytes([chunk[2], chunk[3]]) as f32 / 32768.0;
                        in_frames.push((l, r));
                    }
                } else {
                    for chunk in pcm.chunks_exact(2) {
                        let s = i16::from_be_bytes([chunk[0], chunk[1]]) as f32 / 32768.0;
                        in_frames.push((s, s));
                    }
                }

                if !in_frames.is_empty() {
                    let num_out = ((in_frames.len() as u64 * 48_000) / src_rate as u64) as usize;
                    let step = src_rate as f64 / 48_000.0;
                    for out_idx in 0..num_out {
                        let src_pos = out_idx as f64 * step;
                        let idx = src_pos.floor() as usize;
                        let frac = (src_pos - idx as f64) as f32;
                        if idx + 1 < in_frames.len() {
                            let (l0, r0) = in_frames[idx];
                            let (l1, r1) = in_frames[idx + 1];
                            let l = l0 + (l1 - l0) * frac;
                            let r = r0 + (r1 - r0) * frac;
                            ring.push_back((l, r));
                        } else if idx < in_frames.len() {
                            ring.push_back(in_frames[idx]);
                        }
                    }
                }
            }
        }
    }

    fn on_session_ended(&self) {
        self.session_active.store(false, Ordering::SeqCst);
        if let Ok(mut g) = self.dec_state.lock() {
            #[cfg(target_os = "macos")]
            {
                let (w, h) = {
                    let v = self.video.lock().unwrap();
                    (v.width, v.height)
                };
                g.vt_dec = Some(crate::vt_decoder::VtDecoder::new(w, h));
            }
            g.decoder = create_live_h264_decoder();
        }
        self.video.lock().unwrap().peer_label =
            "SESSAO ENCERRADA - AGUARDANDO IPHONE (OU PRESSIONE T)".to_string();
        self.frame_dirty.store(true, Ordering::Release);
        tracing::info!("CarPlay session ended cleanly");
    }
}

fn start_cpal_output(ring: Arc<Mutex<VecDeque<(f32, f32)>>>) -> Option<cpal::Stream> {
    let host = cpal::default_host();
    let device = host.default_output_device()?;

    // 1. Prefer native 48,000 Hz F32 stereo output
    let mut chosen_config: Option<cpal::SupportedStreamConfig> = None;
    if let Ok(configs) = device.supported_output_configs() {
        for c in configs {
            if c.channels() >= 2
                && c.sample_format() == cpal::SampleFormat::F32
                && c.min_sample_rate().0 <= 48_000
                && c.max_sample_rate().0 >= 48_000
            {
                chosen_config = Some(c.with_sample_rate(cpal::SampleRate(48_000)));
                break;
            }
        }
    }

    let config = chosen_config.or_else(|| device.default_output_config().ok())?;
    let out_sample_rate = config.sample_rate().0;
    let out_channels = config.channels() as usize;
    tracing::info!(
        "Audio CPAL output stream ativo: {} Hz, {} canais, formato {:?} no dispositivo {:?}",
        out_sample_rate,
        out_channels,
        config.sample_format(),
        device.name().unwrap_or_default()
    );

    let is_native_48k = out_sample_rate == 48_000;
    let prebuffer_frames = 1440; // 30ms prebuffer at 48kHz to absorb network/USB jitter
    let playing = Arc::new(AtomicBool::new(false));
    let playing_cb = Arc::clone(&playing);

    let mut resample_pos = 0.0f64;
    let resample_ratio = 48_000.0f64 / out_sample_rate.max(1) as f64;

    let stream = match config.sample_format() {
        cpal::SampleFormat::F32 => device
            .build_output_stream(
                &config.into(),
                move |data: &mut [f32], _| {
                    let mut g = ring.lock().unwrap();

                    if !playing_cb.load(Ordering::Relaxed) {
                        if g.len() >= prebuffer_frames {
                            playing_cb.store(true, Ordering::Relaxed);
                        } else {
                            data.fill(0.0);
                            return;
                        }
                    }

                    if is_native_48k {
                        for frame in data.chunks_mut(out_channels.max(1)) {
                            if let Some((l, r)) = g.pop_front() {
                                for (idx, out) in frame.iter_mut().enumerate() {
                                    *out = if idx % 2 == 0 { l } else { r };
                                }
                            } else {
                                playing_cb.store(false, Ordering::Relaxed);
                                for out in frame.iter_mut() {
                                    *out = 0.0;
                                }
                            }
                        }
                    } else {
                        // Resample from 48kHz ring buffer to device sample rate (e.g. 44.1kHz or 96kHz)
                        for frame in data.chunks_mut(out_channels.max(1)) {
                            let needed_idx = resample_pos.floor() as usize;
                            if g.len() > needed_idx + 1 {
                                let frac = (resample_pos - needed_idx as f64) as f32;
                                let (l0, r0) = g[needed_idx];
                                let (l1, r1) = g[needed_idx + 1];
                                let l = l0 + (l1 - l0) * frac;
                                let r = r0 + (r1 - r0) * frac;
                                for (idx, out) in frame.iter_mut().enumerate() {
                                    *out = if idx % 2 == 0 { l } else { r };
                                }
                                resample_pos += resample_ratio;
                                let pop_count = resample_pos.floor() as usize;
                                if pop_count > 0 {
                                    g.drain(0..pop_count);
                                    resample_pos -= pop_count as f64;
                                }
                            } else {
                                playing_cb.store(false, Ordering::Relaxed);
                                resample_pos = 0.0;
                                for out in frame.iter_mut() {
                                    *out = 0.0;
                                }
                            }
                        }
                    }
                },
                |err| tracing::warn!("Audio output stream error: {err}"),
                None,
            )
            .ok()?,
        _ => return None,
    };
    stream.play().ok()?;
    Some(stream)
}

fn select_mfi_provider(cli: &Cli) -> anyhow::Result<(Arc<dyn MfiAuthenticator>, String)> {
    let remote_url = cli
        .mfi_server_url
        .clone()
        .or_else(|| std::env::var("DIPLAY_MFI_SERVER_URL").ok());
    if let Some(url) = remote_url {
        anyhow::ensure!(
            !url.contains("seu-servidor"),
            "A URL '{url}' era apenas um exemplo ilustrativo! Para chaves locais, use: --mfi-local-dir /caminho/para/pasta"
        );
        tracing::info!("Using Remote MFi signing server: {url}");
        return Ok((
            Arc::new(RemoteMfiClient::new(
                url.clone(),
                None,
                MfiCertificateType::Mfi,
            )),
            format!("SERVIDOR REMOTO ({url})"),
        ));
    }

    let local_dir = cli
        .mfi_local_dir
        .clone()
        .or_else(|| std::env::var("DIPLAY_AUTH_ASSETS_DIR").ok().map(PathBuf::from))
        .or_else(|| {
            for candidate_str in ["offline-mfi", "runtime-assets/offline-mfi"] {
                let candidate = PathBuf::from(candidate_str);
                if candidate.join("identity.pk8").exists()
                    && candidate.join("certificate.p7b").exists()
                {
                    return Some(candidate);
                }
            }
            None
        });
    if let Some(dir) = local_dir {
        tracing::info!("Loading Local P-256 MFi identity from {dir:?}");
        return Ok((
            Arc::new(LocalP256MfiClient::load_from_dir(&dir)?),
            format!("CERTIFICADO LOCAL ({})", dir.display()),
        ));
    }

    if let Some((ch341_mfi, addr)) = try_open_ch341_mfi() {
        tracing::info!("Detected physical Apple MFi coprocessor on CH341 USB-I2C at 0x{addr:02X}!");
        return Ok((ch341_mfi, format!("CHIP MFI HARDWARE CH341 (0x{addr:02X})")));
    }

    tracing::info!(
        "Using ephemeral Local P-256 MFi authenticator (works with simulator; real iPhone requires --mfi-local-dir or CH341 chip)"
    );
    Ok((
        Arc::new(LocalP256MfiClient::ephemeral_for_testing()),
        "CHAVE DE TESTE EFEMERA (USE --mfi-local-dir <dir> OU CHIP CH341)".to_string(),
    ))
}

fn print_usb_scan() {
    println!("=== [1/3] Dispositivos USB Apple via libusb ===");
    match scan_connected_iphones() {
        Ok(list) if list.is_empty() => {
            println!("  Nenhum iPhone USB detectado no momento (VID 0x05AC).");
        }
        Ok(list) => {
            for dev in list {
                println!(
                    "  - Bus {} Addr {} | {:04x}:{:04x} | Nome: {:?} | Serial: {:?} | NCM={} USBMUX={} AppleEth={} NcmIface={:?} ConfigRec={:?}",
                    dev.bus,
                    dev.address,
                    dev.vendor_id,
                    dev.product_id,
                    dev.product_name,
                    dev.serial_number,
                    dev.has_ncm,
                    dev.has_usbmux,
                    dev.has_apple_ethernet,
                    dev.ncm_control_interface,
                    dev.recommended_config_value
                );
            }
        }
        Err(e) => println!("  Erro libusb: {e}"),
    }

    println!("=== [2/3] Sessoes USB via /var/run/usbmuxd ===");
    match list_usb_devices() {
        Ok(devs) if devs.is_empty() => println!("  Nenhum dispositivo USB ativo no usbmuxd."),
        Ok(devs) => {
            for d in devs {
                println!(
                    "  - DeviceID={} | UDID={} | ProductID=0x{:04x}",
                    d.device_id, d.serial_number, d.product_id
                );
            }
        }
        Err(e) => println!("  Erro usbmuxd: {e}"),
    }

    println!("=== [3/3] Interfaces de Rede USB CDC-NCM (IPv6 Link-Local) ===");
    let ncm_ifs = discover_ncm_interfaces();
    if ncm_ifs.is_empty() {
        println!("  Nenhuma interface IPv6 link-local candidata encontrada.");
    } else {
        for c in ncm_ifs {
            println!(
                "  - {} (score={}) | MAC={:?} | IPv4-169.254={} | IPv6={:?}",
                c.name,
                c.score,
                c.mac_colon_uppercase(),
                c.has_link_local_ipv4,
                c.ipv6_link_local
            );
        }
    }
}

fn spawn_usb_carplay_worker(
    wired_cfg: WiredSessionConfig,
    mfi: Arc<dyn MfiAuthenticator>,
    sink: Arc<DesktopMediaSink>,
    usb_ui: Arc<Mutex<UsbUiStatus>>,
    force_retry: Arc<AtomicBool>,
    stop_flag: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("usb-carkit-worker".into())
        .spawn(move || {
            let mut suppressed_udid_after_mfi_fail: Option<String> = None;

            while !stop_flag.load(Ordering::Relaxed) {
                if force_retry.swap(false, Ordering::SeqCst) {
                    suppressed_udid_after_mfi_fail = None;
                }

                // Never re-open Lockdown/CarKit while an AirPlay CarPlay session is already streaming!
                if sink.session_active.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(500));
                    continue;
                }

                let current_udid = list_usb_devices()
                    .ok()
                    .and_then(|d| d.into_iter().next())
                    .map(|d| d.serial_number);

                if current_udid.is_none() {
                    if suppressed_udid_after_mfi_fail.is_some() {
                        suppressed_udid_after_mfi_fail = None;
                    }
                    let mut st = usb_ui.lock().unwrap();
                    st.headline =
                        "USB: NENHUM IPHONE CONECTADO (MONITORANDO /var/run/usbmuxd)".to_string();
                    st.detail =
                        "CONECTE O IPHONE NO CABO USB OU PRESSIONE [T] PARA SIMULADOR".to_string();
                    st.color = 0x5AC8FA;
                    std::thread::sleep(Duration::from_millis(1000));
                    continue;
                }

                if suppressed_udid_after_mfi_fail.as_deref() == current_udid.as_deref() {
                    std::thread::sleep(Duration::from_millis(800));
                    continue;
                }

                let usb_ui_cb = Arc::clone(&usb_ui);
                let result = run_wired_carplay_once(&wired_cfg, mfi.as_ref(), &stop_flag, |stage| {
                    let mut st = usb_ui_cb.lock().unwrap();
                    st.headline = stage.hud_label();
                    match &stage {
                        WiredCarPlayStage::CarPlayStartSent {
                            ipv6_list,
                            airplay_port,
                        } => {
                            let ip = ipv6_list.first().map(String::as_str).unwrap_or("::");
                            st.detail = format!(
                                "CONECTANDO RTSP DO IPHONE EM [{ip}]:{airplay_port}..."
                            );
                            st.color = 0x4CD964;
                        }
                        WiredCarPlayStage::Failed { summary } => {
                            st.detail = summary.to_uppercase();
                            st.color = 0xFF9F0A;
                        }
                        _ => {
                            st.detail =
                                "HANDSHAKE USB -> LOCKDOWN TLS -> CARKIT -> IAP2 EM ANDAMENTO"
                                    .to_string();
                            st.color = 0x5AC8FA;
                        }
                    }
                });

                match result {
                    Ok(_) => {
                        // Wait up to 3s for AirPlay session to attach if CarKit closed cleanly after 0x4301
                        for _ in 0..15 {
                            if stop_flag.load(Ordering::Relaxed)
                                || sink.session_active.load(Ordering::Relaxed)
                            {
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(200));
                        }
                    }
                    Err(CarKitError::Iap2Control(Iap2ControlError::AuthenticationFailed)) => {
                        suppressed_udid_after_mfi_fail = current_udid;
                        let mut st = usb_ui.lock().unwrap();
                        st.headline =
                            "USB: LOCKDOWN + CARKIT + IAP2 OK! FALTOU CREDENCIAL APPLE MFI (0xAA04)"
                                .to_string();
                        st.detail =
                            "PASSE --mfi-local-dir <dir> OU CHIP CH341 (TECLA [U] REPETE)"
                                .to_string();
                        st.color = 0xFF9F0A;
                    }
                    Err(CarKitError::Iap2Control(Iap2ControlError::Mfi(mfi_err))) => {
                        suppressed_udid_after_mfi_fail = current_udid;
                        tracing::warn!("MFi provider error: {mfi_err}");
                        let mut st = usb_ui.lock().unwrap();
                        st.headline = "USB: ERRO AO ACESSAR PROVEDOR MFI".to_string();
                        st.detail =
                            format!("{mfi_err} (PRESSIONE [U] PARA REPETIR)").to_uppercase();
                        st.color = 0xFF453A;
                    }
                    Err(e) => {
                        tracing::warn!("USB Wired CarPlay attempt error: {e}");
                        let mut st = usb_ui.lock().unwrap();
                        st.headline = "USB: FALHA AO INICIAR SESSAO CARPLAY NO IPHONE".to_string();
                        st.detail = e.to_string().to_uppercase();
                        st.color = 0xFF453A;
                        std::thread::sleep(Duration::from_millis(2500));
                    }
                }
            }
        })
        .expect("failed to spawn usb-carkit-worker")
}

fn run_usb_probe(cli: &Cli) -> anyhow::Result<()> {
    print_usb_scan();
    println!("\n=== [4/4] Teste Ao Vivo: Lockdown TLS -> com.apple.carkit.service -> iAP2 ===");
    let (mfi, mfi_label) = select_mfi_provider(cli)?;
    println!("  Provedor MFi selecionado: {mfi_label}");

    let config_dir = PathBuf::from(".carplay-rs-state");
    let identity = AirPlayIdentity::load_or_create(config_dir.join("identity.json"))?;
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_timer = Arc::clone(&stop_flag);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(8));
        stop_timer.store(true, Ordering::SeqCst);
    });

    let mut airplay_cfg = AirPlayConfig::default();
    if let (_, Some(ncm)) = select_wired_ipv6_addresses() {
        if let Some(mac) = ncm.mac_colon_uppercase() {
            airplay_cfg.device_id = mac;
        }
    }
    let wired_cfg = WiredSessionConfig {
        airplay_port: cli.port,
        device_id: airplay_cfg.device_id,
        ed25519_public_key_hex: identity.public_key_hex(),
        source_version: airplay_cfg.source_version,
        accessory_name: airplay_cfg.device_name,
        wifi_ssid: cli.wifi_ssid.clone(),
        wifi_pass: cli.wifi_pass.clone(),
        wifi_channel: cli.wifi_channel,
        wifi_ip: cli.wifi_ip.clone(),
    };

    match run_wired_carplay_once(&wired_cfg, mfi.as_ref(), &stop_flag, |stage| {
        println!("  -> {:?}", stage);
    }) {
        Ok(false) => {
            println!("  Nenhum iPhone conectado via USB para testar.");
        }
        Ok(true) => {
            println!("  Probe USB concluido com sucesso!");
        }
        Err(CarKitError::Iap2Control(Iap2ControlError::AuthenticationFailed)) => {
            println!(
                "  ==> RESULTADO: Transporte USB + USBMUX + Lockdown TLS + CarKit + Link iAP2 + Identificacao (0x1D02) 100% FUNCIONANDO!"
            );
            println!(
                "  ==> Parou apenas no 0xAA04 (MFi AuthenticationFailed) porque nenhuma chave/chip Apple MFi oficial foi fornecido."
            );
        }
        Err(e) => {
            println!("  ==> Erro durante probe USB: {e}");
        }
    }
    Ok(())
}

fn run_headless_self_test(width: u16, height: u16) -> anyhow::Result<()> {
    println!("==> Iniciando Self-Test ponta-a-ponta do CarPlay-RS no macOS/Linux...");
    let w = usize::from(width);
    let h = usize::from(height);

    let cfg = AirPlayConfig {
        main_display: AirPlayDisplayConfig {
            width_pixels: width,
            height_pixels: height,
            ..Default::default()
        },
        ..Default::default()
    };
    let identity = AirPlayIdentity::generate();
    let pairings = PairingStore::in_memory();
    let mfi: Arc<dyn MfiAuthenticator> = Arc::new(LocalP256MfiClient::ephemeral_for_testing());
    let audio_ring = Arc::new(Mutex::new(VecDeque::new()));
    let sink = Arc::new(DesktopMediaSink::new(w, h, audio_ring));

    let mut server = AirPlayServer::bind(
        "127.0.0.1:0".parse()?,
        cfg,
        identity,
        pairings,
        mfi,
        sink.clone(),
    )?;
    let port = server.port();
    let ctrl = server.control_handle();
    sink.set_control_handle(ctrl.clone());
    println!("  [1/5] AirPlayServer escutando em 127.0.0.1:{port}");

    let mut sim = SimulatedIphone::spawn(
        SocketAddr::from(([127, 0, 0, 1], port)),
        w,
        h,
        Some(12),
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    while !ctrl.is_event_ready() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    anyhow::ensure!(ctrl.is_event_ready(), "eventPort nao conectou a tempo");
    println!("  [2/5] SRP-6a (/pair-setup), X25519 (/pair-verify), ControlCipher e /auth-setup concluidos!");

    assert!(ctrl.send_touch(&[AirPlayContact {
        id: 0,
        x: 0.5,
        y: 0.5,
        down: true
    }]));
    assert!(ctrl.send_touch(&[AirPlayContact {
        id: 0,
        x: 0.5,
        y: 0.5,
        down: false
    }]));
    assert!(ctrl.set_night_mode(false));
    assert!(ctrl.invoke_siri());

    sim.join_finished()?;
    std::thread::sleep(Duration::from_millis(120));

    let frames = sink.decoded_frames.load(Ordering::Relaxed);
    let audio_pkts = sink.audio_packets.load(Ordering::Relaxed);
    let hid_rx = sim.state.lock().unwrap().hid_packets_received;

    #[cfg(target_os = "macos")]
    let dec_name = "Apple VideoToolbox (Hardware GPU)";
    #[cfg(not(target_os = "macos"))]
    let dec_name = "OpenH264";
    println!("  [3/5] Video H.264 criptografado (ChaCha20-Poly1305) decodificado via {dec_name}: {frames} quadros");
    println!("  [4/5] Audio RTP criptografado recebido e autenticado: {audio_pkts} pacotes");
    println!("  [5/5] Canal reverso HID Touch/NightMode/Siri recebido pelo iPhone simulado: {hid_rx} eventos");

    anyhow::ensure!(frames >= 8, "esperava >= 8 quadros H.264 decodificados, obteve {frames}");
    anyhow::ensure!(audio_pkts >= 5, "esperava >= 5 pacotes de audio RTP, obteve {audio_pkts}");
    anyhow::ensure!(hid_rx >= 3, "esperava >= 3 eventos HID recebidos, obteve {hid_rx}");

    server.stop();
    println!("==> SUCESSO TOTAL! Stack CarPlay-RS validada ponta-a-ponta.");
    Ok(())
}

fn bind_airplay_dual_stack_with_fallback(
    preferred_port: u16,
    config: AirPlayConfig,
    identity: AirPlayIdentity,
    pairings: PairingStore,
    mfi: Arc<dyn MfiAuthenticator>,
    sink: Arc<dyn MediaSink>,
) -> std::io::Result<AirPlayServer> {
    match AirPlayServer::bind_dual_stack(
        preferred_port,
        config.clone(),
        identity.clone(),
        pairings.clone(),
        Arc::clone(&mfi),
        Arc::clone(&sink),
    ) {
        Ok(srv) => Ok(srv),
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            tracing::warn!(
                "Porta TCP {} ocupada (no macOS o ControlCenter / 'Receptor AirPlay' ocupa a 7000 por padrao). Fazendo fallback dual-stack...",
                preferred_port
            );
            AirPlayServer::bind_dual_stack(
                7001,
                config.clone(),
                identity.clone(),
                pairings.clone(),
                Arc::clone(&mfi),
                Arc::clone(&sink),
            )
            .or_else(|_| AirPlayServer::bind_dual_stack(0, config, identity, pairings, mfi, sink))
        }
        Err(e) => Err(e),
    }
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();

    if let Some(board) = &cli.print_embedded_config {
        let preset = match board.to_ascii_lowercase().as_str() {
            "mangopi" | "t113" => EmbeddedBoardPreset::MangoPiMqDualT113S3,
            "orangepi" | "h618" => EmbeddedBoardPreset::OrangePiZero3H618,
            _ => EmbeddedBoardPreset::RadxaZero3wRk3566,
        };
        let ap = WirelessApConfig::default();
        println!(
            "=== /etc/hostapd-carplay.conf (5 GHz CarPlay AP) ===\n{}",
            ap.to_hostapd_conf()
        );
        println!(
            "=== /etc/init.d/S10carplay (Fast-Boot <2s Init) ===\n{}",
            generate_fastboot_init_script(preset, &ap)
        );
        return Ok(());
    }

    if cli.scan_usb {
        print_usb_scan();
        return Ok(());
    }

    if cli.usb_probe {
        return run_usb_probe(&cli);
    }

    if cli.self_test {
        return run_headless_self_test(cli.width, cli.height);
    }

    let w = usize::from(cli.width);
    let h = usize::from(cli.height);
    let mut config = AirPlayConfig {
        main_display: AirPlayDisplayConfig {
            width_pixels: cli.width,
            height_pixels: cli.height,
            fps: cli.fps.clamp(15, 60),
            ..Default::default()
        },
        ..Default::default()
    };

    // Match AirPlay `deviceID` with the USB NCM Ethernet MAC when connected so iOS correlates instantly
    if let (_, Some(ncm)) = select_wired_ipv6_addresses() {
        if let Some(mac) = ncm.mac_colon_uppercase() {
            config.device_id = mac;
        }
    }

    let config_dir = PathBuf::from(".carplay-rs-state");
    let identity = AirPlayIdentity::load_or_create(config_dir.join("identity.json"))?;
    let pairings = PairingStore::persistent(config_dir.join("pairings.json"));
    let (mfi, mfi_mode_label) = select_mfi_provider(&cli)?;

    let audio_ring = Arc::new(Mutex::new(VecDeque::new()));
    let _cpal_stream = start_cpal_output(Arc::clone(&audio_ring));
    let sink = Arc::new(DesktopMediaSink::new(w, h, audio_ring));

    let server = bind_airplay_dual_stack_with_fallback(
        cli.port,
        config.clone(),
        identity.clone(),
        pairings,
        Arc::clone(&mfi),
        sink.clone(),
    )?;
    let actual_port = server.port();
    let control = server.control_handle();
    sink.set_control_handle(control.clone());
    tracing::info!(
        "AirPlayServer dual-stack (IPv6+IPv4) ativo em [::]:{actual_port} ({}x{} @ {}fps)",
        cli.width,
        cli.height,
        cli.fps
    );

    let _bonjour = if !cli.no_mdns {
        match CarPlayBonjour::start(&config, &identity, actual_port, &[]) {
            Ok(b) => {
                tracing::info!("Published _airplay._tcp.local. on port {actual_port}");
                Some(b)
            }
            Err(e) => {
                tracing::warn!("Bonjour/mDNS startup skipped: {e}");
                None
            }
        }
    } else {
        None
    };

    let usb_ui = Arc::new(Mutex::new(UsbUiStatus::default()));
    if let Some(ssid) = &cli.wifi_ssid {
        let mut ui = usb_ui.lock().unwrap();
        ui.headline = format!("USB: AGUARDANDO IPHONE (ONBOARDING WI-FI: {ssid})");
        tracing::info!(
            "Modo Onboarding Wi-Fi ativo para SSID '{}' (Canal: {:?}, IP customizado: {:?})",
            ssid,
            cli.wifi_channel,
            cli.wifi_ip
        );
    }
    let usb_force_retry = Arc::new(AtomicBool::new(false));
    let usb_stop = Arc::new(AtomicBool::new(false));
    let wired_cfg = WiredSessionConfig {
        airplay_port: actual_port,
        device_id: config.device_id.clone(),
        ed25519_public_key_hex: identity.public_key_hex(),
        source_version: config.source_version.clone(),
        accessory_name: config.device_name.clone(),
        wifi_ssid: cli.wifi_ssid.clone(),
        wifi_pass: cli.wifi_pass.clone(),
        wifi_channel: cli.wifi_channel,
        wifi_ip: cli.wifi_ip.clone(),
    };
    let usb_worker = spawn_usb_carplay_worker(
        wired_cfg,
        Arc::clone(&mfi),
        Arc::clone(&sink),
        Arc::clone(&usb_ui),
        Arc::clone(&usb_force_retry),
        Arc::clone(&usb_stop),
    );

    let mut sim_client = if cli.simulate_iphone {
        Some(SimulatedIphone::spawn(
            SocketAddr::from(([127, 0, 0, 1], actual_port)),
            w,
            h,
            None,
        ))
    } else {
        None
    };

    let mut window = Window::new(
        &format!("CarPlay-RS Desktop (macOS/Linux) - Porta [::]:{actual_port}"),
        w,
        h,
        WindowOptions {
            resize: false,
            ..WindowOptions::default()
        },
    )?;
    window.set_target_fps(60);

    let mut framebuffer = vec![0u32; w * h];
    let mut mouse_was_down = false;
    let mut last_mouse_px: (f32, f32) = (-10.0, -10.0);
    let mut night_mode = true;
    // Hide HUD bar automatically once live CarPlay video starts so we don't draw text over CarPlay status bar; toggle with [D]
    let mut show_hud = false;
    let mut last_standby_draw = Instant::now() - Duration::from_secs(1);

    tracing::info!(
        "Janela aberta ({w}x{h})! Atalhos: [D]=Mostrar/Ocultar HUD FPS, [T]=Simulador, [U]=Retry USB, [H]=Home, [B]=Back, [S]=Siri, [N]=NightMode"
    );

    while window.is_open() && !window.is_key_down(Key::Escape) {
        if window.is_key_pressed(Key::T, KeyRepeat::No) {
            if let Some(mut old) = sim_client.take() {
                let _ = old.stop_and_join();
            } else {
                sim_client = Some(SimulatedIphone::spawn(
                    SocketAddr::from(([127, 0, 0, 1], actual_port)),
                    w,
                    h,
                    None,
                ));
            }
        }
        if window.is_key_pressed(Key::U, KeyRepeat::No) {
            print_usb_scan();
            usb_force_retry.store(true, Ordering::SeqCst);
        }
        if window.is_key_pressed(Key::H, KeyRepeat::No) {
            control.send_knob(
                AirPlayKnobState {
                    home: true,
                    ..Default::default()
                },
                true,
            );
        }
        if window.is_key_pressed(Key::B, KeyRepeat::No)
            || window.is_key_pressed(Key::Backspace, KeyRepeat::No)
        {
            control.send_knob(
                AirPlayKnobState {
                    back: true,
                    ..Default::default()
                },
                true,
            );
        }
        if window.is_key_pressed(Key::Enter, KeyRepeat::No) {
            control.send_knob(
                AirPlayKnobState {
                    select: true,
                    ..Default::default()
                },
                true,
            );
        }
        if window.is_key_pressed(Key::Left, KeyRepeat::Yes) {
            control.send_knob(
                AirPlayKnobState {
                    wheel: -1,
                    ..Default::default()
                },
                false,
            );
        }
        if window.is_key_pressed(Key::Right, KeyRepeat::Yes) {
            control.send_knob(
                AirPlayKnobState {
                    wheel: 1,
                    ..Default::default()
                },
                false,
            );
        }
        if window.is_key_pressed(Key::S, KeyRepeat::No) {
            control.invoke_siri();
        }
        if window.is_key_pressed(Key::N, KeyRepeat::No) {
            night_mode = !night_mode;
            control.set_night_mode(night_mode);
        }
        if window.is_key_pressed(Key::D, KeyRepeat::No) {
            show_hud = !show_hud;
            sink.frame_dirty.store(true, Ordering::Release);
        }

        if let Some((_, scroll_y)) = window.get_scroll_wheel() {
            if scroll_y.abs() > 0.1 {
                control.send_knob(
                    AirPlayKnobState {
                        wheel: if scroll_y > 0.0 { -1 } else { 1 },
                        ..Default::default()
                    },
                    false,
                );
            }
        }

        // Deduplicated Mouse click/drag -> CarPlay Multitouch HID (`0x2a2a2a2a`)
        let mouse_down = window.get_mouse_down(MouseButton::Left);
        if let Some((mx, my)) = window.get_mouse_pos(MouseMode::Clamp) {
            let moved =
                (mx - last_mouse_px.0).abs() >= 1.0 || (my - last_mouse_px.1).abs() >= 1.0;
            if mouse_down && (!mouse_was_down || moved) {
                last_mouse_px = (mx, my);
                let nx = (f64::from(mx) / (w as f64)).clamp(0.0, 1.0);
                let ny = (f64::from(my) / (h as f64)).clamp(0.0, 1.0);
                control.send_touch(&[AirPlayContact {
                    id: 0,
                    x: nx,
                    y: ny,
                    down: true,
                }]);
            } else if !mouse_down && mouse_was_down {
                last_mouse_px = (mx, my);
                let nx = (f64::from(mx) / (w as f64)).clamp(0.0, 1.0);
                let ny = (f64::from(my) / (h as f64)).clamp(0.0, 1.0);
                control.send_touch(&[AirPlayContact {
                    id: 0,
                    x: nx,
                    y: ny,
                    down: false,
                }]);
            }
        }
        mouse_was_down = mouse_down;

        let active = sink.session_active.load(Ordering::Relaxed);
        let needs_standby_refresh = !active && last_standby_draw.elapsed() >= Duration::from_millis(200);
        let video_dirty = sink.frame_dirty.swap(false, Ordering::AcqRel);

        if video_dirty || needs_standby_refresh {
            let peer_label = {
                let v = sink.video.lock().unwrap();
                if active {
                    framebuffer.copy_from_slice(&v.pixels);
                }
                v.peer_label.clone()
            };

            if !active {
                last_standby_draw = Instant::now();
                let usb_snap = usb_ui.lock().unwrap().clone();
                render_standby_screen(
                    &mut framebuffer,
                    w,
                    h,
                    actual_port,
                    &identity.pairing_id,
                    &mfi_mode_label,
                    &usb_snap,
                );
            }

            if show_hud || !active {
                fill_rect(&mut framebuffer, w, h, 0, 0, w, 20, 0x182232);
                let dec_ms = sink.last_decode_us.load(Ordering::Relaxed) as f64 / 1000.0;
                let hud_line = format!(
                    "[::]:{} | {} | FRAMES {} ({:.1}ms) | ERROS {} | AUDIO {} | [D] HUD",
                    actual_port,
                    peer_label,
                    sink.decoded_frames.load(Ordering::Relaxed),
                    dec_ms,
                    sink.decode_errors.load(Ordering::Relaxed),
                    sink.audio_packets.load(Ordering::Relaxed),
                );
                draw_text(&mut framebuffer, w, h, 8, 6, 1, 0x7FE7FF, &hud_line);
            }

            window.update_with_buffer(&framebuffer, w, h)?;
        } else {
            // Poll Cocoa/X11 input events without re-uploading a 3.7 MB Quartz CGImage!
            window.update();
        }
    }

    usb_stop.store(true, Ordering::SeqCst);
    let _ = usb_worker.join();
    if let Some(mut sim) = sim_client {
        let _ = sim.stop_and_join();
    }
    Ok(())
}

fn render_standby_screen(
    fb: &mut [u32],
    w: usize,
    h: usize,
    port: u16,
    pairing_id: &str,
    mfi_mode_label: &str,
    usb_snap: &UsbUiStatus,
) {
    fb.fill(0x0B101B);
    let box_w = 880.min(w.saturating_sub(40));
    let box_x = (w - box_w) / 2;
    let box_y = h / 2 - 155;
    fill_rect(fb, w, h, box_x, box_y, box_w, 310, 0x151F33);

    draw_text(
        fb,
        w,
        h,
        box_x + 30,
        box_y + 24,
        3,
        0x4CD964,
        "CARPLAY-RS RECEIVER",
    );
    draw_text(
        fb,
        w,
        h,
        box_x + 30,
        box_y + 72,
        2,
        0xFFFFFF,
        &format!("SERVIDOR AIRPLAY DUAL-STACK ATIVO EM [::]:{}", port),
    );

    fill_rect(fb, w, h, box_x + 24, box_y + 106, box_w - 48, 66, 0x0E1626);
    draw_text(
        fb,
        w,
        h,
        box_x + 36,
        box_y + 118,
        1,
        usb_snap.color,
        &usb_snap.headline,
    );
    draw_text(
        fb,
        w,
        h,
        box_x + 36,
        box_y + 142,
        1,
        0xD0D8E8,
        &usb_snap.detail,
    );

    draw_text(
        fb,
        w,
        h,
        box_x + 30,
        box_y + 194,
        2,
        0xFFD60A,
        "TECLA [T]: TESTAR STREAM H.264 CRIPTOGRAFADO",
    );
    draw_text(
        fb,
        w,
        h,
        box_x + 30,
        box_y + 226,
        2,
        0x5AC8FA,
        "TECLA [U]: FORCAR RECONEXAO / DIAGNOSTICO USB",
    );
    draw_text(
        fb,
        w,
        h,
        box_x + 30,
        box_y + 262,
        1,
        0x8E9BAE,
        &format!("MFI ATIVO: {}", mfi_mode_label),
    );
    draw_text(
        fb,
        w,
        h,
        box_x + 30,
        box_y + 282,
        1,
        0x8E9BAE,
        &format!("PAIRING ID: {}", pairing_id),
    );
}
