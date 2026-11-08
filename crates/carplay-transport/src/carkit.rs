//! Active Wired CarPlay orchestrator over `/var/run/usbmuxd` -> `lockdownd` (TLS) ->
//! `com.apple.carkit.service` -> `Iap2LinkEngine` -> `Iap2ControlClient`.
//!
//! Works natively on both macOS (`AppleUSBNCM` `enX`) and Linux (`cdc_ncm` `usb0`) without
//! detaching kernel drivers or requiring `sudo`.

use std::io::{Cursor, Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use carplay_iap2::{
    CarPlayStartConfig, CarPlayTransportParams, ControlStepEvent, Iap2ControlClient,
    Iap2ControlError, Iap2LinkEngine, IdentificationConfig, LinkEvent, TransportDeclaration,
};
use carplay_mfi::MfiAuthenticator;
use plist::Value;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, Error as TlsError, SignatureScheme, StreamOwned};
use thiserror::Error;

use crate::lockdown::{
    build_start_carkit_service_xml, build_start_session_xml, LockdownFrameBuffer,
};
use crate::ncm_net::{discover_wifi_host_addresses, select_wired_ipv6_addresses};
use crate::usb::{request_carplay_usb_mode_if_needed, scan_connected_iphones};
use crate::usbmux::LOCKDOWND_PORT;
use crate::usbmuxd_client::{
    connect_tcp, list_usb_devices, read_pair_record, UsbmuxDevice, UsbmuxPairRecord, UsbmuxdError,
};
use crate::wireless::discover_host_bluetooth_mac;

#[derive(Debug, Error)]
pub enum CarKitError {
    #[error(transparent)]
    Usbmuxd(#[from] UsbmuxdError),
    #[error("I/O error on CarKit/Lockdown stream: {0}")]
    Io(#[from] std::io::Error),
    #[error("plist error in lockdownd response: {0}")]
    Plist(#[from] plist::Error),
    #[error("TLS error on lockdownd/carkit: {0}")]
    Tls(#[from] TlsError),
    #[error("invalid Lockdown PairRecord credentials: {0}")]
    InvalidPairRecord(&'static str),
    #[error("iPhone lockdownd rejected {step}: {error_code} ({hint})")]
    LockdownRejected {
        step: &'static str,
        error_code: String,
        hint: &'static str,
    },
    #[error("lockdownd closed connection unexpectedly during {0}")]
    UnexpectedEof(&'static str),
    #[error("iAP2 link layer error: {0}")]
    Iap2Link(#[from] carplay_iap2::Iap2LinkError),
    #[error("iAP2 control error: {0}")]
    Iap2Control(#[from] Iap2ControlError),
}

/// Live status milestones emitted during a USB Wired CarPlay connection attempt.
#[derive(Debug, Clone)]
pub enum WiredCarPlayStage {
    UsbDetected {
        udid: String,
        product_id: u16,
    },
    UsbModeSwitched,
    LockdownAuthenticated {
        session_id: String,
    },
    CarKitServiceOpened {
        port: u16,
        ssl: bool,
        ncm_iface: Option<String>,
        ipv6_list: Vec<String>,
    },
    Iap2LinkEstablished,
    IdentificationAccepted,
    MfiCertificateSent,
    MfiChallengeSigned,
    MfiAuthenticated,
    CarPlayStartSent {
        ipv6_list: Vec<String>,
        airplay_port: u16,
    },
    Failed {
        summary: String,
    },
    Disconnected,
}

impl WiredCarPlayStage {
    /// Short Portuguese status string suitable for rendering on the CarPlay receiver HUD.
    pub fn hud_label(&self) -> String {
        match self {
            Self::UsbDetected { udid, .. } => {
                let short = &udid[..udid.len().min(10)];
                format!("USB: IPHONE DETECTADO ({short}...) -> ABRINDO LOCKDOWN")
            }
            Self::UsbModeSwitched => {
                "USB: MODO CARPLAY NCM ATIVADO (0x52) -> RE-ENUMERANDO".to_string()
            }
            Self::LockdownAuthenticated { .. } => {
                "USB: LOCKDOWN TLS OK -> INICIANDO CARKIT SERVICE".to_string()
            }
            Self::CarKitServiceOpened { ncm_iface, .. } => {
                let ifname = ncm_iface.as_deref().unwrap_or("sem-ncm");
                format!("USB: CARKIT CONECTADO ({ifname}) -> NEGOCIANDO IAP2")
            }
            Self::Iap2LinkEstablished => "USB: LINK IAP2 ESTABELECIDO -> IDENTIFICANDO".to_string(),
            Self::IdentificationAccepted => {
                "USB: IAP2 IDENTIFICADO (0x1D02) -> AUTENTICANDO MFI".to_string()
            }
            Self::MfiCertificateSent => {
                "USB: CERTIFICADO MFI ENVIADO (0xAA01) -> AGUARDANDO IPHONE".to_string()
            }
            Self::MfiChallengeSigned => {
                "USB: DESAFIO MFI ASSINADO (0xAA03) -> VALIDANDO".to_string()
            }
            Self::MfiAuthenticated => {
                "USB: MFI APROVADO (0xAA05)! AGUARDANDO DISPONIBILIDADE CARPLAY".to_string()
            }
            Self::CarPlayStartSent {
                ipv6_list,
                airplay_port,
            } => {
                let ip = ipv6_list.first().map(String::as_str).unwrap_or("::");
                format!("USB: CARPLAY INICIADO (0x4301) -> [{ip}]:{airplay_port}")
            }
            Self::Failed { summary } => format!("USB ERRO: {summary}"),
            Self::Disconnected => "USB: IPHONE DESCONECTADO".to_string(),
        }
    }
}

/// Custom `rustls` verifier scoped strictly to the local `/var/run/usbmuxd` Lockdown/CarKit USB socket.
/// Apple `lockdownd` uses a self-issued `DeviceCertificate` with empty X.509 Subject/Issuer DNs (`SEQUENCE {}`),
/// which standard WebPKI X.509 parsers reject.
#[derive(Debug)]
struct UsbLockdownServerVerifier;

impl ServerCertVerifier for UsbLockdownServerVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

enum MaybeTlsUnixStream {
    Plain(UnixStream),
    Tls(Box<StreamOwned<ClientConnection, UnixStream>>),
}

impl MaybeTlsUnixStream {
    fn set_read_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        match self {
            Self::Plain(s) => s.set_read_timeout(dur),
            Self::Tls(s) => s.get_ref().set_read_timeout(dur),
        }
    }
}

impl Read for MaybeTlsUnixStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(s) => s.read(buf),
            Self::Tls(s) => s.read(buf),
        }
    }
}

impl Write for MaybeTlsUnixStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(s) => s.write(buf),
            Self::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(s) => s.flush(),
            Self::Tls(s) => s.flush(),
        }
    }
}

/// Active `com.apple.carkit.service` stream keeping the parent `lockdownd` session alive.
pub struct CarKitStream {
    stream: MaybeTlsUnixStream,
    _lockdown_keepalive: MaybeTlsUnixStream,
    pub service_port: u16,
    pub service_ssl: bool,
    pub session_id: String,
}

impl Read for CarKitStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(buf)
    }
}

impl Write for CarKitStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

fn build_lockdown_tls_config(pair: &UsbmuxPairRecord) -> Result<Arc<ClientConfig>, CarKitError> {
    // Prefer RootCertificate + RootPrivateKey when present (matches LockdownTlsEngineFactory.kt),
    // falling back to HostCertificate + HostPrivateKey if the OS stripped RootPrivateKey.
    let (cert_pem, key_pem): (&[u8], &[u8]) = match &pair.root_private_key {
        Some(rk) if !rk.is_empty() && !pair.root_certificate.is_empty() => {
            (&pair.root_certificate, rk.as_slice())
        }
        _ => (&pair.host_certificate, pair.host_private_key.as_slice()),
    };

    let mut cert_cursor = Cursor::new(cert_pem);
    let mut certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CarKitError::InvalidPairRecord("failed to parse client certificate PEM"))?;
    if certs.is_empty() {
        return Err(CarKitError::InvalidPairRecord("empty client certificate PEM"));
    }

    // If using HostCertificate and RootCertificate is also available, append RootCertificate to chain
    if std::ptr::eq(cert_pem, pair.host_certificate.as_slice()) && !pair.root_certificate.is_empty()
    {
        let mut root_cursor = Cursor::new(&pair.root_certificate);
        if let Ok(root_certs) =
            rustls_pemfile::certs(&mut root_cursor).collect::<Result<Vec<_>, _>>()
        {
            certs.extend(root_certs);
        }
    }

    let mut key_cursor = Cursor::new(key_pem);
    let priv_key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_cursor)
        .map_err(|_| CarKitError::InvalidPairRecord("failed to parse private key PEM"))?
        .ok_or(CarKitError::InvalidPairRecord("no private key found in PairRecord"))?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(UsbLockdownServerVerifier))
        .with_client_auth_cert(certs, priv_key)?;

    Ok(Arc::new(cfg))
}

fn upgrade_unix_stream_to_tls(
    mut raw: UnixStream,
    tls_cfg: Arc<ClientConfig>,
) -> Result<MaybeTlsUnixStream, CarKitError> {
    let server_name = ServerName::IpAddress(Ipv4Addr::LOCALHOST.into());
    let mut conn = ClientConnection::new(tls_cfg, server_name)?;
    while conn.is_handshaking() {
        conn.complete_io(&mut raw)?;
    }
    Ok(MaybeTlsUnixStream::Tls(Box::new(StreamOwned::new(
        conn, raw,
    ))))
}

fn read_lockdown_plist(
    stream: &mut MaybeTlsUnixStream,
    framer: &mut LockdownFrameBuffer,
    step: &'static str,
) -> Result<plist::Dictionary, CarKitError> {
    let mut scratch = [0u8; 4096];
    loop {
        let n = stream.read(&mut scratch)?;
        if n == 0 {
            return Err(CarKitError::UnexpectedEof(step));
        }
        let frames = framer.push(&scratch[..n]);
        if let Some(first) = frames.into_iter().next() {
            let val = Value::from_reader(Cursor::new(first))?;
            return val
                .into_dictionary()
                .ok_or_else(|| CarKitError::UnexpectedEof(step));
        }
    }
}

fn check_lockdown_error(dict: &plist::Dictionary, step: &'static str) -> Result<(), CarKitError> {
    if let Some(err_str) = dict.get("Error").and_then(Value::as_string) {
        let hint = match err_str {
            "PasswordProtected" | "PairingDialogResponsePending" => {
                "Desbloqueie a tela do iPhone com FaceID/senha e mantenha na tela inicial"
            }
            "InvalidHostID" => {
                "Par de confianca expirado — desconecte o cabo, desbloqueie o iPhone e toque em 'Confiar'"
            }
            "InvalidService" | "ServiceProhibited" => {
                "Verifique Ajustes > Geral > CarPlay ou Tempo de Uso > Restricoes no iPhone"
            }
            _ => "Verifique se o iPhone esta desbloqueado e confiavel neste computador",
        };
        return Err(CarKitError::LockdownRejected {
            step,
            error_code: err_str.to_string(),
            hint,
        });
    }
    Ok(())
}

/// Opens an authenticated TLS `lockdownd` session and launches `com.apple.carkit.service` over USBMUX.
pub fn open_carkit_service(dev: &UsbmuxDevice, label: &str) -> Result<CarKitStream, CarKitError> {
    let pair = read_pair_record(&dev.serial_number)?;
    let tls_cfg = build_lockdown_tls_config(&pair)?;

    let raw_lockdown = connect_tcp(dev.device_id, LOCKDOWND_PORT)?;
    let _ = raw_lockdown.set_read_timeout(Some(Duration::from_secs(6)));
    let _ = raw_lockdown.set_write_timeout(Some(Duration::from_secs(6)));
    let mut lockdown = MaybeTlsUnixStream::Plain(raw_lockdown);
    let mut framer = LockdownFrameBuffer::new();

    // 1. StartSession
    let start_session_pkt = build_start_session_xml(label, &pair.host_id, &pair.system_buid);
    lockdown.write_all(&start_session_pkt)?;
    lockdown.flush()?;
    let session_resp = read_lockdown_plist(&mut lockdown, &mut framer, "StartSession")?;
    check_lockdown_error(&session_resp, "StartSession")?;

    let session_id = session_resp
        .get("SessionID")
        .and_then(Value::as_string)
        .unwrap_or("unknown")
        .to_string();
    let enable_session_ssl = session_resp
        .get("EnableSessionSSL")
        .and_then(Value::as_boolean)
        .unwrap_or(false);

    if enable_session_ssl {
        let MaybeTlsUnixStream::Plain(raw) = lockdown else {
            unreachable!();
        };
        lockdown = upgrade_unix_stream_to_tls(raw, Arc::clone(&tls_cfg))?;
    }

    // 2. StartService("com.apple.carkit.service")
    let start_carkit_pkt = build_start_carkit_service_xml(label);
    lockdown.write_all(&start_carkit_pkt)?;
    lockdown.flush()?;
    let svc_resp = read_lockdown_plist(&mut lockdown, &mut framer, "StartService(carkit)")?;
    check_lockdown_error(&svc_resp, "StartService(carkit)")?;

    let port = svc_resp
        .get("Port")
        .and_then(Value::as_unsigned_integer)
        .ok_or(CarKitError::UnexpectedEof("missing Port in StartService"))? as u16;
    let enable_service_ssl = svc_resp
        .get("EnableServiceSSL")
        .and_then(Value::as_boolean)
        .unwrap_or(false);

    // 3. Connect USBMUX TCP channel to carkit dynamic port
    let raw_carkit = connect_tcp(dev.device_id, port)?;
    let _ = raw_carkit.set_read_timeout(Some(Duration::from_secs(6)));
    let _ = raw_carkit.set_write_timeout(Some(Duration::from_secs(6)));
    let carkit_stream = if enable_service_ssl {
        upgrade_unix_stream_to_tls(raw_carkit, tls_cfg)?
    } else {
        MaybeTlsUnixStream::Plain(raw_carkit)
    };

    // Switch to 40ms read timeout so the iAP2 pump loop stays snappy
    let _ = carkit_stream.set_read_timeout(Some(Duration::from_millis(40)));

    Ok(CarKitStream {
        stream: carkit_stream,
        _lockdown_keepalive: lockdown,
        service_port: port,
        service_ssl: enable_service_ssl,
        session_id,
    })
}

#[derive(Clone)]
pub struct WiredSessionConfig {
    pub airplay_port: u16,
    pub device_id: String,
    pub ed25519_public_key_hex: String,
    pub source_version: String,
    pub accessory_name: String,
    pub wifi_ssid: Option<String>,
    pub wifi_pass: Option<String>,
    pub wifi_channel: Option<u8>,
    pub wifi_ip: Option<String>,
}

/// Runs one complete USB Wired CarPlay handshake and control pump on the first connected iPhone.
/// Returns `Ok(false)` immediately if no USB iPhone is currently attached to `usbmuxd`.
pub fn run_wired_carplay_once<F>(
    cfg: &WiredSessionConfig,
    mfi: &dyn MfiAuthenticator,
    stop_flag: &AtomicBool,
    mut on_stage: F,
) -> Result<bool, CarKitError>
where
    F: FnMut(WiredCarPlayStage),
{
    let devices = list_usb_devices()?;
    let Some(dev) = devices.first() else {
        return Ok(false);
    };

    on_stage(WiredCarPlayStage::UsbDetected {
        udid: dev.serial_number.clone(),
        product_id: dev.product_id,
    });

    // Ensure iOS has enabled the Apple CarPlay NCM configuration (vendor request 0x52)
    if let Ok(true) = request_carplay_usb_mode_if_needed() {
        on_stage(WiredCarPlayStage::UsbModeSwitched);
        // Give macOS/Linux USB stack ~1.2s to re-enumerate the new configuration
        std::thread::sleep(Duration::from_millis(1200));
        return Ok(true);
    }

    // Discover active USB CDC-NCM interface (`en9` on macOS / `usb0` on Linux) & USB interface number
    let usb_ncm_iface_num = scan_connected_iphones()
        .ok()
        .and_then(|list| list.into_iter().next())
        .and_then(|d| d.ncm_control_interface)
        .unwrap_or(3);

    // Wait briefly (up to 1.5s) if USB NCM IPv6 link-local is still completing SLAAC/DAD
    let mut ipv6_list = Vec::new();
    let mut best_ncm = None;
    for _ in 0..6 {
        let (addrs, best) = select_wired_ipv6_addresses();
        if !addrs.is_empty() {
            ipv6_list = addrs;
            best_ncm = best;
            break;
        }
        if stop_flag.load(Ordering::Relaxed) {
            return Ok(true);
        }
        std::thread::sleep(Duration::from_millis(250));
    }

    let mut carkit = open_carkit_service(dev, "CarPlayRS")?;
    on_stage(WiredCarPlayStage::LockdownAuthenticated {
        session_id: carkit.session_id.clone(),
    });
    on_stage(WiredCarPlayStage::CarKitServiceOpened {
        port: carkit.service_port,
        ssl: carkit.service_ssl,
        ncm_iface: best_ncm.as_ref().map(|c| c.name.clone()),
        ipv6_list: ipv6_list.clone(),
    });

    let (ident_transport, carplay_transport) = if let Some(ssid) = &cfg.wifi_ssid {
        let (wifi_ips, _) = discover_wifi_host_addresses();
        let mut final_wifi_ips = wifi_ips;
        if let Some(explicit_ip) = &cfg.wifi_ip {
            if !final_wifi_ips.contains(explicit_ip) {
                final_wifi_ips.insert(0, explicit_ip.clone());
            }
        }
        let passphrase = cfg.wifi_pass.clone().unwrap_or_default();
        let security_type = if passphrase.is_empty() { 0 } else { 1 };
        let channel = cfg.wifi_channel.unwrap_or(0);
        let bt_mac = discover_host_bluetooth_mac().unwrap_or([0x6C, 0x7E, 0x67, 0xC8, 0x1C, 0xD0]);
        tracing::info!(
            "Wireless CarPlay Onboarding enabled: SSID='{ssid}', channel={channel}, security={security_type}, BT MAC={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}, Wi-Fi IPs={:?}",
            bt_mac[0], bt_mac[1], bt_mac[2], bt_mac[3], bt_mac[4], bt_mac[5],
            final_wifi_ips
        );

        (
            TransportDeclaration::WiredUsbHost {
                interface_number: usb_ncm_iface_num,
            },
            CarPlayTransportParams::DualWiredWithWirelessOnboarding {
                wired_ipv6_addresses: ipv6_list.clone(),
                ssid: ssid.clone(),
                passphrase,
                bssid: None,
                channel,
                security_type,
                wireless_ipv6_addresses: final_wifi_ips,
            },
        )
    } else {
        (
            TransportDeclaration::WiredUsbHost {
                interface_number: usb_ncm_iface_num,
            },
            CarPlayTransportParams::Wired {
                ipv6_addresses: ipv6_list.clone(),
            },
        )
    };

    let ident = IdentificationConfig {
        name: cfg.accessory_name.clone(),
        transport: ident_transport,
        ..IdentificationConfig::default()
    };

    let start_cfg = CarPlayStartConfig {
        transport: carplay_transport,
        airplay_port: u32::from(cfg.airplay_port),
        // Must match AirPlay `GET /info` `deviceID` so iOS correlates 0x4301 with the RTSP server
        device_identifier: Some(cfg.device_id.clone()),
        ed25519_public_key_hex: cfg.ed25519_public_key_hex.clone(),
        source_version: cfg.source_version.clone(),
    };

    let mut link = Iap2LinkEngine::new_wired();
    let mut control = Iap2ControlClient::new(ident, start_cfg);
    link.start_initiator();

    let mut rx_buf = [0u8; 4096];
    let handshake_start = Instant::now();
    let mut link_up = false;

    while !stop_flag.load(Ordering::Relaxed) {
        // Flush any pending outbound iAP2 Link frames in 256B TLS chunks
        // (avoids multi-second USBMUX/TLS stalls when transmitting large MFi certificates)
        while let Some(frame) = link.poll_transmit() {
            for chunk in frame.chunks(256) {
                carkit.write_all(chunk)?;
                carkit.flush()?;
            }
        }

        match carkit.read(&mut rx_buf) {
            Ok(0) => {
                on_stage(WiredCarPlayStage::Disconnected);
                break;
            }
            Ok(n) => {
                let events = link.feed_bytes(&rx_buf[..n])?;
                for ev in events {
                    match ev {
                        LinkEvent::DetectedPeer => {
                            tracing::debug!("iAP2 detect handshake byte synchronized");
                        }
                        LinkEvent::LinkEstablished(syn) => {
                            link_up = true;
                            tracing::info!(
                                "iAP2 Link established over CarKit (max_pkt={}, sessions={})",
                                syn.max_packet_length,
                                syn.sessions.len()
                            );
                            on_stage(WiredCarPlayStage::Iap2LinkEstablished);
                        }
                        LinkEvent::ControlMessage(msg) => {
                            tracing::info!(
                                "iAP2 RX Control message 0x{:04X} ({} params)",
                                msg.message_id,
                                msg.params.len()
                            );
                            let (tx_msgs, step_events) = match control.handle_message(&msg, mfi) {
                                Ok(pair) => pair,
                                Err(Iap2ControlError::AuthenticationFailed) => {
                                    let hint = "iPhone rejeitou certificado MFi de teste (0xAA04) — requer chip MFi CH341, --mfi-local-dir ou --mfi-server-url";
                                    tracing::warn!("{hint}");
                                    on_stage(WiredCarPlayStage::Failed {
                                        summary: hint.to_string(),
                                    });
                                    return Err(CarKitError::Iap2Control(
                                        Iap2ControlError::AuthenticationFailed,
                                    ));
                                }
                                Err(e) => return Err(CarKitError::Iap2Control(e)),
                            };

                            for step in step_events {
                                match step {
                                    ControlStepEvent::IdentificationSent { retry } => {
                                        tracing::info!("Sent IdentificationInformation (retry={retry})");
                                    }
                                    ControlStepEvent::IdentificationAccepted => {
                                        tracing::info!("iPhone accepted iAP2 Identification (0x1D02)!");
                                        on_stage(WiredCarPlayStage::IdentificationAccepted);
                                    }
                                    ControlStepEvent::MfiCertificateSent => {
                                        tracing::info!("Sent MFi AuthenticationCertificate (0xAA01)");
                                        on_stage(WiredCarPlayStage::MfiCertificateSent);
                                    }
                                    ControlStepEvent::MfiChallengeSigned => {
                                        tracing::info!("Signed MFi challenge & sent AuthenticationResponse (0xAA03)");
                                        on_stage(WiredCarPlayStage::MfiChallengeSigned);
                                    }
                                    ControlStepEvent::MfiAuthenticated => {
                                        tracing::info!("MFi Authentication Succeeded (0xAA05)!");
                                        on_stage(WiredCarPlayStage::MfiAuthenticated);
                                    }
                                    ControlStepEvent::CarPlayAvailable {
                                        wired_available,
                                        wireless_available,
                                    } => {
                                        tracing::info!(
                                            "CarPlayAvailability (0x4300): wired={wired_available}, wireless={wireless_available}"
                                        );
                                    }
                                    ControlStepEvent::CarPlaySessionStarted => {
                                        tracing::info!(
                                            "Sent CarPlayStartSession (0x4301) -> {:?} port {}",
                                            ipv6_list,
                                            cfg.airplay_port
                                        );
                                        on_stage(WiredCarPlayStage::CarPlayStartSent {
                                            ipv6_list: ipv6_list.clone(),
                                            airplay_port: cfg.airplay_port,
                                        });
                                    }
                                    ControlStepEvent::WifiCredentialsSent => {
                                        tracing::info!("Sent AccessoryWiFiConfigurationInformation (0x5703) to iPhone");
                                    }
                                    ControlStepEvent::DeviceTransportNotified { bt_id, usb_id } => {
                                        tracing::info!(
                                            "DeviceTransportIdentifierNotification (0x4E0E): bt={bt_id:?}, usb={usb_id:?}"
                                        );
                                    }
                                }
                            }

                            for out_msg in tx_msgs {
                                tracing::info!(
                                    "iAP2 TX Control message 0x{:04X}",
                                    out_msg.message_id
                                );
                                link.send_control_message(&out_msg)?;
                            }
                        }
                        LinkEvent::ExternalAccessoryPayload(data) => {
                            tracing::debug!("iAP2 EA session payload ({} bytes)", data.len());
                        }
                        LinkEvent::FileTransferPayload(data) => {
                            tracing::debug!("iAP2 FileTransfer payload ({} bytes)", data.len());
                        }
                        LinkEvent::LinkReset => {
                            tracing::warn!("iPhone reset iAP2 link");
                            return Ok(true);
                        }
                    }
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // Re-send initial SYN once if no response after 1.5s
                if !link_up && handshake_start.elapsed() > Duration::from_millis(1500) && handshake_start.elapsed() < Duration::from_millis(1650) {
                    link.start_initiator();
                }
            }
            Err(e) => return Err(CarKitError::Io(e)),
        }
    }

    Ok(true)
}
