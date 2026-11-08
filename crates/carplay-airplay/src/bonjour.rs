//! Pure-Rust Bonjour / mDNS service publisher (`_airplay._tcp.local.`) and iPhone CarPlay controller
//! browser + HTTP connect probe (`_carplay-ctrl._tcp.local.` -> `GET /ctrl-int/1/connect`).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use mdns_sd::{IfKind, ServiceDaemon, ServiceEvent, ServiceInfo};

use crate::crypto::AirPlayIdentity;
use crate::info_plist::AirPlayConfig;

pub const AIRPLAY_SERVICE_TYPE: &str = "_airplay._tcp.local.";
pub const CARPLAY_CTRL_SERVICE_TYPE: &str = "_carplay-ctrl._tcp.local.";

pub struct CarPlayBonjour {
    daemon: ServiceDaemon,
    fullname: Option<String>,
    running: Arc<AtomicBool>,
    browse_thread: Option<JoinHandle<()>>,
}

impl CarPlayBonjour {
    pub fn start(
        config: &AirPlayConfig,
        identity: &AirPlayIdentity,
        port: u16,
        local_ips: &[IpAddr],
    ) -> anyhow::Result<Self> {
        let daemon = ServiceDaemon::new()?;

        // Exclude dormant macOS virtual/point-to-point interfaces (e.g. `nan0`, `awdl0`, `llw0`, `utun*`)
        // that hold link-local IPv6 addresses while powered down and return ENETDOWN (os error 50).
        let mut ignored_ifs = vec![
            IfKind::Name("nan0".into()),
            IfKind::Name("awdl0".into()),
            IfKind::Name("llw0".into()),
            IfKind::Name("ap1".into()),
            IfKind::Name("bridge0".into()),
            IfKind::Name("anri0".into()),
            IfKind::Name("anri1".into()),
        ];
        for i in 0..4 {
            ignored_ifs.push(IfKind::Name(format!("anpi{i}")));
        }
        for i in 0..16 {
            ignored_ifs.push(IfKind::Name(format!("utun{i}")));
        }
        let _ = daemon.disable_interface(ignored_ifs);

        let mut props = HashMap::new();
        props.insert("deviceid".to_string(), config.device_id.clone());
        props.insert("features".to_string(), config.bonjour_features_txt());
        props.insert("flags".to_string(), "0x4".to_string());
        props.insert("model".to_string(), config.model.clone());
        props.insert("srcvers".to_string(), config.source_version.clone());
        props.insert("protovers".to_string(), "1.1".to_string());
        props.insert("pi".to_string(), identity.pairing_id.clone());
        props.insert("pk".to_string(), identity.public_key_hex());

        let host_name = format!(
            "{}.local.",
            config
                .device_name
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
                .collect::<String>()
        );

        let ip_str = local_ips
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(",");

        let svc = ServiceInfo::new(
            AIRPLAY_SERVICE_TYPE,
            &config.device_name,
            &host_name,
            ip_str.as_str(),
            port,
            Some(props),
        )?;
        let fullname = svc.get_fullname().to_string();
        if ip_str.is_empty() {
            let svc_auto = svc.enable_addr_auto();
            daemon.register(svc_auto)?;
        } else {
            daemon.register(svc)?;
        }

        let running = Arc::new(AtomicBool::new(true));
        let running_bg = Arc::clone(&running);
        let rx = daemon.browse(CARPLAY_CTRL_SERVICE_TYPE)?;
        let device_id_hex = config.device_id.replace(':', "");
        let srcvers = config.source_version.clone();

        let browse_thread = thread::Builder::new()
            .name("carplay-mdns-browse".into())
            .spawn(move || {
                while running_bg.load(Ordering::Relaxed) {
                    let Ok(ev) = rx.recv_timeout(Duration::from_millis(300)) else {
                        continue;
                    };
                    if let ServiceEvent::ServiceResolved(info) = ev {
                        let port = info.get_port();
                        for ip in info.get_addresses() {
                            let target = SocketAddr::new(*ip, port);
                            tracing::info!("Discovered iPhone _carplay-ctrl._tcp at {target}, sending connect probe");
                            let _ = send_carplay_connect_probe(target, &srcvers, &device_id_hex);
                        }
                    }
                }
            })?;

        Ok(Self {
            daemon,
            fullname: Some(fullname),
            running,
            browse_thread: Some(browse_thread),
        })
    }

    pub fn shutdown(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(name) = self.fullname.take() {
            let _ = self.daemon.unregister(&name);
        }
        let _ = self.daemon.shutdown();
        if let Some(t) = self.browse_thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for CarPlayBonjour {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Sends the CarPlay reverse HTTP wake/connect probe to the iPhone's `_carplay-ctrl._tcp` service.
pub fn send_carplay_connect_probe(
    target: SocketAddr,
    source_version: &str,
    receiver_device_id_no_colons: &str,
) -> std::io::Result<u16> {
    let mut stream = TcpStream::connect_timeout(&target, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;

    let host_hdr = match target.ip() {
        IpAddr::V6(v6) => format!("[{v6}]:{}", target.port()),
        IpAddr::V4(v4) => format!("{v4}:{}", target.port()),
    };
    let req = format!(
        "GET /ctrl-int/1/connect HTTP/1.1\r\n\
         Host: {host_hdr}\r\n\
         User-Agent: AirPlay/{source_version}\r\n\
         AirPlay-Receiver-Device-ID: {receiver_device_id_no_colons}\r\n\
         Connection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes())?;
    stream.flush()?;

    let mut resp = [0u8; 256];
    let n = stream.read(&mut resp).unwrap_or(0);
    let text = String::from_utf8_lossy(&resp[..n]);
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    Ok(status)
}
