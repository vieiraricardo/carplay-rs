//! Native Unix-socket client for `/var/run/usbmuxd` (macOS and Linux).
//!
//! Allows `carplay-rs` to enumerate USB-connected iPhones, read the host's trusted Lockdown
//! `PairRecord`, and open multiplexed TCP streams to `lockdownd` (`62078`) and
//! `com.apple.carkit.service` without detaching the OS kernel's USB NCM/USBMUX drivers.

use std::io::{Cursor, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use plist::{Dictionary, Integer, Value};
use thiserror::Error;

pub const DEFAULT_USBMUXD_SOCKET: &str = "/var/run/usbmuxd";
const USBMUX_PLIST_VERSION: u32 = 1;
const USBMUX_MSG_PLIST: u32 = 8;

#[derive(Debug, Error)]
pub enum UsbmuxdError {
    #[error("cannot connect to {path}: {source}")]
    SocketConnect {
        path: String,
        source: std::io::Error,
    },
    #[error("usbmuxd I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("usbmuxd plist parse error: {0}")]
    Plist(#[from] plist::Error),
    #[error("iPhone ({udid}) is not paired/trusted with this computer yet — unlock the iPhone and tap 'Confiar / Trust'")]
    DeviceNotPaired { udid: String },
    #[error("usbmuxd returned error code {code} during {operation}")]
    MuxResult {
        operation: &'static str,
        code: i64,
    },
    #[error("missing expected field '{0}' in usbmuxd plist response")]
    MissingField(&'static str),
}

#[derive(Debug, Clone)]
pub struct UsbmuxDevice {
    pub device_id: u64,
    pub serial_number: String,
    pub product_id: u16,
    pub location_id: u64,
}

#[derive(Clone)]
pub struct UsbmuxPairRecord {
    pub host_id: String,
    pub system_buid: String,
    pub host_certificate: Vec<u8>,
    pub host_private_key: Vec<u8>,
    pub root_certificate: Vec<u8>,
    pub root_private_key: Option<Vec<u8>>,
    pub device_certificate: Vec<u8>,
}

impl std::fmt::Debug for UsbmuxPairRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsbmuxPairRecord")
            .field("host_id", &self.host_id)
            .field("system_buid", &self.system_buid)
            .field("host_cert_len", &self.host_certificate.len())
            .field("root_cert_len", &self.root_certificate.len())
            .finish()
    }
}

fn open_usbmuxd_stream(socket_path: &Path) -> Result<UnixStream, UsbmuxdError> {
    let stream = UnixStream::connect(socket_path).map_err(|source| UsbmuxdError::SocketConnect {
        path: socket_path.display().to_string(),
        source,
    })?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(4)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(4)));
    Ok(stream)
}

fn base_request_dict(message_type: &str) -> Dictionary {
    let mut dict = Dictionary::new();
    dict.insert(
        "BundleID".to_string(),
        Value::String("com.opencarplay.carplay-rs".to_string()),
    );
    dict.insert(
        "ClientVersionString".to_string(),
        Value::String("carplay-rs-1.0".to_string()),
    );
    dict.insert(
        "ProgName".to_string(),
        Value::String("carplay-desktop".to_string()),
    );
    dict.insert(
        "kLibUSBMuxVersion".to_string(),
        Value::Integer(Integer::from(3u64)),
    );
    dict.insert(
        "MessageType".to_string(),
        Value::String(message_type.to_string()),
    );
    dict
}

fn send_plist_packet(stream: &mut UnixStream, tag: u32, dict: &Dictionary) -> Result<(), UsbmuxdError> {
    let mut xml = Vec::new();
    plist::to_writer_xml(&mut xml, &Value::Dictionary(dict.clone()))?;
    let total_len = (16 + xml.len()) as u32;
    let mut header = [0u8; 16];
    header[0..4].copy_from_slice(&total_len.to_le_bytes());
    header[4..8].copy_from_slice(&USBMUX_PLIST_VERSION.to_le_bytes());
    header[8..12].copy_from_slice(&USBMUX_MSG_PLIST.to_le_bytes());
    header[12..16].copy_from_slice(&tag.to_le_bytes());
    stream.write_all(&header)?;
    stream.write_all(&xml)?;
    stream.flush()?;
    Ok(())
}

fn recv_plist_packet(stream: &mut UnixStream) -> Result<Dictionary, UsbmuxdError> {
    let mut header = [0u8; 16];
    stream.read_exact(&mut header)?;
    let total_len = u32::from_le_bytes(header[0..4].try_into().unwrap()) as usize;
    if total_len < 16 || total_len > 4 * 1024 * 1024 {
        return Err(UsbmuxdError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid usbmuxd packet length: {total_len}"),
        )));
    }
    let mut payload = vec![0u8; total_len - 16];
    stream.read_exact(&mut payload)?;
    let val = Value::from_reader(Cursor::new(payload))?;
    val.into_dictionary()
        .ok_or(UsbmuxdError::MissingField("root dictionary"))
}

fn check_result_number(dict: &Dictionary, operation: &'static str) -> Result<(), UsbmuxdError> {
    if let Some(num) = dict.get("Number").and_then(Value::as_signed_integer) {
        if num != 0 {
            return Err(UsbmuxdError::MuxResult {
                operation,
                code: num,
            });
        }
    }
    Ok(())
}

/// Lists all USB-connected iOS devices currently visible to `/var/run/usbmuxd`.
pub fn list_usb_devices() -> Result<Vec<UsbmuxDevice>, UsbmuxdError> {
    list_usb_devices_at(Path::new(DEFAULT_USBMUXD_SOCKET))
}

pub fn list_usb_devices_at(socket_path: &Path) -> Result<Vec<UsbmuxDevice>, UsbmuxdError> {
    let mut stream = open_usbmuxd_stream(socket_path)?;
    let req = base_request_dict("ListDevices");
    send_plist_packet(&mut stream, 1, &req)?;
    let resp = recv_plist_packet(&mut stream)?;

    let mut devices = Vec::new();
    let Some(list) = resp.get("DeviceList").and_then(Value::as_array) else {
        return Ok(devices);
    };

    for entry in list {
        let Some(entry_dict) = entry.as_dictionary() else {
            continue;
        };
        let props = entry_dict
            .get("Properties")
            .and_then(Value::as_dictionary)
            .unwrap_or(entry_dict);

        let conn_type = props
            .get("ConnectionType")
            .and_then(Value::as_string)
            .unwrap_or("USB");
        if !conn_type.eq_ignore_ascii_case("USB") {
            continue;
        }

        let Some(device_id) = props
            .get("DeviceID")
            .and_then(Value::as_unsigned_integer)
            .or_else(|| entry_dict.get("DeviceID").and_then(Value::as_unsigned_integer))
        else {
            continue;
        };
        let Some(serial) = props.get("SerialNumber").and_then(Value::as_string) else {
            continue;
        };
        let product_id = props
            .get("ProductID")
            .and_then(Value::as_unsigned_integer)
            .unwrap_or(0) as u16;
        let location_id = props
            .get("LocationID")
            .and_then(Value::as_unsigned_integer)
            .unwrap_or(0);

        devices.push(UsbmuxDevice {
            device_id,
            serial_number: serial.trim_end_matches('\0').to_string(),
            product_id,
            location_id,
        });
    }

    Ok(devices)
}

/// Reads the host machine's `SystemBUID` from `usbmuxd`.
pub fn read_buid() -> Result<String, UsbmuxdError> {
    read_buid_at(Path::new(DEFAULT_USBMUXD_SOCKET))
}

pub fn read_buid_at(socket_path: &Path) -> Result<String, UsbmuxdError> {
    let mut stream = open_usbmuxd_stream(socket_path)?;
    let req = base_request_dict("ReadBUID");
    send_plist_packet(&mut stream, 2, &req)?;
    let resp = recv_plist_packet(&mut stream)?;
    check_result_number(&resp, "ReadBUID")?;
    resp.get("BUID")
        .and_then(Value::as_string)
        .map(str::to_string)
        .ok_or(UsbmuxdError::MissingField("BUID"))
}

/// Reads the trusted Lockdown `PairRecord` for `udid` (`SerialNumber` from `list_usb_devices`).
pub fn read_pair_record(udid: &str) -> Result<UsbmuxPairRecord, UsbmuxdError> {
    read_pair_record_at(Path::new(DEFAULT_USBMUXD_SOCKET), udid)
}

pub fn read_pair_record_at(socket_path: &Path, udid: &str) -> Result<UsbmuxPairRecord, UsbmuxdError> {
    let mut stream = open_usbmuxd_stream(socket_path)?;
    let mut req = base_request_dict("ReadPairRecord");
    req.insert(
        "PairRecordID".to_string(),
        Value::String(udid.to_string()),
    );
    send_plist_packet(&mut stream, 3, &req)?;
    let resp = recv_plist_packet(&mut stream)?;

    if let Some(code) = resp.get("Number").and_then(Value::as_signed_integer) {
        if code != 0 {
            // ENOENT (2) or negative code means this Mac/Linux host has not paired with the iPhone yet
            return Err(UsbmuxdError::DeviceNotPaired {
                udid: udid.to_string(),
            });
        }
    }

    let raw_record = resp
        .get("PairRecordData")
        .and_then(Value::as_data)
        .ok_or_else(|| UsbmuxdError::DeviceNotPaired {
            udid: udid.to_string(),
        })?;

    let inner = Value::from_reader(Cursor::new(raw_record))?
        .into_dictionary()
        .ok_or(UsbmuxdError::MissingField("PairRecordData dictionary"))?;

    let host_id = inner
        .get("HostID")
        .and_then(Value::as_string)
        .ok_or(UsbmuxdError::MissingField("HostID"))?
        .to_string();

    let system_buid = match inner.get("SystemBUID").and_then(Value::as_string) {
        Some(s) => s.to_string(),
        None => read_buid_at(socket_path)?,
    };

    let host_certificate = inner
        .get("HostCertificate")
        .and_then(Value::as_data)
        .ok_or(UsbmuxdError::MissingField("HostCertificate"))?
        .to_vec();
    let host_private_key = inner
        .get("HostPrivateKey")
        .and_then(Value::as_data)
        .ok_or(UsbmuxdError::MissingField("HostPrivateKey"))?
        .to_vec();
    let root_certificate = inner
        .get("RootCertificate")
        .and_then(Value::as_data)
        .unwrap_or_default()
        .to_vec();
    let root_private_key = inner
        .get("RootPrivateKey")
        .and_then(Value::as_data)
        .map(<[u8]>::to_vec);
    let device_certificate = inner
        .get("DeviceCertificate")
        .and_then(Value::as_data)
        .unwrap_or_default()
        .to_vec();

    Ok(UsbmuxPairRecord {
        host_id,
        system_buid,
        host_certificate,
        host_private_key,
        root_certificate,
        root_private_key,
        device_certificate,
    })
}

/// Opens a multiplexed TCP connection over USB to `port` (in host byte order, e.g. `62078` for `lockdownd`)
/// on the given `device_id`. Once connected, the returned `UnixStream` carries raw TCP payload bytes.
pub fn connect_tcp(device_id: u64, port: u16) -> Result<UnixStream, UsbmuxdError> {
    connect_tcp_at(Path::new(DEFAULT_USBMUXD_SOCKET), device_id, port)
}

pub fn connect_tcp_at(
    socket_path: &Path,
    device_id: u64,
    port: u16,
) -> Result<UnixStream, UsbmuxdError> {
    let mut stream = open_usbmuxd_stream(socket_path)?;
    let mut req = base_request_dict("Connect");
    req.insert(
        "DeviceID".to_string(),
        Value::Integer(Integer::from(device_id)),
    );
    // usbmuxd expects PortNumber in network byte order (`htons(port)`).
    req.insert(
        "PortNumber".to_string(),
        Value::Integer(Integer::from(u64::from(port.to_be()))),
    );
    send_plist_packet(&mut stream, 4, &req)?;
    let resp = recv_plist_packet(&mut stream)?;
    check_result_number(&resp, "Connect")?;
    Ok(stream)
}
