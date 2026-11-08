//! Apple `lockdownd` 4-byte length-prefixed XML plist framing and `com.apple.carkit.service`
//! request builders for wired CarPlay over USBMUX.

pub const CARKIT_SERVICE_NAME: &str = "com.apple.carkit.service";

/// Wraps an XML (or binary) plist payload with `lockdownd`'s 4-byte big-endian length header.
pub fn encode_lockdown_frame(plist_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + plist_bytes.len());
    out.extend_from_slice(&(plist_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(plist_bytes);
    out
}

/// Incremental reassembly buffer for `lockdownd` length-prefixed plist messages.
#[derive(Debug, Default)]
pub struct LockdownFrameBuffer {
    buf: Vec<u8>,
}

impl LockdownFrameBuffer {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn push(&mut self, incoming: &[u8]) -> Vec<Vec<u8>> {
        self.buf.extend_from_slice(incoming);
        let mut frames = Vec::new();
        while self.buf.len() >= 4 {
            let len = u32::from_be_bytes(self.buf[0..4].try_into().unwrap()) as usize;
            if len > 4 * 1024 * 1024 || self.buf.len() < 4 + len {
                break;
            }
            self.buf.drain(..4);
            let payload: Vec<u8> = self.buf.drain(..len).collect();
            frames.push(payload);
        }
        frames
    }
}

pub fn build_query_type_xml(label: &str) -> Vec<u8> {
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>Request</key>
    <string>QueryType</string>
</dict>
</plist>
"#
    );
    encode_lockdown_frame(xml.as_bytes())
}

pub fn build_start_session_xml(label: &str, host_id: &str, system_buid: &str) -> Vec<u8> {
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>HostID</key>
    <string>{host_id}</string>
    <key>Label</key>
    <string>{label}</string>
    <key>Request</key>
    <string>StartSession</string>
    <key>SystemBUID</key>
    <string>{system_buid}</string>
</dict>
</plist>
"#
    );
    encode_lockdown_frame(xml.as_bytes())
}

pub fn build_start_carkit_service_xml(label: &str) -> Vec<u8> {
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>Request</key>
    <string>StartService</string>
    <key>Service</key>
    <string>{CARKIT_SERVICE_NAME}</string>
</dict>
</plist>
"#
    );
    encode_lockdown_frame(xml.as_bytes())
}
