//! iAP2 Identification, MFi Authentication, and Wired/Wireless CarPlay session state machines.

use carplay_mfi::{MfiAuthenticator, MfiCertificateType, MfiError};
use thiserror::Error;

use crate::catalog::*;
use crate::wire::{Iap2BodyBuilder, Iap2BodyReader, Iap2Message, Iap2WireError};

#[derive(Debug, Error)]
pub enum Iap2ControlError {
    #[error("wire codec error: {0}")]
    Wire(#[from] Iap2WireError),
    #[error("MFi authentication error: {0}")]
    Mfi(#[from] MfiError),
    #[error("iPhone rejected identification twice")]
    IdentificationRejected,
    #[error("iPhone reported MFi authentication failure (0xAA04)")]
    AuthenticationFailed,
    #[error("missing challenge parameter in 0xAA02")]
    MissingChallenge,
}

#[derive(Debug, Clone)]
pub enum TransportDeclaration {
    WiredUsbHost {
        interface_number: u8,
    },
    Wireless {
        bluetooth_mac: [u8; 6],
        bluetooth_name: String,
    },
    DualWiredWithWirelessOnboarding {
        interface_number: u8,
        bluetooth_mac: [u8; 6],
        bluetooth_name: String,
        wireless_ssid: String,
    },
}

#[derive(Debug, Clone)]
pub struct IdentificationConfig {
    pub name: String,
    pub model_identifier: String,
    pub manufacturer: String,
    pub serial_number: String,
    pub firmware_version: String,
    pub hardware_version: String,
    pub current_language: String,
    pub supported_languages: Vec<String>,
    pub ea_protocol_name: Option<String>,
    pub available_current_ma: u16,
    pub transport: TransportDeclaration,
}

impl Default for IdentificationConfig {
    fn default() -> Self {
        Self {
            name: "CarPlay-RS".to_string(),
            model_identifier: "CarPlayRS1,1".to_string(),
            manufacturer: "OpenCarPlay".to_string(),
            serial_number: "CPRS00000001".to_string(),
            firmware_version: "1.0.0".to_string(),
            hardware_version: "1.0.0".to_string(),
            current_language: "en".to_string(),
            supported_languages: vec!["en".to_string()],
            ea_protocol_name: Some("com.shilapi.xcertplay".to_string()),
            available_current_ma: 2400,
            transport: TransportDeclaration::WiredUsbHost {
                interface_number: 3,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub enum CarPlayTransportParams {
    Wired {
        ipv6_addresses: Vec<String>,
    },
    Wireless {
        ssid: String,
        passphrase: String,
        bssid: Option<[u8; 6]>,
        channel: u8,
        security_type: u8,
        ipv6_addresses: Vec<String>,
    },
    DualWiredWithWirelessOnboarding {
        wired_ipv6_addresses: Vec<String>,
        ssid: String,
        passphrase: String,
        bssid: Option<[u8; 6]>,
        channel: u8,
        security_type: u8,
        wireless_ipv6_addresses: Vec<String>,
    },
}

#[derive(Debug, Clone)]
pub struct CarPlayStartConfig {
    pub transport: CarPlayTransportParams,
    pub airplay_port: u32,
    pub device_identifier: Option<String>,
    pub ed25519_public_key_hex: String,
    pub source_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlStepEvent {
    IdentificationSent { retry: bool },
    IdentificationAccepted,
    MfiCertificateSent,
    MfiChallengeSigned,
    MfiAuthenticated,
    CarPlayAvailable {
        wired_available: bool,
        wireless_available: bool,
    },
    CarPlaySessionStarted,
    WifiCredentialsSent,
    DeviceTransportNotified {
        bt_id: Option<String>,
        usb_id: Option<String>,
    },
}

/// High-level iAP2 Control Session coordinator handling Identification, MFi, Power, Wi-Fi config, and CarPlay start.
pub struct Iap2ControlClient {
    ident: IdentificationConfig,
    start_cfg: CarPlayStartConfig,
    sent_messages: Vec<u16>,
    received_messages: Vec<u16>,
    retried_identification: bool,
    identified: bool,
    authenticated: bool,
}

impl Iap2ControlClient {
    pub fn new(ident: IdentificationConfig, start_cfg: CarPlayStartConfig) -> Self {
        let is_wireless_capable = matches!(
            ident.transport,
            TransportDeclaration::Wireless { .. }
                | TransportDeclaration::DualWiredWithWirelessOnboarding { .. }
        ) || matches!(
            start_cfg.transport,
            CarPlayTransportParams::Wireless { .. }
                | CarPlayTransportParams::DualWiredWithWirelessOnboarding { .. }
        );

        let (mut sent_messages, mut received_messages) = match ident.transport {
            TransportDeclaration::WiredUsbHost { .. }
            | TransportDeclaration::DualWiredWithWirelessOnboarding { .. } => (
                default_wired_sent_messages(),
                default_wired_received_messages(),
            ),
            TransportDeclaration::Wireless { .. } => (
                default_wireless_sent_messages(),
                default_wireless_received_messages(),
            ),
        };

        if is_wireless_capable && !matches!(ident.transport, TransportDeclaration::WiredUsbHost { .. }) {
            if !sent_messages.contains(&MSG_ACCESSORY_WIFI_CONFIG_INFO) {
                sent_messages.push(MSG_ACCESSORY_WIFI_CONFIG_INFO);
            }
            if !sent_messages.contains(&MSG_WIRELESS_CARPLAY_UPDATE) {
                sent_messages.push(MSG_WIRELESS_CARPLAY_UPDATE);
            }
            if !received_messages.contains(&MSG_REQUEST_ACCESSORY_WIFI_CONFIG) {
                received_messages.push(MSG_REQUEST_ACCESSORY_WIFI_CONFIG);
            }
            if !received_messages.contains(&MSG_DEVICE_TRANSPORT_IDENTIFIER_NOTIFICATION) {
                received_messages.push(MSG_DEVICE_TRANSPORT_IDENTIFIER_NOTIFICATION);
            }
            if !received_messages.contains(&MSG_WIRELESS_CARPLAY_UPDATE) {
                received_messages.push(MSG_WIRELESS_CARPLAY_UPDATE);
            }
        }

        Self {
            ident,
            start_cfg,
            sent_messages,
            received_messages,
            retried_identification: false,
            identified: false,
            authenticated: false,
        }
    }

    pub fn is_identified(&self) -> bool {
        self.identified
    }

    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    /// Processes one inbound `Iap2Message` from the iPhone and returns `(outbound_messages, events)`.
    pub fn handle_message(
        &mut self,
        msg: &Iap2Message,
        mfi: &dyn MfiAuthenticator,
    ) -> Result<(Vec<Iap2Message>, Vec<ControlStepEvent>), Iap2ControlError> {
        let mut out = Vec::new();
        let mut events = Vec::new();

        match msg.message_id {
            MSG_START_IDENTIFICATION => {
                out.push(self.build_identification_info()?);
                events.push(ControlStepEvent::IdentificationSent { retry: false });
            }

            MSG_IDENTIFICATION_REJECTED => {
                let params_desc: Vec<String> = msg
                    .params
                    .iter()
                    .map(|p| format!("id={} len={} data={}", p.id, p.data.len(), hex::encode(&p.data)))
                    .collect();
                tracing::warn!(
                    "iAP2 IdentificationRejected (0x1D03): params={:?}",
                    params_desc
                );
                if self.retried_identification {
                    return Err(Iap2ControlError::IdentificationRejected);
                }
                self.retried_identification = true;
                let reader = msg.reader();
                // Parameters 6 and 7 list unsupported sent/received message IDs
                let rejected_sent = reader.u16_list(6);
                let rejected_recv = reader.u16_list(7);
                tracing::warn!(
                    "iAP2 IdentificationRejected details: rejected_sent={:04X?}, rejected_recv={:04X?}",
                    rejected_sent,
                    rejected_recv
                );
                if !rejected_sent.is_empty() {
                    self.sent_messages.retain(|id| !rejected_sent.contains(id));
                }
                if !rejected_recv.is_empty() {
                    self.received_messages
                        .retain(|id| !rejected_recv.contains(id));
                }
                out.push(self.build_identification_info()?);
                events.push(ControlStepEvent::IdentificationSent { retry: true });
            }

            MSG_IDENTIFICATION_ACCEPTED => {
                self.identified = true;
                events.push(ControlStepEvent::IdentificationAccepted);
            }

            MSG_REQUEST_AUTH_CERTIFICATE => {
                let mut builder = Iap2BodyBuilder::new();
                match mfi.certificate_type() {
                    MfiCertificateType::Mfi => {
                        let cert = mfi.read_certificate()?;
                        builder.put_bytes(0, &cert);
                    }
                    MfiCertificateType::Baa => {
                        let certs = mfi.baa_certificates()?;
                        builder.put_bytes(0, &certs.leaf);
                        builder.put_u8(1, 1);
                        builder.put_bytes(2, &certs.intermediate);
                    }
                }
                out.push(builder.build_message(MSG_AUTH_CERTIFICATE));
                events.push(ControlStepEvent::MfiCertificateSent);
            }

            MSG_REQUEST_AUTH_CHALLENGE_RESPONSE => {
                let challenge = msg
                    .reader()
                    .bytes(0)
                    .ok_or(Iap2ControlError::MissingChallenge)?;
                let signature = mfi.sign_challenge(challenge)?;
                let mut builder = Iap2BodyBuilder::new();
                builder.put_bytes(0, &signature);
                out.push(builder.build_message(MSG_AUTH_RESPONSE));
                events.push(ControlStepEvent::MfiChallengeSigned);
            }

            MSG_AUTH_FAILED => {
                return Err(Iap2ControlError::AuthenticationFailed);
            }

            MSG_AUTH_SUCCEEDED => {
                self.authenticated = true;
                events.push(ControlStepEvent::MfiAuthenticated);
                if matches!(
                    self.ident.transport,
                    TransportDeclaration::WiredUsbHost { .. }
                        | TransportDeclaration::DualWiredWithWirelessOnboarding { .. }
                ) {
                    // Advertise USB charging power + exact 5 LIVI wired update subscriptions
                    let mut pwr = Iap2BodyBuilder::new();
                    pwr.put_u16(0, self.ident.available_current_ma);
                    pwr.put_u8(1, 1);
                    out.push(pwr.build_message(MSG_POWER_SOURCE_UPDATE));

                    for sub in build_wired_subscriptions(&self.sent_messages)? {
                        out.push(sub);
                    }
                } else if self.sent_messages.contains(&MSG_WIRELESS_CARPLAY_UPDATE) {
                    let mut w = Iap2BodyBuilder::new();
                    w.put_u8(0, 1);
                    out.push(w.build_message(MSG_WIRELESS_CARPLAY_UPDATE));
                }

                // Proactively deliver Wi-Fi configuration credentials to the iPhone
                if let Some(wifi) = self.build_wifi_config_message() {
                    out.push(wifi);
                    events.push(ControlStepEvent::WifiCredentialsSent);
                }
            }

            MSG_REQUEST_ACCESSORY_WIFI_CONFIG => {
                if let Some(wifi) = self.build_wifi_config_message() {
                    out.push(wifi);
                    events.push(ControlStepEvent::WifiCredentialsSent);
                }
            }

            MSG_CARPLAY_AVAILABILITY => {
                let r = msg.reader();
                let wired_available = r
                    .group(0)
                    .ok()
                    .flatten()
                    .and_then(|g| Iap2BodyReader::new(&g).bool(0))
                    .or_else(|| r.bool(0))
                    .unwrap_or(true);
                let wireless_available = r
                    .group(1)
                    .ok()
                    .flatten()
                    .and_then(|g| Iap2BodyReader::new(&g).bool(0))
                    .or_else(|| r.bool(2))
                    .unwrap_or(false);
                events.push(ControlStepEvent::CarPlayAvailable {
                    wired_available,
                    wireless_available,
                });
                out.push(self.build_carplay_start_session()?);
                events.push(ControlStepEvent::CarPlaySessionStarted);
            }

            MSG_DEVICE_TRANSPORT_IDENTIFIER_NOTIFICATION => {
                let r = msg.reader();
                let bt_id = r.string(0)?;
                let usb_id = r.string(1)?;
                events.push(ControlStepEvent::DeviceTransportNotified { bt_id, usb_id });
                if let Some(wifi) = self.build_wifi_config_message() {
                    out.push(wifi);
                    events.push(ControlStepEvent::WifiCredentialsSent);
                }
            }

            _ => {}
        }

        Ok((out, events))
    }

    pub fn build_identification_info(&self) -> Result<Iap2Message, Iap2WireError> {
        let mut b = Iap2BodyBuilder::new();
        b.put_string(0, &self.ident.name);
        b.put_string(1, &self.ident.model_identifier);
        b.put_string(2, &self.ident.manufacturer);
        b.put_string(3, &self.ident.serial_number);
        b.put_string(4, &self.ident.firmware_version);
        b.put_string(5, &self.ident.hardware_version);
        b.put_u16_list(6, &self.sent_messages);
        b.put_u16_list(7, &self.received_messages);

        let is_wired = matches!(self.ident.transport, TransportDeclaration::WiredUsbHost { .. });
        b.put_u8(8, if is_wired { 2 } else { 0 });
        b.put_u16(9, 20);

        if let Some(proto) = &self.ident.ea_protocol_name {
            b.put_group(10, |g| {
                g.put_u8(0, 1);
                g.put_string(1, proto);
                g.put_u8(2, 0);
            })?;
        }

        b.put_string(12, &self.ident.current_language);
        let mut langs_blob = Vec::new();
        for lang in &self.ident.supported_languages {
            langs_blob.extend_from_slice(lang.as_bytes());
            langs_blob.push(0);
        }
        b.put_bytes(13, &langs_blob);

        match &self.ident.transport {
            TransportDeclaration::WiredUsbHost { interface_number } => {
                b.put_group(16, |g| {
                    g.put_u16(0, 0);
                    g.put_string(1, "USBHostTransport");
                    g.put_none(2); // CarPlay supported on this USB Host transport
                    g.put_u8(3, *interface_number);
                    g.put_none(4);
                })?;
            }
            TransportDeclaration::Wireless {
                bluetooth_mac,
                bluetooth_name,
            } => {
                b.put_group(17, |g| {
                    g.put_u16(0, 0);
                    g.put_string(1, "blue");
                    g.put_none(2);
                    g.put_bytes(3, bluetooth_mac);
                    g.put_string(4, "blue");
                    g.put_none(5);
                })?;
                b.put_group(24, |g| {
                    g.put_u16(0, 1);
                    g.put_string(1, bluetooth_name);
                    g.put_none(2);
                    g.put_u16(3, 1);
                    g.put_none(4);
                    g.put_none(5);
                })?;
            }
            TransportDeclaration::DualWiredWithWirelessOnboarding {
                interface_number,
                bluetooth_mac,
                bluetooth_name,
                wireless_ssid,
            } => {
                // Component 0: USB Host Transport
                b.put_group(16, |g| {
                    g.put_u16(0, 0);
                    g.put_string(1, "USBHostTransport");
                    g.put_none(2);
                    g.put_u8(3, *interface_number);
                    g.put_none(4);
                })?;
                // Component 1: Bluetooth Transport
                b.put_group(17, |g| {
                    g.put_u16(0, 1);
                    g.put_string(1, "blue");
                    g.put_none(2);
                    g.put_bytes(3, bluetooth_mac);
                    g.put_string(4, bluetooth_name);
                    g.put_none(5);
                })?;
                // Component 2: Wireless CarPlay Transport (Associated with Component 1)
                b.put_group(24, |g| {
                    g.put_u16(0, 2);
                    g.put_string(1, wireless_ssid);
                    g.put_none(2);
                    g.put_u16(3, 1);
                    g.put_none(4);
                    g.put_none(5);
                })?;
            }
        }

        if self.sent_messages.contains(&MSG_START_ROUTE_GUIDANCE_UPDATES) {
            b.put_group(30, |g| {
                g.put_u16(0, 42);
                g.put_string(1, "RouteGuidance");
                g.put_u16(2, 64);
                g.put_u16(4, 64);
                g.put_u16(6, 8);
                g.put_u16(7, 64);
                g.put_u16(8, 8);
            })?;
        }

        Ok(b.build_message(MSG_IDENTIFICATION_INFORMATION))
    }

    fn build_wifi_config_message(&self) -> Option<Iap2Message> {
        let (ssid, passphrase, bssid, channel, security_type) = match &self.start_cfg.transport {
            CarPlayTransportParams::Wireless {
                ssid,
                passphrase,
                bssid,
                channel,
                security_type,
                ..
            }
            | CarPlayTransportParams::DualWiredWithWirelessOnboarding {
                ssid,
                passphrase,
                bssid,
                channel,
                security_type,
                ..
            } => (ssid, passphrase, bssid, *channel, *security_type),
            _ => return None,
        };

        let mut wifi = Iap2BodyBuilder::new();
        if let Some(mac) = bssid {
            wifi.put_bytes(0, mac);
        }
        wifi.put_string(1, ssid);
        wifi.put_string(2, passphrase);
        wifi.put_u8(3, security_type);
        wifi.put_u8(4, channel);
        tracing::info!("Built AccessoryWiFiConfigurationInformation (0x5703) for SSID '{ssid}'");
        Some(wifi.build_message(MSG_ACCESSORY_WIFI_CONFIG_INFO))
    }

    pub fn build_carplay_start_session(&self) -> Result<Iap2Message, Iap2WireError> {
        let mut b = Iap2BodyBuilder::new();
        match &self.start_cfg.transport {
            CarPlayTransportParams::Wired { ipv6_addresses } => {
                b.put_group(0, |g| {
                    for ip in ipv6_addresses {
                        g.put_string(0, ip);
                    }
                })?;
            }
            CarPlayTransportParams::Wireless {
                ssid,
                passphrase,
                channel,
                security_type,
                ipv6_addresses,
                ..
            } => {
                b.put_group(1, |g| {
                    g.put_string(0, ssid);
                    g.put_string(1, passphrase);
                    g.put_u8(2, *channel);
                    for ip in ipv6_addresses {
                        g.put_string(3, ip);
                    }
                    g.put_u8(4, *security_type);
                })?;
            }
            CarPlayTransportParams::DualWiredWithWirelessOnboarding {
                wired_ipv6_addresses,
                ssid,
                passphrase,
                channel,
                security_type,
                wireless_ipv6_addresses,
                ..
            } => {
                b.put_group(0, |g| {
                    for ip in wired_ipv6_addresses {
                        g.put_string(0, ip);
                    }
                })?;
                b.put_group(1, |g| {
                    g.put_string(0, ssid);
                    g.put_string(1, passphrase);
                    g.put_u8(2, *channel);
                    for ip in wireless_ipv6_addresses {
                        g.put_string(3, ip);
                    }
                    g.put_u8(4, *security_type);
                })?;
            }
        }
        b.put_u32(2, self.start_cfg.airplay_port);
        if let Some(dev_id) = &self.start_cfg.device_identifier {
            b.put_string(3, dev_id);
        }
        b.put_string(4, &self.start_cfg.ed25519_public_key_hex);
        b.put_string(5, &self.start_cfg.source_version);
        Ok(b.build_message(MSG_CARPLAY_START_SESSION))
    }
}

fn build_wired_subscriptions(sent_messages: &[u16]) -> Result<Vec<Iap2Message>, Iap2WireError> {
    let mut subs = Vec::new();
    if sent_messages.contains(&MSG_START_NOW_PLAYING_UPDATES) {
        let mut b = Iap2BodyBuilder::new();
        b.put_group(0, |g| {
            for id in [1, 4, 6, 12, 26] {
                g.put_none(id);
            }
        })?;
        b.put_group(1, |g| {
            for id in [0, 1, 7] {
                g.put_none(id);
            }
        })?;
        subs.push(b.build_message(MSG_START_NOW_PLAYING_UPDATES));
    }
    if sent_messages.contains(&MSG_START_ROUTE_GUIDANCE_UPDATES) {
        let mut b = Iap2BodyBuilder::new();
        b.put_u16(0, 42);
        b.put_none(1);
        b.put_none(2);
        subs.push(b.build_message(MSG_START_ROUTE_GUIDANCE_UPDATES));
    }
    if sent_messages.contains(&MSG_START_POWER_UPDATES) {
        let mut b = Iap2BodyBuilder::new();
        for id in [4, 5, 6] {
            b.put_none(id);
        }
        subs.push(b.build_message(MSG_START_POWER_UPDATES));
    }
    if sent_messages.contains(&MSG_START_COMMUNICATIONS_UPDATES) {
        let mut b = Iap2BodyBuilder::new();
        for id in [0, 4, 5] {
            b.put_none(id);
        }
        subs.push(b.build_message(MSG_START_COMMUNICATIONS_UPDATES));
    }
    if sent_messages.contains(&MSG_START_CALL_STATE_UPDATES) {
        let mut b = Iap2BodyBuilder::new();
        for id in [0, 1, 2, 3, 4, 11] {
            b.put_none(id);
        }
        subs.push(b.build_message(MSG_START_CALL_STATE_UPDATES));
    }
    Ok(subs)
}
