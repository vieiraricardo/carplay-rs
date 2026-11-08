//! Wireless CarPlay 5 GHz Wi-Fi Access Point (`hostapd` WPA2-PSK) and Bluetooth iAP2 SDP UUID helpers
//! for embedded Linux boards (Radxa Zero 3W / AIC8800D80, Orange Pi Zero 3 / AW859A, etc.).

/// Official Apple Wireless iAP2 over Bluetooth RFCOMM 128-bit SDP Service Class UUID.
pub const IAP2_BLUETOOTH_UUID: &str = "00000000-deca-fade-deca-deafdecacafe";

/// Wireless CarPlay Access Point settings advertised to the iPhone during `0x5703` & `0x4301`.
#[derive(Debug, Clone)]
pub struct WirelessApConfig {
    pub interface: String,
    pub ssid: String,
    pub passphrase: String,
    /// 5 GHz non-DFS channel (`36` = 5180 MHz or `149` = 5745 MHz recommended for CarPlay 60fps).
    pub channel: u8,
    pub country_code: String,
    pub bssid: Option<[u8; 6]>,
}

impl Default for WirelessApConfig {
    fn default() -> Self {
        Self {
            interface: "wlan0".to_string(),
            ssid: "CarPlay-RS-5G".to_string(),
            passphrase: "carplayrs2026".to_string(),
            channel: 36,
            country_code: "BR".to_string(),
            bssid: None,
        }
    }
}

impl WirelessApConfig {
    /// Generates a minimal, fast-starting `hostapd.conf` tuned for 5 GHz 802.11ac Wireless CarPlay
    /// (WMM QoS enabled for low-latency RTP audio + H.264 video).
    pub fn to_hostapd_conf(&self) -> String {
        format!(
            "interface={iface}\n\
             driver=nl80211\n\
             ssid={ssid}\n\
             country_code={cc}\n\
             hw_mode=a\n\
             channel={ch}\n\
             ieee80211n=1\n\
             ieee80211ac=1\n\
             wmm_enabled=1\n\
             auth_algs=1\n\
             wpa=2\n\
             wpa_passphrase={psk}\n\
             wpa_key_mgmt=WPA-PSK\n\
             rsn_pairwise=CCMP\n",
            iface = self.interface,
            ssid = self.ssid,
            cc = self.country_code,
            ch = self.channel,
            psk = self.passphrase,
        )
    }
}

/// Discovers the local host Bluetooth controller MAC address for Wireless CarPlay onboarding.
pub fn discover_host_bluetooth_mac() -> Option<[u8; 6]> {
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = std::process::Command::new("/usr/sbin/system_profiler")
            .arg("SPBluetoothDataType")
            .output()
        {
            if let Ok(text) = std::str::from_utf8(&out.stdout) {
                let mut in_controller = false;
                for line in text.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("Bluetooth Controller:") {
                        in_controller = true;
                        continue;
                    }
                    if in_controller && trimmed.starts_with("Address:") {
                        if let Some(mac_str) = trimmed.strip_prefix("Address:").map(str::trim) {
                            if let Some(mac) = parse_mac_hex(mac_str) {
                                return Some(mac);
                            }
                        }
                    }
                    if in_controller
                        && !trimmed.starts_with("Address:")
                        && !trimmed.starts_with("State:")
                        && !trimmed.starts_with("Chipset:")
                        && line.starts_with("      ")
                        && !line.starts_with("          ")
                    {
                        in_controller = false;
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        for hci in &["hci0", "hci1"] {
            let path = format!("/sys/class/bluetooth/{hci}/address");
            if let Ok(s) = std::fs::read_to_string(&path) {
                if let Some(mac) = parse_mac_hex(s.trim()) {
                    return Some(mac);
                }
            }
        }
    }

    None
}

pub fn parse_mac_hex(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = if s.contains(':') {
        s.split(':').collect()
    } else if s.contains('-') {
        s.split('-').collect()
    } else {
        return None;
    };
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(p.trim(), 16).ok()?;
    }
    if mac != [0u8; 6] {
        Some(mac)
    } else {
        None
    }
}
