//! CarPlay `/info` binary plist builder and `AirPlayConfig` settings.

use indexmap::IndexMap;

use crate::bplist::PlistValue;
use crate::hid::{knob_hid_device, media_hid_device, telephony_hid_device, touch_hid_device};

pub const MAIN_DISPLAY_UUID: &str = "b7e6c5a0-1111-4000-8000-000000000001";
pub const ALT_DISPLAY_UUID: &str = "b7e6c5a0-2222-4000-8000-000000000002";

pub const CARPLAY_FEATURES: u64 = 0x615653aee2;
pub const CARPLAY_AUDIO_FEATURES: u64 = 0x10004540a00;
pub const CARPLAY_FEATURES_NO_AUDIO: u64 = CARPLAY_FEATURES & !CARPLAY_AUDIO_FEATURES;

#[derive(Debug, Clone)]
pub struct AirPlayDisplayConfig {
    pub width_pixels: u16,
    pub height_pixels: u16,
    pub width_physical_mm: u16,
    pub height_physical_mm: u16,
    pub fps: u16,
    pub primary_input_device: u64,
}

impl Default for AirPlayDisplayConfig {
    fn default() -> Self {
        Self {
            width_pixels: 1280,
            height_pixels: 720,
            width_physical_mm: 155,
            height_physical_mm: 87,
            fps: 60,
            primary_input_device: 1, // Touchscreen
        }
    }
}

#[derive(Debug, Clone)]
pub struct AirPlayConfig {
    pub device_name: String,
    pub model: String,
    pub manufacturer: String,
    pub device_id: String,
    pub bt_mac: String,
    pub source_version: String,
    pub right_hand_drive: bool,
    pub disable_audio_output: bool,
    pub microphone_enabled: bool,
    pub entertainment_sample_rate: u32,
    pub hevc: bool,
    pub oem_label: String,
    pub main_display: AirPlayDisplayConfig,
    pub cluster_display: Option<AirPlayDisplayConfig>,
}

impl Default for AirPlayConfig {
    fn default() -> Self {
        Self {
            device_name: "CarPlay-RS".to_string(),
            model: "CarPlayRS1,1".to_string(),
            manufacturer: "OpenCarPlay".to_string(),
            device_id: "AA:BB:CC:11:22:33".to_string(),
            bt_mac: "AA:BB:CC:11:22:34".to_string(),
            source_version: "690.7.1".to_string(),
            right_hand_drive: false,
            disable_audio_output: false,
            microphone_enabled: true,
            entertainment_sample_rate: 48_000,
            hevc: false,
            oem_label: "Home".to_string(),
            main_display: AirPlayDisplayConfig::default(),
            cluster_display: None,
        }
    }
}

impl AirPlayConfig {
    pub fn features_mask(&self) -> u64 {
        if self.disable_audio_output {
            CARPLAY_FEATURES_NO_AUDIO
        } else {
            CARPLAY_FEATURES
        }
    }

    /// Formats the 64-bit `features` mask for `_airplay._tcp` TXT records (`"0xLLLLLLLL,0xHH"`).
    pub fn bonjour_features_txt(&self) -> String {
        let f = self.features_mask();
        let lo = f & 0xFFFF_FFFF;
        let hi = f >> 32;
        format!("0x{lo:x},0x{hi:x}")
    }
}

pub fn build_info_plist(config: &AirPlayConfig) -> PlistValue {
    let mut displays = vec![display_entry(&config.main_display, 110, MAIN_DISPLAY_UUID)];
    if let Some(cluster) = &config.cluster_display {
        displays.push(display_entry(cluster, 111, ALT_DISPLAY_UUID));
    }

    let mut info = IndexMap::new();
    info.insert(
        "sourceVersion".to_string(),
        PlistValue::from(config.source_version.as_str()),
    );
    info.insert(
        "features".to_string(),
        PlistValue::Uint(config.features_mask()),
    );
    info.insert("statusFlags".to_string(), PlistValue::Uint(4));
    info.insert("model".to_string(), PlistValue::from(config.model.as_str()));
    info.insert(
        "manufacturer".to_string(),
        PlistValue::from(config.manufacturer.as_str()),
    );
    info.insert(
        "deviceID".to_string(),
        PlistValue::from(config.device_id.as_str()),
    );
    info.insert(
        "bluetoothIDs".to_string(),
        PlistValue::Array(vec![PlistValue::from(config.bt_mac.as_str())]),
    );
    info.insert(
        "name".to_string(),
        PlistValue::from(config.device_name.as_str()),
    );
    info.insert(
        "rightHandDrive".to_string(),
        PlistValue::Bool(config.right_hand_drive),
    );
    info.insert("keepAliveLowPower".to_string(), PlistValue::Bool(false));
    info.insert(
        "keepAliveSendStatsAsBody".to_string(),
        PlistValue::Bool(false),
    );
    info.insert("modes".to_string(), build_modes());

    if !config.disable_audio_output {
        info.insert("audioLatencies".to_string(), build_audio_latencies());
        info.insert(
            "audioFormats".to_string(),
            build_audio_formats(config.entertainment_sample_rate, config.microphone_enabled),
        );
    }

    info.insert(
        "extendedFeatures".to_string(),
        PlistValue::Array(vec![
            PlistValue::from("vocoderInfo"),
            PlistValue::from("enhancedRequestCarUI"),
        ]),
    );
    info.insert("displays".to_string(), PlistValue::Array(displays));
    info.insert(
        "hidDevices".to_string(),
        PlistValue::Array(vec![
            touch_hid_device(
                config.main_display.width_pixels,
                config.main_display.height_pixels,
                MAIN_DISPLAY_UUID,
            ),
            knob_hid_device(MAIN_DISPLAY_UUID),
            media_hid_device(MAIN_DISPLAY_UUID),
            telephony_hid_device(MAIN_DISPLAY_UUID),
        ]),
    );

    if config.hevc {
        info.insert("hevcInfo".to_string(), PlistValue::Dict(IndexMap::new()));
    }

    PlistValue::Dict(info)
}

fn display_entry(d: &AirPlayDisplayConfig, stream_type: u64, uuid: &str) -> PlistValue {
    let safe_area = plist_dict! {
        "widthPixels" => u64::from(d.width_pixels),
        "heightPixels" => u64::from(d.height_pixels),
        "originXPixels" => 0u64,
        "originYPixels" => 0u64,
        "drawUIOutsideSafeArea" => true,
    };
    let view_area = plist_dict! {
        "widthPixels" => u64::from(d.width_pixels),
        "heightPixels" => u64::from(d.height_pixels),
        "originXPixels" => 0u64,
        "originYPixels" => 0u64,
        "safeArea" => safe_area,
    };
    plist_dict! {
        "uuid" => uuid,
        "type" => stream_type,
        "maxFPS" => u64::from(d.fps),
        "widthPixels" => u64::from(d.width_pixels),
        "heightPixels" => u64::from(d.height_pixels),
        "widthPhysical" => u64::from(d.width_physical_mm),
        "heightPhysical" => u64::from(d.height_physical_mm),
        "features" => 0x0Au64, // High-fidelity touch (0x08) | Knobs (0x02)
        "primaryInputDevice" => d.primary_input_device,
        "uiAppearanceMode" => 0u64,
        "uiAppearanceSetting" => 0u64,
        "mapAppearanceMode" => 0u64,
        "mapAppearanceSetting" => 0u64,
        "viewAreas" => PlistValue::Array(vec![view_area]),
        "initialViewArea" => 0u64,
    }
}

fn resource_entry(resource_id: u64) -> PlistValue {
    plist_dict! {
        "resourceID" => resource_id,
        "transferType" => 1u64,
        "transferPriority" => 100u64,
        "takeConstraint" => 100u64,
        "borrowConstraint" => 100u64,
        "unborrowConstraint" => 100u64,
    }
}

fn build_modes() -> PlistValue {
    plist_dict! {
        "resources" => PlistValue::Array(vec![resource_entry(1), resource_entry(2)]),
        "appStates" => PlistValue::Array(vec![
            plist_dict! { "appStateID" => 2u64, "state" => false },
            plist_dict! { "appStateID" => 1u64, "speechMode" => -1i64 },
            plist_dict! { "appStateID" => 3u64, "state" => false },
        ]),
    }
}

fn build_audio_latencies() -> PlistValue {
    let base = |t: u64, audio_type: Option<&str>| -> PlistValue {
        let mut m = IndexMap::new();
        m.insert("type".to_string(), PlistValue::Uint(t));
        m.insert("inputLatencyMicros".to_string(), PlistValue::Uint(0));
        m.insert("outputLatencyMicros".to_string(), PlistValue::Uint(0));
        if let Some(at) = audio_type {
            m.insert("audioType".to_string(), PlistValue::from(at));
        }
        PlistValue::Dict(m)
    };
    PlistValue::Array(vec![
        base(100, None),
        base(100, Some("default")),
        base(100, Some("media")),
        base(100, Some("telephony")),
        base(100, Some("speechRecognition")),
        base(100, Some("alert")),
        base(101, None),
        base(101, Some("default")),
        base(102, Some("default")),
    ])
}

fn build_audio_formats(entertainment_rate: u32, microphone: bool) -> PlistValue {
    let is_48 = entertainment_rate == 48_000;
    let pcm_voice = 0x3FCu64;
    let pcm = pcm_voice | if is_48 { 0xC000 } else { 0xC00 };
    let pcm_mono = 0x154u64 | if is_48 { 0x4000 } else { 0x400 };
    let opus = 0x7000_0000u64;
    let aac_lc = if is_48 { 0x80_0000u64 } else { 0x40_0000u64 };
    let pcm_in = microphone.then_some(pcm_mono);
    let wireless_in = microphone.then_some(pcm_mono | opus);

    let fmt = |t: u64, at: &str, out_fmt: u64, in_fmt: Option<u64>| -> PlistValue {
        let mut m = IndexMap::new();
        m.insert("type".to_string(), PlistValue::Uint(t));
        m.insert("audioType".to_string(), PlistValue::from(at));
        m.insert("audioOutputFormats".to_string(), PlistValue::Uint(out_fmt));
        if let Some(inp) = in_fmt {
            m.insert("audioInputFormats".to_string(), PlistValue::Uint(inp));
        }
        PlistValue::Dict(m)
    };

    PlistValue::Array(vec![
        fmt(100, "compatibility", pcm, pcm_in),
        fmt(101, "compatibility", pcm, None),
        fmt(100, "default", pcm | opus, wireless_in),
        fmt(100, "alert", pcm | opus, None),
        fmt(100, "media", pcm, None),
        fmt(100, "telephony", pcm_mono | opus, wireless_in),
        fmt(100, "speechRecognition", pcm_mono | opus, wireless_in),
        fmt(101, "default", pcm | opus, None),
        fmt(102, "media", aac_lc, None),
    ])
}
