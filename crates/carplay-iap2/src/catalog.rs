//! CarPlay iAP2 message ID catalog and human-readable names.

/// Identification messages
pub const MSG_START_IDENTIFICATION: u16 = 0x1D00;
pub const MSG_IDENTIFICATION_INFORMATION: u16 = 0x1D01;
pub const MSG_IDENTIFICATION_ACCEPTED: u16 = 0x1D02;
pub const MSG_IDENTIFICATION_REJECTED: u16 = 0x1D03;
pub const MSG_CANCEL_IDENTIFICATION: u16 = 0x1D05;
pub const MSG_IDENTIFICATION_INFO_UPDATE: u16 = 0x1D06;

/// MFi authentication messages
pub const MSG_REQUEST_AUTH_CERTIFICATE: u16 = 0xAA00;
pub const MSG_AUTH_CERTIFICATE: u16 = 0xAA01;
pub const MSG_REQUEST_AUTH_CHALLENGE_RESPONSE: u16 = 0xAA02;
pub const MSG_AUTH_RESPONSE: u16 = 0xAA03;
pub const MSG_AUTH_FAILED: u16 = 0xAA04;
pub const MSG_AUTH_SUCCEEDED: u16 = 0xAA05;
pub const MSG_ACCESSORY_AUTH_SERIAL_NUMBER: u16 = 0xAA10;

/// CarPlay availability & session bootstrap
pub const MSG_CARPLAY_AVAILABILITY: u16 = 0x4300;
pub const MSG_CARPLAY_START_SESSION: u16 = 0x4301;

/// Wireless CarPlay & Wi-Fi credential exchange
pub const MSG_WIRELESS_CARPLAY_UPDATE: u16 = 0x4E0D;
pub const MSG_DEVICE_TRANSPORT_IDENTIFIER_NOTIFICATION: u16 = 0x4E0E;
pub const MSG_REQUEST_ACCESSORY_WIFI_CONFIG: u16 = 0x5702;
pub const MSG_ACCESSORY_WIFI_CONFIG_INFO: u16 = 0x5703;

/// Power, NowPlaying, Telephony, Route Guidance & Vehicle Status
pub const MSG_START_POWER_UPDATES: u16 = 0xAE00;
pub const MSG_POWER_UPDATE: u16 = 0xAE01;
pub const MSG_STOP_POWER_UPDATES: u16 = 0xAE02;
pub const MSG_POWER_SOURCE_UPDATE: u16 = 0xAE03;

pub const MSG_START_NOW_PLAYING_UPDATES: u16 = 0x5000;
pub const MSG_NOW_PLAYING_UPDATE: u16 = 0x5001;
pub const MSG_STOP_NOW_PLAYING_UPDATES: u16 = 0x5002;

pub const MSG_START_ROUTE_GUIDANCE_UPDATES: u16 = 0x5200;
pub const MSG_ROUTE_GUIDANCE_UPDATE: u16 = 0x5201;
pub const MSG_ROUTE_GUIDANCE_MANEUVER_UPDATE: u16 = 0x5202;
pub const MSG_STOP_ROUTE_GUIDANCE_UPDATES: u16 = 0x5203;
pub const MSG_LANE_GUIDANCE_INFO_UPDATE: u16 = 0x5204;

pub const MSG_START_CALL_STATE_UPDATES: u16 = 0x4154;
pub const MSG_CALL_STATE_UPDATE: u16 = 0x4155;
pub const MSG_STOP_CALL_STATE_UPDATES: u16 = 0x4156;

pub const MSG_START_COMMUNICATIONS_UPDATES: u16 = 0x4157;
pub const MSG_COMMUNICATIONS_UPDATE: u16 = 0x4158;
pub const MSG_STOP_COMMUNICATIONS_UPDATES: u16 = 0x4159;

pub const MSG_START_EXTERNAL_ACCESSORY_PROTOCOL_SESSION: u16 = 0xEA00;
pub const MSG_STOP_EXTERNAL_ACCESSORY_PROTOCOL_SESSION: u16 = 0xEA01;
pub const MSG_STATUS_EXTERNAL_ACCESSORY_PROTOCOL_SESSION: u16 = 0xEA03;

pub fn message_name(id: u16) -> &'static str {
    match id {
        MSG_START_IDENTIFICATION => "StartIdentification",
        MSG_IDENTIFICATION_INFORMATION => "IdentificationInformation",
        MSG_IDENTIFICATION_ACCEPTED => "IdentificationAccepted",
        MSG_IDENTIFICATION_REJECTED => "IdentificationRejected",
        MSG_CANCEL_IDENTIFICATION => "CancelIdentification",
        MSG_IDENTIFICATION_INFO_UPDATE => "IdentificationInformationUpdate",
        MSG_REQUEST_AUTH_CERTIFICATE => "RequestAuthenticationCertificate",
        MSG_AUTH_CERTIFICATE => "AuthenticationCertificate",
        MSG_REQUEST_AUTH_CHALLENGE_RESPONSE => "RequestAuthenticationChallengeResponse",
        MSG_AUTH_RESPONSE => "AuthenticationResponse",
        MSG_AUTH_FAILED => "AuthenticationFailed",
        MSG_AUTH_SUCCEEDED => "AuthenticationSucceeded",
        MSG_CARPLAY_AVAILABILITY => "CarPlayAvailability",
        MSG_CARPLAY_START_SESSION => "CarPlayStartSession",
        MSG_WIRELESS_CARPLAY_UPDATE => "WirelessCarPlayUpdate",
        MSG_DEVICE_TRANSPORT_IDENTIFIER_NOTIFICATION => "DeviceTransportIdentifierNotification",
        MSG_REQUEST_ACCESSORY_WIFI_CONFIG => "RequestAccessoryWiFiConfiguration",
        MSG_ACCESSORY_WIFI_CONFIG_INFO => "AccessoryWiFiConfigurationInformation",
        MSG_START_POWER_UPDATES => "StartPowerUpdates",
        MSG_POWER_UPDATE => "PowerUpdate",
        MSG_STOP_POWER_UPDATES => "StopPowerUpdates",
        MSG_POWER_SOURCE_UPDATE => "PowerSourceUpdate",
        MSG_START_NOW_PLAYING_UPDATES => "StartNowPlayingUpdates",
        MSG_NOW_PLAYING_UPDATE => "NowPlayingUpdate",
        MSG_STOP_NOW_PLAYING_UPDATES => "StopNowPlayingUpdates",
        MSG_START_ROUTE_GUIDANCE_UPDATES => "StartRouteGuidanceUpdates",
        MSG_ROUTE_GUIDANCE_UPDATE => "RouteGuidanceUpdate",
        MSG_ROUTE_GUIDANCE_MANEUVER_UPDATE => "RouteGuidanceManeuverUpdate",
        MSG_STOP_ROUTE_GUIDANCE_UPDATES => "StopRouteGuidanceUpdates",
        MSG_START_CALL_STATE_UPDATES => "StartCallStateUpdates",
        MSG_CALL_STATE_UPDATE => "CallStateUpdate",
        MSG_STOP_CALL_STATE_UPDATES => "StopCallStateUpdates",
        MSG_START_COMMUNICATIONS_UPDATES => "StartCommunicationsUpdates",
        MSG_COMMUNICATIONS_UPDATE => "CommunicationsUpdate",
        MSG_STOP_COMMUNICATIONS_UPDATES => "StopCommunicationsUpdates",
        MSG_START_EXTERNAL_ACCESSORY_PROTOCOL_SESSION => "StartExternalAccessoryProtocolSession",
        MSG_STOP_EXTERNAL_ACCESSORY_PROTOCOL_SESSION => "StopExternalAccessoryProtocolSession",
        MSG_STATUS_EXTERNAL_ACCESSORY_PROTOCOL_SESSION => "StatusExternalAccessoryProtocolSession",
        _ => "UnknownIap2Message",
    }
}

/// Default list of messages sent by a wired CarPlay accessory.
pub fn default_wired_sent_messages() -> Vec<u16> {
    vec![
        MSG_AUTH_CERTIFICATE,
        MSG_AUTH_RESPONSE,
        MSG_CARPLAY_START_SESSION,
        MSG_START_POWER_UPDATES,
        MSG_STOP_POWER_UPDATES,
        MSG_POWER_SOURCE_UPDATE,
        MSG_START_NOW_PLAYING_UPDATES,
        MSG_STOP_NOW_PLAYING_UPDATES,
        MSG_START_ROUTE_GUIDANCE_UPDATES,
        MSG_STOP_ROUTE_GUIDANCE_UPDATES,
        MSG_START_CALL_STATE_UPDATES,
        MSG_STOP_CALL_STATE_UPDATES,
        MSG_START_COMMUNICATIONS_UPDATES,
        MSG_STOP_COMMUNICATIONS_UPDATES,
    ]
}

/// Default list of messages received from the iPhone by a wired CarPlay accessory.
pub fn default_wired_received_messages() -> Vec<u16> {
    vec![
        MSG_REQUEST_AUTH_CERTIFICATE,
        MSG_REQUEST_AUTH_CHALLENGE_RESPONSE,
        MSG_AUTH_FAILED,
        MSG_AUTH_SUCCEEDED,
        MSG_START_EXTERNAL_ACCESSORY_PROTOCOL_SESSION,
        MSG_STOP_EXTERNAL_ACCESSORY_PROTOCOL_SESSION,
        MSG_NOW_PLAYING_UPDATE,
        MSG_ROUTE_GUIDANCE_UPDATE,
        MSG_ROUTE_GUIDANCE_MANEUVER_UPDATE,
        MSG_LANE_GUIDANCE_INFO_UPDATE,
        MSG_POWER_UPDATE,
        MSG_COMMUNICATIONS_UPDATE,
        MSG_CALL_STATE_UPDATE,
        MSG_CARPLAY_AVAILABILITY,
    ]
}

/// Default list of messages sent by a wireless CarPlay bootstrap accessory (over Bluetooth/USB).
pub fn default_wireless_sent_messages() -> Vec<u16> {
    let mut list = default_wired_sent_messages();
    list.push(MSG_ACCESSORY_WIFI_CONFIG_INFO);
    list.push(MSG_WIRELESS_CARPLAY_UPDATE);
    list
}

/// Default list of messages received by a wireless CarPlay bootstrap accessory.
pub fn default_wireless_received_messages() -> Vec<u16> {
    let mut list = default_wired_received_messages();
    list.push(MSG_REQUEST_ACCESSORY_WIFI_CONFIG);
    list.push(MSG_DEVICE_TRANSPORT_IDENTIFIER_NOTIFICATION);
    list
}
