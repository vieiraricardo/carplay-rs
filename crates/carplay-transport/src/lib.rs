//! `carplay-transport`: Wired USB (`rusb` Apple role switch, CDC-NCM `NTB16`, Ethernet IPv6 NDP,
//! `USBMUX` v2 pseudo-TCP, `lockdownd`) and Wireless CarPlay (5 GHz AP + Bluetooth iAP2) transports.

pub mod carkit;
pub mod ch341_usb;
pub mod ethernet_ipv6;
pub mod lockdown;
pub mod ncm_net;
pub mod ntb16;
pub mod usb;
pub mod usbmux;
pub mod usbmuxd_client;
pub mod wireless;

pub use carkit::{
    open_carkit_service, run_wired_carplay_once, CarKitError, CarKitStream, WiredCarPlayStage,
    WiredSessionConfig,
};
pub use ch341_usb::{try_open_ch341_mfi, Ch341UsbI2cTransport};
pub use ethernet_ipv6::{
    icmpv6_checksum, ipv6_multicast_mac, rewrite_ndp_link_layer_mac, EthernetIpv6Frame,
};
pub use lockdown::{
    build_query_type_xml, build_start_carkit_service_xml, build_start_session_xml,
    encode_lockdown_frame, LockdownFrameBuffer, CARKIT_SERVICE_NAME,
};
pub use ncm_net::{discover_ncm_interfaces, select_wired_ipv6_addresses, NcmInterfaceCandidate};
pub use ntb16::{decode_ntb16, encode_ntb16, Ntb16Error};
pub use usb::{
    request_carplay_usb_mode_if_needed, scan_connected_iphones, BulkEndpoints, DiscoveredIphone,
    IphoneUsbSession, APPLE_VID,
};
pub use usbmux::{
    PseudoTcpSegment, UsbMuxError, UsbMuxFrame, UsbMuxFrameBuffer, LOCKDOWND_PORT, PROTO_TCP,
};
pub use usbmuxd_client::{
    connect_tcp, list_usb_devices, read_buid, read_pair_record, UsbmuxDevice, UsbmuxPairRecord,
    UsbmuxdError, DEFAULT_USBMUXD_SOCKET,
};
pub use wireless::{
    discover_host_bluetooth_mac, parse_mac_hex, WirelessApConfig, IAP2_BLUETOOTH_UUID,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntb16_packs_and_unpacks_multiple_ethernet_frames() {
        let f1 = [0x11u8; 64];
        let f2 = [0x22u8; 128];
        let ntb = encode_ntb16(7, &[&f1, &f2]);
        let decoded = decode_ntb16(&ntb).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0], f1);
        assert_eq!(decoded[1], f2);
    }

    #[test]
    fn ethernet_ipv6_rewrites_neighbor_advertisement_target_mac_and_checksum() {
        let mut ipv6 = vec![0u8; 40 + 32];
        ipv6[0] = 0x60; // IPv6 version 6
        ipv6[4..6].copy_from_slice(&32u16.to_be_bytes()); // payload len = 32
        ipv6[6] = 58; // Next Header = ICMPv6
        ipv6[7] = 255; // Hop limit
        ipv6[8] = 0xFE;
        ipv6[9] = 0x80;
        ipv6[23] = 0x01; // fe80::1
        ipv6[24] = 0xFE;
        ipv6[25] = 0x80;
        ipv6[39] = 0x02; // fe80::2

        // ICMPv6 Neighbor Advertisement (type 136) + Target Link-Layer Address option (type 2, len 1 = 8 bytes)
        ipv6[40] = 136;
        ipv6[40 + 24] = 2; // Option Type = Target Link-Layer Address
        ipv6[40 + 25] = 1; // Length = 1 (8 octets)
        ipv6[40 + 26..40 + 32].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01]);

        let new_mac = [0x02, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E];
        assert!(rewrite_ndp_link_layer_mac(&mut ipv6, &new_mac));
        assert_eq!(&ipv6[40 + 26..40 + 32], &new_mac);

        // Verify recomputed ICMPv6 checksum validates to 0xFFFF (one's complement 0)
        let mut src = [0u8; 16];
        let mut dst = [0u8; 16];
        src.copy_from_slice(&ipv6[8..24]);
        dst.copy_from_slice(&ipv6[24..40]);
        assert_eq!(icmpv6_checksum(&src, &dst, &ipv6[40..]), 0xFFFF);
    }

    #[test]
    fn usbmux_v2_and_pseudo_tcp_roundtrip() {
        let tcp = PseudoTcpSegment {
            src_port: 49152,
            dst_port: LOCKDOWND_PORT,
            seq: 1000,
            ack: 2000,
            flags: usbmux::TCP_PSH | usbmux::TCP_ACK,
            window: 65535,
            payload: b"hello lockdownd".to_vec(),
        };
        let mux = UsbMuxFrame {
            protocol: PROTO_TCP,
            tx_seq: 1,
            rx_seq: 2,
            payload: tcp.encode(),
        };
        let wire = mux.encode();
        let mut buf = UsbMuxFrameBuffer::new();
        assert!(buf.push(&wire[..10]).unwrap().is_empty());
        let frames = buf.push(&wire[10..]).unwrap();
        assert_eq!(frames.len(), 1);
        let parsed_tcp = PseudoTcpSegment::decode(&frames[0].payload).unwrap();
        assert_eq!(parsed_tcp, tcp);
    }
}
