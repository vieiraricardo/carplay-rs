//! `carplay-iap2`: Apple iAP2 Link Layer, `0x4040` CSM framing, Identification, MFi over iAP2,
//! and Wired/Wireless CarPlay session bootstrap.

pub mod catalog;
pub mod control;
pub mod link;
pub mod wire;

pub use catalog::*;
pub use control::{
    CarPlayStartConfig, CarPlayTransportParams, ControlStepEvent, Iap2ControlClient,
    Iap2ControlError, IdentificationConfig, TransportDeclaration,
};
pub use link::{
    Iap2LinkEngine, Iap2LinkError, LinkEvent, LinkPacket, LinkState, SessionDescriptor, SynPayload,
    CONTROL_SESSION_ID, EA_SESSION_ID, FILE_TRANSFER_SESSION_ID, IAP2_DETECT_SEQUENCE,
};
pub use wire::{Iap2BodyBuilder, Iap2BodyReader, Iap2CsmFramer, Iap2Message, Iap2Param, Iap2WireError};

#[cfg(test)]
mod tests {
    use super::*;
    use carplay_mfi::LocalP256MfiClient;

    #[test]
    fn csm_roundtrip_and_stream_framing() {
        let mut b = Iap2BodyBuilder::new();
        b.put_string(0, "CarPlay-RS")
            .put_u16(1, 1500)
            .put_u16_list(6, &[0xAA01, 0x4301])
            .put_group(16, |g| {
                g.put_u16(0, 0);
                g.put_string(1, "USBHostTransport");
                g.put_none(2);
            })
            .unwrap();
        let msg = b.build_message(MSG_IDENTIFICATION_INFORMATION);
        let wire = msg.encode().unwrap();

        // Feed fragmented chunks with leading noise into Iap2CsmFramer
        let mut framer = Iap2CsmFramer::new();
        assert!(framer.push(&[0x00, 0xFF]).unwrap().is_empty());
        assert!(framer.push(&wire[..5]).unwrap().is_empty());
        let parsed = framer.push(&wire[5..]).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].message_id, MSG_IDENTIFICATION_INFORMATION);
        let r = parsed[0].reader();
        assert_eq!(r.string(0).unwrap().as_deref(), Some("CarPlay-RS"));
        assert_eq!(r.u16(1), Some(1500));
        assert_eq!(r.u16_list(6), vec![0xAA01, 0x4301]);
        let grp = r.group(16).unwrap().unwrap();
        let gr = Iap2BodyReader::new(&grp);
        assert_eq!(gr.string(1).unwrap().as_deref(), Some("USBHostTransport"));
        assert!(gr.has(2));
    }

    #[test]
    fn link_handshake_and_csm_delivery() {
        let mut accessory = Iap2LinkEngine::default();
        accessory.start_initiator();

        let detect = accessory.poll_transmit().unwrap();
        assert_eq!(detect, IAP2_DETECT_SEQUENCE);
        let syn_wire = accessory.poll_transmit().unwrap();
        let syn_pkt = LinkPacket::decode(&syn_wire).unwrap();
        assert_eq!(syn_pkt.control, link::CTRL_SYN);

        // Simulate iPhone replying with SYN+ACK
        let peer_syn_ack = LinkPacket {
            control: link::CTRL_SYN | link::CTRL_ACK,
            seq: 42,
            ack: syn_pkt.seq,
            session_id: 0,
            payload: SynPayload::default().encode(),
        };
        let events = accessory.feed_bytes(&peer_syn_ack.encode()).unwrap();
        assert_eq!(accessory.state(), LinkState::Established);
        assert!(events
            .iter()
            .any(|e| matches!(e, LinkEvent::LinkEstablished(_))));

        // Drain final ACK
        let final_ack = LinkPacket::decode(&accessory.poll_transmit().unwrap()).unwrap();
        assert_eq!(final_ack.control, link::CTRL_ACK);

        // Simulate iPhone sending StartIdentification (0x1D00) over Control Session 10
        let start_id = Iap2BodyBuilder::new()
            .build_message(MSG_START_IDENTIFICATION)
            .encode()
            .unwrap();
        let data_pkt = LinkPacket {
            control: link::CTRL_ACK,
            seq: 43,
            ack: final_ack.seq,
            session_id: CONTROL_SESSION_ID,
            payload: start_id,
        };
        let events = accessory.feed_bytes(&data_pkt.encode()).unwrap();
        assert!(events.iter().any(|e| matches!(
            e,
            LinkEvent::ControlMessage(m) if m.message_id == MSG_START_IDENTIFICATION
        )));
    }

    #[test]
    fn full_control_session_identification_mfi_and_carplay_start() {
        let mfi = LocalP256MfiClient::ephemeral_for_testing();
        let ident = IdentificationConfig::default();
        let start_cfg = CarPlayStartConfig {
            transport: CarPlayTransportParams::Wired {
                ipv6_addresses: vec!["fe80::1%ncm0".to_string()],
            },
            airplay_port: 7000,
            device_identifier: Some("AA:BB:CC:DD:EE:FF".to_string()),
            ed25519_public_key_hex: "01".repeat(32),
            source_version: "690.7.1".to_string(),
        };
        let mut client = Iap2ControlClient::new(ident, start_cfg);

        // 1. StartIdentification -> IdentificationInformation
        let (tx, _) = client
            .handle_message(
                &Iap2BodyBuilder::new().build_message(MSG_START_IDENTIFICATION),
                &mfi,
            )
            .unwrap();
        assert_eq!(tx[0].message_id, MSG_IDENTIFICATION_INFORMATION);

        // 2. IdentificationRejected with unsupported message 0x4157 -> retries without 0x4157
        let mut rej = Iap2BodyBuilder::new();
        rej.put_u16_list(6, &[MSG_START_COMMUNICATIONS_UPDATES]);
        let (tx, ev) = client
            .handle_message(&rej.build_message(MSG_IDENTIFICATION_REJECTED), &mfi)
            .unwrap();
        assert_eq!(
            ev,
            vec![ControlStepEvent::IdentificationSent { retry: true }]
        );
        assert!(!tx[0]
            .reader()
            .u16_list(6)
            .contains(&MSG_START_COMMUNICATIONS_UPDATES));

        // 3. IdentificationAccepted
        client
            .handle_message(
                &Iap2BodyBuilder::new().build_message(MSG_IDENTIFICATION_ACCEPTED),
                &mfi,
            )
            .unwrap();
        assert!(client.is_identified());

        // 4. RequestAuthenticationCertificate -> AuthenticationCertificate
        let (tx, _) = client
            .handle_message(
                &Iap2BodyBuilder::new().build_message(MSG_REQUEST_AUTH_CERTIFICATE),
                &mfi,
            )
            .unwrap();
        assert_eq!(tx[0].message_id, MSG_AUTH_CERTIFICATE);

        // 5. RequestAuthenticationChallengeResponse -> AuthenticationResponse (64B P-256 signature)
        let mut ch = Iap2BodyBuilder::new();
        ch.put_bytes(0, &[0xAB; 32]);
        let (tx, _) = client
            .handle_message(
                &ch.build_message(MSG_REQUEST_AUTH_CHALLENGE_RESPONSE),
                &mfi,
            )
            .unwrap();
        assert_eq!(tx[0].message_id, MSG_AUTH_RESPONSE);
        assert_eq!(tx[0].reader().bytes(0).unwrap().len(), 64);

        // 6. AuthenticationSucceeded -> PowerSourceUpdate + subscriptions
        let (tx, _) = client
            .handle_message(
                &Iap2BodyBuilder::new().build_message(MSG_AUTH_SUCCEEDED),
                &mfi,
            )
            .unwrap();
        assert!(client.is_authenticated());
        assert_eq!(tx[0].message_id, MSG_POWER_SOURCE_UPDATE);

        // 7. CarPlayAvailability -> CarPlayStartSession (0x4301)
        let mut avail = Iap2BodyBuilder::new();
        avail.put_u8(0, 1);
        let (tx, ev) = client
            .handle_message(&avail.build_message(MSG_CARPLAY_AVAILABILITY), &mfi)
            .unwrap();
        assert_eq!(tx[0].message_id, MSG_CARPLAY_START_SESSION);
        assert!(ev.contains(&ControlStepEvent::CarPlaySessionStarted));
    }

    #[test]
    fn dual_wired_with_wireless_onboarding_session() {
        let mfi = LocalP256MfiClient::ephemeral_for_testing();
        let ident = IdentificationConfig {
            transport: TransportDeclaration::DualWiredWithWirelessOnboarding {
                interface_number: 3,
                bluetooth_mac: [0x6C, 0x7E, 0x67, 0xC8, 0x1C, 0xD0],
                bluetooth_name: "CarPlay-RS".to_string(),
                wireless_ssid: "MinhaRedeWiFi".to_string(),
            },
            ..IdentificationConfig::default()
        };
        let start_cfg = CarPlayStartConfig {
            transport: CarPlayTransportParams::DualWiredWithWirelessOnboarding {
                wired_ipv6_addresses: vec!["fe80::1%en9".to_string()],
                ssid: "MinhaRedeWiFi".to_string(),
                passphrase: "senha_super_secreta".to_string(),
                bssid: Some([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]),
                channel: 36,
                security_type: 1,
                wireless_ipv6_addresses: vec!["192.168.1.50".to_string()],
            },
            airplay_port: 7000,
            device_identifier: Some("AA:BB:CC:DD:EE:FF".to_string()),
            ed25519_public_key_hex: "01".repeat(32),
            source_version: "690.7.1".to_string(),
        };
        let mut client = Iap2ControlClient::new(ident, start_cfg);

        // 1. Identification advertises Wi-Fi config capabilities
        let (tx, _) = client
            .handle_message(
                &Iap2BodyBuilder::new().build_message(MSG_START_IDENTIFICATION),
                &mfi,
            )
            .unwrap();
        let r = tx[0].reader();
        let sent_msgs = r.u16_list(6);
        let recv_msgs = r.u16_list(7);
        assert!(sent_msgs.contains(&MSG_ACCESSORY_WIFI_CONFIG_INFO));
        assert!(recv_msgs.contains(&MSG_REQUEST_ACCESSORY_WIFI_CONFIG));
        assert!(recv_msgs.contains(&MSG_DEVICE_TRANSPORT_IDENTIFIER_NOTIFICATION));
        // Verify groups 16, 17, 24 are all present
        assert!(r.group(16).unwrap().is_some());
        assert!(r.group(17).unwrap().is_some());
        assert!(r.group(24).unwrap().is_some());

        // 2. RequestAccessoryWiFiConfiguration (0x5702) -> AccessoryWiFiConfigurationInformation (0x5703)
        let (tx, ev) = client
            .handle_message(
                &Iap2BodyBuilder::new().build_message(MSG_REQUEST_ACCESSORY_WIFI_CONFIG),
                &mfi,
            )
            .unwrap();
        assert_eq!(tx[0].message_id, MSG_ACCESSORY_WIFI_CONFIG_INFO);
        assert!(ev.contains(&ControlStepEvent::WifiCredentialsSent));
        let wifi_r = tx[0].reader();
        assert_eq!(wifi_r.bytes(0).unwrap(), &[0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]);
        assert_eq!(wifi_r.string(1).unwrap().as_deref(), Some("MinhaRedeWiFi"));
        assert_eq!(wifi_r.string(2).unwrap().as_deref(), Some("senha_super_secreta"));
        assert_eq!(wifi_r.u8(3), Some(1));
        assert_eq!(wifi_r.u8(4), Some(36));

        // 3. DeviceTransportIdentifierNotification (0x4E0E) -> Resends 0x5703
        let mut dtin = Iap2BodyBuilder::new();
        dtin.put_string(0, "AA:BB:CC:DD:EE:FF");
        dtin.put_string(1, "00008110-001E2C3A0123401E");
        let (tx, ev) = client
            .handle_message(&dtin.build_message(MSG_DEVICE_TRANSPORT_IDENTIFIER_NOTIFICATION), &mfi)
            .unwrap();
        assert_eq!(tx[0].message_id, MSG_ACCESSORY_WIFI_CONFIG_INFO);
        assert!(ev.contains(&ControlStepEvent::WifiCredentialsSent));

        // 4. CarPlayAvailability -> CarPlayStartSession (0x4301) with both Wired (Group 0) and Wireless (Group 1)
        let mut avail = Iap2BodyBuilder::new();
        avail.put_u8(0, 1);
        let (tx, ev) = client
            .handle_message(&avail.build_message(MSG_CARPLAY_AVAILABILITY), &mfi)
            .unwrap();
        assert_eq!(tx[0].message_id, MSG_CARPLAY_START_SESSION);
        assert!(ev.contains(&ControlStepEvent::CarPlaySessionStarted));

        let start_r = tx[0].reader();
        // Group 0: Wired IPv6
        let g0 = start_r.group(0).unwrap().unwrap();
        let g0_r = Iap2BodyReader::new(&g0);
        assert_eq!(g0_r.string(0).unwrap().as_deref(), Some("fe80::1%en9"));

        // Group 1: Wireless parameters
        let g1 = start_r.group(1).unwrap().unwrap();
        let g1_r = Iap2BodyReader::new(&g1);
        assert_eq!(g1_r.string(0).unwrap().as_deref(), Some("MinhaRedeWiFi"));
        assert_eq!(g1_r.string(1).unwrap().as_deref(), Some("senha_super_secreta"));
        assert_eq!(g1_r.u8(2), Some(36));
        assert_eq!(g1_r.string(3).unwrap().as_deref(), Some("192.168.1.50"));
        assert_eq!(g1_r.u8(4), Some(1));
    }
}
