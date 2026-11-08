//! iAP2 Link Layer state machine (`FF 55 02 00 EE 10` detection + `FF 5A` reliable packet engine).

use std::collections::VecDeque;
use thiserror::Error;

use crate::wire::{Iap2CsmFramer, Iap2Message, Iap2WireError};

/// 6-byte iAP2 presence detection sequence (`FF 55 02 00 EE 10`).
pub const IAP2_DETECT_SEQUENCE: [u8; 6] = [0xFF, 0x55, 0x02, 0x00, 0xEE, 0x10];
/// 6-byte iAP2 unsupported / fallback response (`FF 55 0E 00 13 FF ...` prefix check).
pub const PACKET_SOM: [u8; 2] = [0xFF, 0x5A];
pub const LINK_HEADER_LEN: usize = 9;

pub const CTRL_SYN: u8 = 0x80;
pub const CTRL_ACK: u8 = 0x40;
pub const CTRL_EAK: u8 = 0x20;
pub const CTRL_RST: u8 = 0x10;
pub const CTRL_SLP: u8 = 0x08;

pub const INITIAL_SEQ: u8 = 99;
pub const CONTROL_SESSION_ID: u8 = 10;
pub const EA_SESSION_ID: u8 = 11;
pub const FILE_TRANSFER_SESSION_ID: u8 = 12;

#[derive(Debug, Error)]
pub enum Iap2LinkError {
    #[error("link packet shorter than 9 bytes ({0})")]
    TooShort(usize),
    #[error("invalid link packet magic: {0:02x?}")]
    BadMagic([u8; 2]),
    #[error("header checksum mismatch")]
    HeaderChecksumMismatch,
    #[error("payload checksum mismatch")]
    PayloadChecksumMismatch,
    #[error("wire decode error: {0}")]
    Wire(#[from] Iap2WireError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    Detecting,
    Negotiating,
    Established,
    Reset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionDescriptor {
    pub id: u8,
    pub session_type: u8,
    pub version: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynPayload {
    pub version: u8,
    pub max_outstanding: u8,
    pub max_packet_length: u16,
    pub retransmit_timeout_ms: u16,
    pub cumulative_ack_timeout_ms: u16,
    pub max_retransmissions: u8,
    pub max_cumulative_acks: u8,
    pub sessions: Vec<SessionDescriptor>,
}

impl Default for SynPayload {
    fn default() -> Self {
        Self {
            version: 1,
            max_outstanding: 4,
            max_packet_length: 65535,
            retransmit_timeout_ms: 4000,
            cumulative_ack_timeout_ms: 500,
            max_retransmissions: 4,
            max_cumulative_acks: 3,
            sessions: vec![
                SessionDescriptor {
                    id: CONTROL_SESSION_ID,
                    session_type: 0,
                    version: 2,
                },
                SessionDescriptor {
                    id: EA_SESSION_ID,
                    session_type: 2,
                    version: 1,
                },
                SessionDescriptor {
                    id: FILE_TRANSFER_SESSION_ID,
                    session_type: 1,
                    version: 2,
                },
            ],
        }
    }
}

impl SynPayload {
    /// Zero-acknowledgement SYN configuration used by wired `com.apple.carkit.service` and AirPlay Type-130 tunnels.
    pub fn wired_default() -> Self {
        Self {
            retransmit_timeout_ms: 0,
            cumulative_ack_timeout_ms: 0,
            max_retransmissions: 0,
            max_cumulative_acks: 0,
            ..Self::default()
        }
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(10 + self.sessions.len() * 3);
        out.push(self.version);
        out.push(self.max_outstanding);
        out.extend_from_slice(&self.max_packet_length.to_be_bytes());
        out.extend_from_slice(&self.retransmit_timeout_ms.to_be_bytes());
        out.extend_from_slice(&self.cumulative_ack_timeout_ms.to_be_bytes());
        out.push(self.max_retransmissions);
        out.push(self.max_cumulative_acks);
        for s in &self.sessions {
            out.push(s.id);
            out.push(s.session_type);
            out.push(s.version);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 10 {
            return None;
        }
        let version = bytes[0];
        let max_outstanding = bytes[1];
        let max_packet_length = u16::from_be_bytes([bytes[2], bytes[3]]);
        let retransmit_timeout_ms = u16::from_be_bytes([bytes[4], bytes[5]]);
        let cumulative_ack_timeout_ms = u16::from_be_bytes([bytes[6], bytes[7]]);
        let max_retransmissions = bytes[8];
        let max_cumulative_acks = bytes[9];
        let mut sessions = Vec::new();
        for chunk in bytes[10..].chunks_exact(3) {
            sessions.push(SessionDescriptor {
                id: chunk[0],
                session_type: chunk[1],
                version: chunk[2],
            });
        }
        Some(Self {
            version,
            max_outstanding,
            max_packet_length,
            retransmit_timeout_ms,
            cumulative_ack_timeout_ms,
            max_retransmissions,
            max_cumulative_acks,
            sessions,
        })
    }
}

/// Computes the two's-complement modulo-256 iAP2 checksum byte (`(-sum) & 0xFF`).
pub fn iap2_checksum(bytes: &[u8]) -> u8 {
    let sum: u8 = bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    0u8.wrapping_sub(sum)
}

pub fn verify_iap2_checksum(bytes_with_checksum: &[u8]) -> bool {
    let sum: u8 = bytes_with_checksum
        .iter()
        .fold(0u8, |acc, &b| acc.wrapping_add(b));
    sum == 0
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkPacket {
    pub control: u8,
    pub seq: u8,
    pub ack: u8,
    pub session_id: u8,
    pub payload: Vec<u8>,
}

impl LinkPacket {
    pub fn encode(&self) -> Vec<u8> {
        let total_len = if self.payload.is_empty() {
            LINK_HEADER_LEN
        } else {
            LINK_HEADER_LEN + self.payload.len() + 1
        };
        let mut out = Vec::with_capacity(total_len);
        out.extend_from_slice(&PACKET_SOM);
        out.extend_from_slice(&(total_len as u16).to_be_bytes());
        out.push(self.control);
        out.push(self.seq);
        out.push(self.ack);
        out.push(self.session_id);
        let hdr_cksum = iap2_checksum(&out);
        out.push(hdr_cksum);
        if !self.payload.is_empty() {
            out.extend_from_slice(&self.payload);
            out.push(iap2_checksum(&self.payload));
        }
        out
    }

    pub fn decode(raw: &[u8]) -> Result<Self, Iap2LinkError> {
        if raw.len() < LINK_HEADER_LEN {
            return Err(Iap2LinkError::TooShort(raw.len()));
        }
        if raw[0..2] != PACKET_SOM {
            return Err(Iap2LinkError::BadMagic([raw[0], raw[1]]));
        }
        if !verify_iap2_checksum(&raw[0..LINK_HEADER_LEN]) {
            return Err(Iap2LinkError::HeaderChecksumMismatch);
        }
        let total_len = u16::from_be_bytes([raw[2], raw[3]]) as usize;
        if total_len < LINK_HEADER_LEN || total_len > raw.len() {
            return Err(Iap2LinkError::TooShort(raw.len()));
        }
        let control = raw[4];
        let seq = raw[5];
        let ack = raw[6];
        let session_id = raw[7];
        let payload = if total_len > LINK_HEADER_LEN {
            if !verify_iap2_checksum(&raw[LINK_HEADER_LEN..total_len]) {
                return Err(Iap2LinkError::PayloadChecksumMismatch);
            }
            raw[LINK_HEADER_LEN..total_len - 1].to_vec()
        } else {
            Vec::new()
        };
        Ok(Self {
            control,
            seq,
            ack,
            session_id,
            payload,
        })
    }
}

#[derive(Debug, Clone)]
pub enum LinkEvent {
    DetectedPeer,
    LinkEstablished(SynPayload),
    ControlMessage(Iap2Message),
    ExternalAccessoryPayload(Vec<u8>),
    FileTransferPayload(Vec<u8>),
    LinkReset,
}

/// Complete iAP2 Link Engine managing presence detection, SYN/ACK negotiation, sequence numbers, and CSM framing.
#[derive(Debug)]
pub struct Iap2LinkEngine {
    state: LinkState,
    local_seq: u8,
    peer_seq: u8,
    peer_max_packet_length: u16,
    peer_max_cumulative_acks: u8,
    sent_syn: bool,
    peer_syn_received: bool,
    control_session_id: u8,
    syn_config: SynPayload,
    rx_buf: Vec<u8>,
    tx_queue: VecDeque<Vec<u8>>,
    csm_framer: Iap2CsmFramer,
}

impl Default for Iap2LinkEngine {
    fn default() -> Self {
        Self::new(SynPayload::default())
    }
}

impl Iap2LinkEngine {
    pub fn new(syn_config: SynPayload) -> Self {
        let ack_cfg = syn_config.max_cumulative_acks;
        let max_pkt = syn_config.max_packet_length;
        Self {
            state: LinkState::Detecting,
            local_seq: INITIAL_SEQ,
            peer_seq: 0,
            peer_max_packet_length: max_pkt,
            peer_max_cumulative_acks: ack_cfg,
            sent_syn: false,
            peer_syn_received: false,
            control_session_id: CONTROL_SESSION_ID,
            syn_config,
            rx_buf: Vec::new(),
            tx_queue: VecDeque::new(),
            csm_framer: Iap2CsmFramer::new(),
        }
    }

    pub fn new_wired() -> Self {
        Self::new(SynPayload::wired_default())
    }

    pub fn state(&self) -> LinkState {
        self.state
    }

    /// Initiates wired/tunnel link detection by queueing `FF 55 02 00 EE 10` and `SYN`.
    pub fn start_initiator(&mut self) {
        self.tx_queue.push_back(IAP2_DETECT_SEQUENCE.to_vec());
        self.state = LinkState::Negotiating;
        self.sent_syn = true;
        let syn = LinkPacket {
            control: CTRL_SYN,
            seq: self.local_seq,
            ack: 0,
            session_id: 0,
            payload: self.syn_config.encode(),
        };
        self.tx_queue.push_back(syn.encode());
    }

    /// Drains all outbound raw link bytes ready to be written to the transport (USB, Bluetooth RFCOMM, or TLS carkit).
    pub fn poll_transmit(&mut self) -> Option<Vec<u8>> {
        self.tx_queue.pop_front()
    }

    /// Queues an `Iap2Message` over the Control Session once the link is established,
    /// splitting into `peer_max_packet_length` segments if needed (e.g. large MFi certificates).
    pub fn send_control_message(&mut self, msg: &Iap2Message) -> Result<(), Iap2LinkError> {
        let encoded = msg.encode()?;
        let max_payload = usize::from(self.peer_max_packet_length)
            .saturating_sub(LINK_HEADER_LEN + 1)
            .max(128);
        for chunk in encoded.chunks(max_payload) {
            self.local_seq = self.local_seq.wrapping_add(1);
            let pkt = LinkPacket {
                control: CTRL_ACK,
                seq: self.local_seq,
                ack: self.peer_seq,
                session_id: self.control_session_id,
                payload: chunk.to_vec(),
            };
            self.tx_queue.push_back(pkt.encode());
        }
        Ok(())
    }

    /// Feeds incoming transport bytes into the link engine and returns high-level events.
    pub fn feed_bytes(&mut self, incoming: &[u8]) -> Result<Vec<LinkEvent>, Iap2LinkError> {
        self.rx_buf.extend_from_slice(incoming);
        let mut events = Vec::new();

        loop {
            if self.rx_buf.len() >= IAP2_DETECT_SEQUENCE.len()
                && self.rx_buf.starts_with(&IAP2_DETECT_SEQUENCE)
            {
                self.rx_buf.drain(..IAP2_DETECT_SEQUENCE.len());
                events.push(LinkEvent::DetectedPeer);
                if self.state == LinkState::Detecting {
                    self.tx_queue.push_back(IAP2_DETECT_SEQUENCE.to_vec());
                    self.state = LinkState::Negotiating;
                }
                continue;
            }

            if self.rx_buf.len() < LINK_HEADER_LEN {
                break;
            }

            if self.rx_buf[0..2] != PACKET_SOM {
                // Scan forward to either FF 55 or FF 5A
                if let Some(pos) = self
                    .rx_buf
                    .windows(2)
                    .skip(1)
                    .position(|w| w == PACKET_SOM || w == [0xFF, 0x55])
                {
                    self.rx_buf.drain(..pos + 1);
                    continue;
                } else {
                    let keep = usize::from(self.rx_buf.last() == Some(&0xFF));
                    let drain_len = self.rx_buf.len() - keep;
                    self.rx_buf.drain(..drain_len);
                    break;
                }
            }

            if !verify_iap2_checksum(&self.rx_buf[0..LINK_HEADER_LEN]) {
                self.rx_buf.drain(..2);
                continue;
            }

            let total_len = u16::from_be_bytes([self.rx_buf[2], self.rx_buf[3]]) as usize;
            if total_len < LINK_HEADER_LEN {
                self.rx_buf.drain(..2);
                continue;
            }
            if self.rx_buf.len() < total_len {
                break;
            }

            let frame: Vec<u8> = self.rx_buf.drain(..total_len).collect();
            let pkt = LinkPacket::decode(&frame)?;
            self.handle_packet(pkt, &mut events)?;
        }

        Ok(events)
    }

    fn handle_packet(
        &mut self,
        pkt: LinkPacket,
        events: &mut Vec<LinkEvent>,
    ) -> Result<(), Iap2LinkError> {
        if (pkt.control & CTRL_RST) != 0 {
            self.state = LinkState::Reset;
            events.push(LinkEvent::LinkReset);
            return Ok(());
        }

        if (pkt.control & CTRL_SYN) != 0 {
            self.peer_seq = pkt.seq;
            let negotiated =
                SynPayload::decode(&pkt.payload).unwrap_or_else(|| self.syn_config.clone());
            self.peer_max_packet_length = negotiated.max_packet_length;
            self.peer_max_cumulative_acks = negotiated.max_cumulative_acks;
            self.peer_syn_received = true;
            if let Some(ctrl) = negotiated.sessions.iter().find(|s| s.session_type == 0) {
                self.control_session_id = ctrl.id;
            }
            if (pkt.control & CTRL_ACK) != 0 {
                // Peer sent SYN+ACK: reply with final ACK to complete 3-way handshake
                let ack = LinkPacket {
                    control: CTRL_ACK,
                    seq: self.local_seq,
                    ack: self.peer_seq,
                    session_id: 0,
                    payload: Vec::new(),
                };
                self.tx_queue.push_back(ack.encode());
                self.state = LinkState::Established;
                events.push(LinkEvent::LinkEstablished(negotiated));
            } else if self.sent_syn {
                // Simultaneous open: we already sent SYN, so acknowledge peer's SYN and wait for peer's ACK
                let ack = LinkPacket {
                    control: CTRL_ACK,
                    seq: self.local_seq,
                    ack: self.peer_seq,
                    session_id: 0,
                    payload: Vec::new(),
                };
                self.tx_queue.push_back(ack.encode());
            } else {
                // Passive open: peer sent initial SYN, reply with SYN+ACK
                self.sent_syn = true;
                let syn_ack = LinkPacket {
                    control: CTRL_SYN | CTRL_ACK,
                    seq: self.local_seq,
                    ack: self.peer_seq,
                    session_id: 0,
                    payload: negotiated.encode(),
                };
                self.tx_queue.push_back(syn_ack.encode());
                self.state = LinkState::Established;
                events.push(LinkEvent::LinkEstablished(negotiated));
            }
            return Ok(());
        }

        if self.state == LinkState::Negotiating
            && (pkt.control & CTRL_ACK) != 0
            && pkt.payload.is_empty()
            && self.peer_syn_received
        {
            self.state = LinkState::Established;
            events.push(LinkEvent::LinkEstablished(self.syn_config.clone()));
            return Ok(());
        }

        if !pkt.payload.is_empty() {
            self.peer_seq = pkt.seq;
            // Only send standalone data ACKs when peer negotiated non-zero cumulative ACKs
            if self.peer_max_cumulative_acks > 0 {
                let ack = LinkPacket {
                    control: CTRL_ACK,
                    seq: self.local_seq,
                    ack: self.peer_seq,
                    session_id: 0,
                    payload: Vec::new(),
                };
                self.tx_queue.push_back(ack.encode());
            }

            if pkt.session_id == self.control_session_id {
                for msg in self.csm_framer.push(&pkt.payload)? {
                    events.push(LinkEvent::ControlMessage(msg));
                }
            } else if pkt.session_id == EA_SESSION_ID {
                events.push(LinkEvent::ExternalAccessoryPayload(pkt.payload));
            } else if pkt.session_id == FILE_TRANSFER_SESSION_ID {
                events.push(LinkEvent::FileTransferPayload(pkt.payload));
            }
        }

        Ok(())
    }
}
