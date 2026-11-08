//! Apple USBMUX v2 framing (`magic = 0xFEEDFACE`), version/setup handshake, and pseudo-TCP (`proto = 6`)
//! tunnel codec for connecting to `lockdownd` (`port 62078`) over USB bulk endpoints.

use thiserror::Error;

pub const USBMUX_MAGIC: u32 = 0xFEED_FACE;
pub const USBMUX_HEADER_LEN: usize = 16;

pub const PROTO_VERSION: u32 = 0;
pub const PROTO_CONTROL: u32 = 1;
pub const PROTO_SETUP: u32 = 2;
pub const PROTO_TCP: u32 = 6;

pub const LOCKDOWND_PORT: u16 = 62078;

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

#[derive(Debug, Error)]
pub enum UsbMuxError {
    #[error("USBMUX packet shorter than 16 bytes ({0})")]
    TooShort(usize),
    #[error("invalid USBMUX magic: 0x{0:08x}")]
    BadMagic(u32),
    #[error("truncated TCP header inside USBMUX frame")]
    TruncatedTcp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbMuxFrame {
    pub protocol: u32,
    pub tx_seq: u16,
    pub rx_seq: u16,
    pub payload: Vec<u8>,
}

impl UsbMuxFrame {
    pub fn encode(&self) -> Vec<u8> {
        let total_len = (USBMUX_HEADER_LEN + self.payload.len()) as u32;
        let mut out = Vec::with_capacity(total_len as usize);
        out.extend_from_slice(&self.protocol.to_be_bytes());
        out.extend_from_slice(&total_len.to_be_bytes());
        out.extend_from_slice(&USBMUX_MAGIC.to_be_bytes());
        out.extend_from_slice(&self.tx_seq.to_be_bytes());
        out.extend_from_slice(&self.rx_seq.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(raw: &[u8]) -> Result<Self, UsbMuxError> {
        if raw.len() < USBMUX_HEADER_LEN {
            return Err(UsbMuxError::TooShort(raw.len()));
        }
        let protocol = u32::from_be_bytes(raw[0..4].try_into().unwrap());
        let total_len = u32::from_be_bytes(raw[4..8].try_into().unwrap()) as usize;
        let magic = u32::from_be_bytes(raw[8..12].try_into().unwrap());
        if magic != USBMUX_MAGIC {
            return Err(UsbMuxError::BadMagic(magic));
        }
        if total_len < USBMUX_HEADER_LEN || total_len > raw.len() {
            return Err(UsbMuxError::TooShort(raw.len()));
        }
        let tx_seq = u16::from_be_bytes([raw[12], raw[13]]);
        let rx_seq = u16::from_be_bytes([raw[14], raw[15]]);
        Ok(Self {
            protocol,
            tx_seq,
            rx_seq,
            payload: raw[USBMUX_HEADER_LEN..total_len].to_vec(),
        })
    }

    /// Initial USBMUX v2 version announcement (`major = 2, minor = 0`).
    pub fn version_handshake() -> Self {
        let mut payload = vec![0u8; 4];
        payload[0..4].copy_from_slice(&2u32.to_be_bytes());
        Self {
            protocol: PROTO_VERSION,
            tx_seq: 0,
            rx_seq: 0,
            payload,
        }
    }

    /// USBMUX setup byte `[0x07]` sent after receiving the iPhone's version reply.
    pub fn setup_enable() -> Self {
        Self {
            protocol: PROTO_SETUP,
            tx_seq: 0,
            rx_seq: 0xFFFF,
            payload: vec![0x07],
        }
    }
}

/// Incremental reassembly buffer for USBMUX bulk IN streams.
#[derive(Debug, Default)]
pub struct UsbMuxFrameBuffer {
    buf: Vec<u8>,
}

impl UsbMuxFrameBuffer {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn push(&mut self, incoming: &[u8]) -> Result<Vec<UsbMuxFrame>, UsbMuxError> {
        self.buf.extend_from_slice(incoming);
        let mut out = Vec::new();
        while self.buf.len() >= USBMUX_HEADER_LEN {
            let total_len = u32::from_be_bytes(self.buf[4..8].try_into().unwrap()) as usize;
            let magic = u32::from_be_bytes(self.buf[8..12].try_into().unwrap());
            if magic != USBMUX_MAGIC || total_len < USBMUX_HEADER_LEN {
                return Err(UsbMuxError::BadMagic(magic));
            }
            if self.buf.len() < total_len {
                break;
            }
            let raw: Vec<u8> = self.buf.drain(..total_len).collect();
            out.push(UsbMuxFrame::decode(&raw)?);
        }
        Ok(out)
    }
}

/// 20-byte pseudo-TCP header carried inside `PROTO_TCP` (`6`) USBMUX frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PseudoTcpSegment {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub payload: Vec<u8>,
}

impl PseudoTcpSegment {
    pub const HEADER_LEN: usize = 20;

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::HEADER_LEN + self.payload.len());
        out.extend_from_slice(&self.src_port.to_be_bytes());
        out.extend_from_slice(&self.dst_port.to_be_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.ack.to_be_bytes());
        out.push(0x50); // Data offset = 5 (20 bytes)
        out.push(self.flags);
        out.extend_from_slice(&self.window.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes()); // Checksum unused over USB
        out.extend_from_slice(&0u16.to_be_bytes()); // Urgent pointer
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, UsbMuxError> {
        if bytes.len() < Self::HEADER_LEN {
            return Err(UsbMuxError::TruncatedTcp);
        }
        let data_offset = ((bytes[12] >> 4) as usize) * 4;
        if data_offset < Self::HEADER_LEN || data_offset > bytes.len() {
            return Err(UsbMuxError::TruncatedTcp);
        }
        Ok(Self {
            src_port: u16::from_be_bytes([bytes[0], bytes[1]]),
            dst_port: u16::from_be_bytes([bytes[2], bytes[3]]),
            seq: u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
            ack: u32::from_be_bytes(bytes[8..12].try_into().unwrap()),
            flags: bytes[13],
            window: u16::from_be_bytes([bytes[14], bytes[15]]),
            payload: bytes[data_offset..].to_vec(),
        })
    }
}
