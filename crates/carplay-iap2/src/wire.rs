//! iAP2 Control Session Message (CSM) wire codec (`0x4040`), parameter builders, and readers.

use thiserror::Error;

pub const CSM_START_OF_MESSAGE: u16 = 0x4040;
pub const CSM_HEADER_LEN: usize = 6;
pub const PARAM_HEADER_LEN: usize = 4;

#[derive(Debug, Error)]
pub enum Iap2WireError {
    #[error("iAP2 CSM frame too short: {0} bytes")]
    FrameTooShort(usize),
    #[error("invalid iAP2 CSM magic: 0x{0:04x}")]
    BadMagic(u16),
    #[error("iAP2 CSM frame length mismatch: declared {declared}, available {available}")]
    LengthMismatch { declared: usize, available: usize },
    #[error("malformed parameter at offset {offset}: length {length}")]
    MalformedParam { offset: usize, length: usize },
    #[error("parameter 0x{param_id:04x} invalid UTF-8 string")]
    InvalidUtf8 { param_id: u16 },
    #[error("payload exceeds u16 maximum length ({0} bytes)")]
    OversizedPayload(usize),
}

/// Decoded iAP2 Control Session Message (`0x4040 | u16be len | u16be msg_id | params...`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Iap2Message {
    pub message_id: u16,
    pub params: Vec<Iap2Param>,
}

/// One TLV parameter inside an iAP2 message or nested parameter group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Iap2Param {
    pub id: u16,
    pub data: Vec<u8>,
}

impl Iap2Message {
    pub fn new(message_id: u16, params: Vec<Iap2Param>) -> Self {
        Self { message_id, params }
    }

    pub fn encode(&self) -> Result<Vec<u8>, Iap2WireError> {
        let body = encode_params(&self.params)?;
        let total_len = CSM_HEADER_LEN + body.len();
        if total_len > u16::MAX as usize {
            return Err(Iap2WireError::OversizedPayload(total_len));
        }
        let mut out = Vec::with_capacity(total_len);
        out.extend_from_slice(&CSM_START_OF_MESSAGE.to_be_bytes());
        out.extend_from_slice(&(total_len as u16).to_be_bytes());
        out.extend_from_slice(&self.message_id.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    pub fn decode(frame: &[u8]) -> Result<Self, Iap2WireError> {
        if frame.len() < CSM_HEADER_LEN {
            return Err(Iap2WireError::FrameTooShort(frame.len()));
        }
        let magic = u16::from_be_bytes([frame[0], frame[1]]);
        if magic != CSM_START_OF_MESSAGE {
            return Err(Iap2WireError::BadMagic(magic));
        }
        let total_len = u16::from_be_bytes([frame[2], frame[3]]) as usize;
        if total_len < CSM_HEADER_LEN || total_len > frame.len() {
            return Err(Iap2WireError::LengthMismatch {
                declared: total_len,
                available: frame.len(),
            });
        }
        let message_id = u16::from_be_bytes([frame[4], frame[5]]);
        let params = decode_params(&frame[CSM_HEADER_LEN..total_len])?;
        Ok(Self { message_id, params })
    }

    pub fn reader(&self) -> Iap2BodyReader<'_> {
        Iap2BodyReader::new(&self.params)
    }
}

pub fn encode_params(params: &[Iap2Param]) -> Result<Vec<u8>, Iap2WireError> {
    let mut out = Vec::new();
    for p in params {
        let param_len = PARAM_HEADER_LEN + p.data.len();
        if param_len > u16::MAX as usize {
            return Err(Iap2WireError::OversizedPayload(param_len));
        }
        out.extend_from_slice(&(param_len as u16).to_be_bytes());
        out.extend_from_slice(&p.id.to_be_bytes());
        out.extend_from_slice(&p.data);
    }
    Ok(out)
}

pub fn decode_params(buf: &[u8]) -> Result<Vec<Iap2Param>, Iap2WireError> {
    let mut params = Vec::new();
    let mut offset = 0;
    while offset < buf.len() {
        if buf.len() - offset < PARAM_HEADER_LEN {
            return Err(Iap2WireError::MalformedParam {
                offset,
                length: buf.len() - offset,
            });
        }
        let length = u16::from_be_bytes([buf[offset], buf[offset + 1]]) as usize;
        let id = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
        if length < PARAM_HEADER_LEN || offset + length > buf.len() {
            return Err(Iap2WireError::MalformedParam { offset, length });
        }
        let data = buf[offset + PARAM_HEADER_LEN..offset + length].to_vec();
        params.push(Iap2Param { id, data });
        offset += length;
    }
    Ok(params)
}

/// Fluent builder for iAP2 message bodies and nested parameter groups.
#[derive(Debug, Default, Clone)]
pub struct Iap2BodyBuilder {
    params: Vec<Iap2Param>,
}

impl Iap2BodyBuilder {
    pub fn new() -> Self {
        Self { params: Vec::new() }
    }

    pub fn put_none(&mut self, id: u16) -> &mut Self {
        self.params.push(Iap2Param { id, data: Vec::new() });
        self
    }

    pub fn put_bool(&mut self, id: u16, value: bool) -> &mut Self {
        self.put_u8(id, u8::from(value))
    }

    pub fn put_u8(&mut self, id: u16, value: u8) -> &mut Self {
        self.params.push(Iap2Param {
            id,
            data: vec![value],
        });
        self
    }

    pub fn put_u16(&mut self, id: u16, value: u16) -> &mut Self {
        self.params.push(Iap2Param {
            id,
            data: value.to_be_bytes().to_vec(),
        });
        self
    }

    pub fn put_u32(&mut self, id: u16, value: u32) -> &mut Self {
        self.params.push(Iap2Param {
            id,
            data: value.to_be_bytes().to_vec(),
        });
        self
    }

    pub fn put_u64(&mut self, id: u16, value: u64) -> &mut Self {
        self.params.push(Iap2Param {
            id,
            data: value.to_be_bytes().to_vec(),
        });
        self
    }

    /// iAP2 UTF-8 string parameter (always NUL-terminated).
    pub fn put_string(&mut self, id: u16, value: &str) -> &mut Self {
        let mut data = Vec::with_capacity(value.len() + 1);
        data.extend_from_slice(value.as_bytes());
        data.push(0x00);
        self.params.push(Iap2Param { id, data });
        self
    }

    pub fn put_bytes(&mut self, id: u16, bytes: &[u8]) -> &mut Self {
        self.params.push(Iap2Param {
            id,
            data: bytes.to_vec(),
        });
        self
    }

    /// Packed big-endian `u16` array (used in Identification `MessagesSentByAccessory`, etc.).
    pub fn put_u16_list(&mut self, id: u16, values: &[u16]) -> &mut Self {
        let mut data = Vec::with_capacity(values.len() * 2);
        for v in values {
            data.extend_from_slice(&v.to_be_bytes());
        }
        self.params.push(Iap2Param { id, data });
        self
    }

    pub fn put_group<F>(&mut self, id: u16, build_fn: F) -> Result<&mut Self, Iap2WireError>
    where
        F: FnOnce(&mut Iap2BodyBuilder),
    {
        let mut inner = Iap2BodyBuilder::new();
        build_fn(&mut inner);
        let encoded = encode_params(&inner.params)?;
        self.params.push(Iap2Param { id, data: encoded });
        Ok(self)
    }

    pub fn build_message(self, message_id: u16) -> Iap2Message {
        Iap2Message::new(message_id, self.params)
    }

    pub fn into_params(self) -> Vec<Iap2Param> {
        self.params
    }
}

/// Reader over decoded iAP2 TLV parameters.
#[derive(Debug, Clone, Copy)]
pub struct Iap2BodyReader<'a> {
    params: &'a [Iap2Param],
}

impl<'a> Iap2BodyReader<'a> {
    pub fn new(params: &'a [Iap2Param]) -> Self {
        Self { params }
    }

    pub fn has(&self, id: u16) -> bool {
        self.params.iter().any(|p| p.id == id)
    }

    pub fn bytes(&self, id: u16) -> Option<&'a [u8]> {
        self.params.iter().find(|p| p.id == id).map(|p| p.data.as_slice())
    }

    pub fn all_bytes(&self, id: u16) -> Vec<&'a [u8]> {
        self.params
            .iter()
            .filter(|p| p.id == id)
            .map(|p| p.data.as_slice())
            .collect()
    }

    pub fn u8(&self, id: u16) -> Option<u8> {
        self.bytes(id).and_then(|b| b.first().copied())
    }

    pub fn bool(&self, id: u16) -> Option<bool> {
        self.u8(id).map(|b| b != 0)
    }

    pub fn u16(&self, id: u16) -> Option<u16> {
        let b = self.bytes(id)?;
        if b.len() < 2 {
            return None;
        }
        Some(u16::from_be_bytes([b[0], b[1]]))
    }

    pub fn u32(&self, id: u16) -> Option<u32> {
        let b = self.bytes(id)?;
        if b.len() < 4 {
            return None;
        }
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn string(&self, id: u16) -> Result<Option<String>, Iap2WireError> {
        let Some(raw) = self.bytes(id) else {
            return Ok(None);
        };
        let trimmed = raw.strip_suffix(&[0x00]).unwrap_or(raw);
        std::str::from_utf8(trimmed)
            .map(|s| Some(s.to_owned()))
            .map_err(|_| Iap2WireError::InvalidUtf8 { param_id: id })
    }

    pub fn strings(&self, id: u16) -> Result<Vec<String>, Iap2WireError> {
        let mut out = Vec::new();
        for raw in self.all_bytes(id) {
            let trimmed = raw.strip_suffix(&[0x00]).unwrap_or(raw);
            let s = std::str::from_utf8(trimmed)
                .map_err(|_| Iap2WireError::InvalidUtf8 { param_id: id })?;
            out.push(s.to_owned());
        }
        Ok(out)
    }

    pub fn u16_list(&self, id: u16) -> Vec<u16> {
        let mut out = Vec::new();
        for raw in self.all_bytes(id) {
            for chunk in raw.chunks_exact(2) {
                out.push(u16::from_be_bytes([chunk[0], chunk[1]]));
            }
        }
        out
    }

    pub fn group(&self, id: u16) -> Result<Option<Vec<Iap2Param>>, Iap2WireError> {
        let Some(raw) = self.bytes(id) else {
            return Ok(None);
        };
        decode_params(raw).map(Some)
    }
}

/// Incremental stream framer for iAP2 `0x4040` Control Session Messages (used on iAP2 tunnel / USB streams).
#[derive(Debug, Default)]
pub struct Iap2CsmFramer {
    buf: Vec<u8>,
}

impl Iap2CsmFramer {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Appends incoming stream bytes and extracts all complete `Iap2Message` frames.
    pub fn push(&mut self, incoming: &[u8]) -> Result<Vec<Iap2Message>, Iap2WireError> {
        self.buf.extend_from_slice(incoming);
        let mut messages = Vec::new();
        loop {
            if self.buf.len() < CSM_HEADER_LEN {
                break;
            }
            // Resync to 0x4040 if leading noise exists
            if self.buf[0] != 0x40 || self.buf[1] != 0x40 {
                if let Some(pos) = self.buf.windows(2).position(|w| w == [0x40, 0x40]) {
                    self.buf.drain(..pos);
                    if self.buf.len() < CSM_HEADER_LEN {
                        break;
                    }
                } else {
                    let keep = usize::from(self.buf.last() == Some(&0x40));
                    let drain_to = self.buf.len() - keep;
                    self.buf.drain(..drain_to);
                    break;
                }
            }
            let total_len = u16::from_be_bytes([self.buf[2], self.buf[3]]) as usize;
            if total_len < CSM_HEADER_LEN {
                return Err(Iap2WireError::MalformedParam {
                    offset: 0,
                    length: total_len,
                });
            }
            if self.buf.len() < total_len {
                break;
            }
            let frame: Vec<u8> = self.buf.drain(..total_len).collect();
            messages.push(Iap2Message::decode(&frame)?);
        }
        Ok(messages)
    }

    pub fn buffered_len(&self) -> usize {
        self.buf.len()
    }
}
