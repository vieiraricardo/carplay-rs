//! Apple HomeKit / AirPlay TLV8 (`application/pairing+tlv8`) encoder and decoder.
//! Automatically splits values > 255 bytes into consecutive same-tag chunks and coalesces them on decode.

use indexmap::IndexMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Tlv8Error {
    #[error("truncated TLV8 item at offset {offset}: needed {needed}, remaining {remaining}")]
    Truncated {
        offset: usize,
        needed: usize,
        remaining: usize,
    },
}

pub const TLV_METHOD: u8 = 0x00;
pub const TLV_IDENTIFIER: u8 = 0x01;
pub const TLV_SALT: u8 = 0x02;
pub const TLV_PUBLIC_KEY: u8 = 0x03;
pub const TLV_PROOF: u8 = 0x04;
pub const TLV_ENCRYPTED_DATA: u8 = 0x05;
pub const TLV_STATE: u8 = 0x06;
pub const TLV_ERROR: u8 = 0x07;
pub const TLV_SIGNATURE: u8 = 0x0A;

pub fn encode(items: &[(u8, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for &(tag, data) in items {
        if data.is_empty() {
            out.push(tag);
            out.push(0);
            continue;
        }
        for chunk in data.chunks(255) {
            out.push(tag);
            out.push(chunk.len() as u8);
            out.extend_from_slice(chunk);
        }
    }
    out
}

pub fn decode(bytes: &[u8]) -> Result<IndexMap<u8, Vec<u8>>, Tlv8Error> {
    let mut map: IndexMap<u8, Vec<u8>> = IndexMap::new();
    let mut offset = 0usize;
    let mut prev_tag: Option<u8> = None;

    while offset < bytes.len() {
        if bytes.len() - offset < 2 {
            return Err(Tlv8Error::Truncated {
                offset,
                needed: 2,
                remaining: bytes.len() - offset,
            });
        }
        let tag = bytes[offset];
        let len = bytes[offset + 1] as usize;
        offset += 2;
        if bytes.len() - offset < len {
            return Err(Tlv8Error::Truncated {
                offset,
                needed: len,
                remaining: bytes.len() - offset,
            });
        }
        let slice = &bytes[offset..offset + len];
        offset += len;

        if prev_tag == Some(tag) {
            if let Some(existing) = map.get_mut(&tag) {
                existing.extend_from_slice(slice);
            }
        } else {
            map.entry(tag)
                .and_modify(|v| v.extend_from_slice(slice))
                .or_insert_with(|| slice.to_vec());
        }
        prev_tag = Some(tag);
    }

    Ok(map)
}
