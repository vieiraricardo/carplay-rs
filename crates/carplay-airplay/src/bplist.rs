//! Minimal, faithful Apple Binary Property List (`bplist00`) encoder and decoder for CarPlay RTSP.
//! Preserves dictionary insertion order (`IndexMap`) and matches `BplistCodec.kt` integer/float semantics.

use indexmap::IndexMap;
use thiserror::Error;

const MAGIC: &[u8; 8] = b"bplist00";
const MAX_DEPTH: usize = 32;
const MAX_OBJECTS: usize = 65_535;

#[derive(Debug, Error)]
pub enum BplistError {
    #[error("bplist too short ({0} bytes)")]
    TooShort(usize),
    #[error("invalid bplist00 magic")]
    BadMagic,
    #[error("invalid trailer or offset table")]
    BadTrailer,
    #[error("object reference out of bounds: {0}")]
    InvalidReference(usize),
    #[error("nesting depth exceeded")]
    MaxDepthExceeded,
    #[error("unsupported bplist object marker 0x{0:02x}")]
    UnsupportedMarker(u8),
    #[error("dictionary key must be string")]
    NonStringKey,
    #[error("invalid UTF-16 string in bplist")]
    InvalidString,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PlistValue {
    Null,
    Bool(bool),
    Uint(u64),
    Int(i64),
    Real(f64),
    String(String),
    Data(Vec<u8>),
    Array(Vec<PlistValue>),
    Dict(IndexMap<String, PlistValue>),
}

impl PlistValue {
    pub fn as_dict(&self) -> Option<&IndexMap<String, PlistValue>> {
        match self {
            Self::Dict(m) => Some(m),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[PlistValue]> {
        match self {
            Self::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Data(d) => Some(d),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match *self {
            Self::Uint(v) => Some(v),
            Self::Int(v) if v >= 0 => Some(v as u64),
            Self::Int(v) => Some(v as u64),
            Self::Bool(b) => Some(u64::from(b)),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match *self {
            Self::Int(v) => Some(v),
            Self::Uint(v) => Some(v as i64),
            Self::Real(v) => Some(v as i64),
            Self::Bool(b) => Some(i64::from(b)),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match *self {
            Self::Bool(b) => Some(b),
            Self::Uint(v) => Some(v != 0),
            Self::Int(v) => Some(v != 0),
            _ => None,
        }
    }
}

impl From<bool> for PlistValue {
    fn from(v: bool) -> Self {
        Self::Bool(v)
    }
}

impl From<u64> for PlistValue {
    fn from(v: u64) -> Self {
        Self::Uint(v)
    }
}

impl From<u32> for PlistValue {
    fn from(v: u32) -> Self {
        Self::Uint(u64::from(v))
    }
}

impl From<usize> for PlistValue {
    fn from(v: usize) -> Self {
        Self::Uint(v as u64)
    }
}

impl From<i64> for PlistValue {
    fn from(v: i64) -> Self {
        if v >= 0 {
            Self::Uint(v as u64)
        } else {
            Self::Int(v)
        }
    }
}

impl From<i32> for PlistValue {
    fn from(v: i32) -> Self {
        i64::from(v).into()
    }
}

impl From<f64> for PlistValue {
    fn from(v: f64) -> Self {
        Self::Real(v)
    }
}

impl From<&str> for PlistValue {
    fn from(v: &str) -> Self {
        Self::String(v.to_owned())
    }
}

impl From<String> for PlistValue {
    fn from(v: String) -> Self {
        Self::String(v)
    }
}

impl From<Vec<u8>> for PlistValue {
    fn from(v: Vec<u8>) -> Self {
        Self::Data(v)
    }
}

enum SerializedNode {
    Leaf(Vec<u8>),
    Container { head: Vec<u8>, refs: Vec<usize> },
}

pub fn encode(root: &PlistValue) -> Vec<u8> {
    let mut nodes: Vec<SerializedNode> = Vec::new();
    let top_index = flatten_node(root, &mut nodes);

    let ref_size = if nodes.len() > 0xFFFF {
        4
    } else if nodes.len() > 0xFF {
        2
    } else {
        1
    };

    let mut body = Vec::new();
    body.extend_from_slice(MAGIC);
    let mut offsets = Vec::with_capacity(nodes.len());

    for node in &nodes {
        offsets.push(body.len());
        match node {
            SerializedNode::Leaf(bytes) => body.extend_from_slice(bytes),
            SerializedNode::Container { head, refs } => {
                body.extend_from_slice(head);
                for &r in refs {
                    write_be_uint(&mut body, r as u64, ref_size);
                }
            }
        }
    }

    let offset_table_offset = body.len();
    let offset_size = if offset_table_offset > 0xFFFF {
        4
    } else if offset_table_offset > 0xFF {
        2
    } else {
        1
    };

    for &off in &offsets {
        write_be_uint(&mut body, off as u64, offset_size);
    }

    let mut trailer = [0u8; 32];
    trailer[6] = offset_size as u8;
    trailer[7] = ref_size as u8;
    trailer[8..16].copy_from_slice(&(nodes.len() as u64).to_be_bytes());
    trailer[16..24].copy_from_slice(&(top_index as u64).to_be_bytes());
    trailer[24..32].copy_from_slice(&(offset_table_offset as u64).to_be_bytes());
    body.extend_from_slice(&trailer);
    body
}

fn flatten_node(value: &PlistValue, nodes: &mut Vec<SerializedNode>) -> usize {
    let idx = nodes.len();
    nodes.push(SerializedNode::Leaf(Vec::new()));
    match value {
        PlistValue::Null => {
            nodes[idx] = SerializedNode::Leaf(vec![0x00]);
        }
        PlistValue::Bool(b) => {
            nodes[idx] = SerializedNode::Leaf(vec![if *b { 0x09 } else { 0x08 }]);
        }
        PlistValue::Uint(n) => {
            nodes[idx] = SerializedNode::Leaf(encode_uint(*n));
        }
        PlistValue::Int(n) => {
            if *n >= 0 {
                nodes[idx] = SerializedNode::Leaf(encode_uint(*n as u64));
            } else {
                // Match BplistCodec.kt: negative values (e.g. speechMode = -1) serialized as 64-bit IEEE754 real
                let mut v = Vec::with_capacity(9);
                v.push(0x23);
                v.extend_from_slice(&(*n as f64).to_bits().to_be_bytes());
                nodes[idx] = SerializedNode::Leaf(v);
            }
        }
        PlistValue::Real(f) => {
            let mut v = Vec::with_capacity(9);
            v.push(0x23);
            v.extend_from_slice(&f.to_bits().to_be_bytes());
            nodes[idx] = SerializedNode::Leaf(v);
        }
        PlistValue::String(s) => {
            if s.is_ascii() {
                let mut v = make_marker(0x5, s.len());
                v.extend_from_slice(s.as_bytes());
                nodes[idx] = SerializedNode::Leaf(v);
            } else {
                let utf16: Vec<u16> = s.encode_utf16().collect();
                let mut v = make_marker(0x6, utf16.len());
                for ch in utf16 {
                    v.extend_from_slice(&ch.to_be_bytes());
                }
                nodes[idx] = SerializedNode::Leaf(v);
            }
        }
        PlistValue::Data(d) => {
            let mut v = make_marker(0x4, d.len());
            v.extend_from_slice(d);
            nodes[idx] = SerializedNode::Leaf(v);
        }
        PlistValue::Array(items) => {
            let refs: Vec<usize> = items.iter().map(|it| flatten_node(it, nodes)).collect();
            nodes[idx] = SerializedNode::Container {
                head: make_marker(0xA, items.len()),
                refs,
            };
        }
        PlistValue::Dict(map) => {
            let key_refs: Vec<usize> = map
                .keys()
                .map(|k| flatten_node(&PlistValue::String(k.clone()), nodes))
                .collect();
            let val_refs: Vec<usize> = map.values().map(|v| flatten_node(v, nodes)).collect();
            let mut refs = Vec::with_capacity(key_refs.len() * 2);
            refs.extend(key_refs);
            refs.extend(val_refs);
            nodes[idx] = SerializedNode::Container {
                head: make_marker(0xD, map.len()),
                refs,
            };
        }
    }
    idx
}

fn encode_uint(n: u64) -> Vec<u8> {
    let (size, log2) = if n > 0xFFFF_FFFF {
        (8, 3u8)
    } else if n > 0xFFFF {
        (4, 2u8)
    } else if n > 0xFF {
        (2, 1u8)
    } else {
        (1, 0u8)
    };
    let mut out = Vec::with_capacity(1 + size);
    out.push(0x10 | log2);
    write_be_uint(&mut out, n, size);
    out
}

fn make_marker(kind_nibble: u8, count: usize) -> Vec<u8> {
    if count < 0x0F {
        vec![(kind_nibble << 4) | (count as u8)]
    } else {
        let mut out = vec![(kind_nibble << 4) | 0x0F];
        out.extend_from_slice(&encode_uint(count as u64));
        out
    }
}

fn write_be_uint(out: &mut Vec<u8>, val: u64, width: usize) {
    let be = val.to_be_bytes();
    out.extend_from_slice(&be[8 - width..]);
}

fn read_be_uint(bytes: &[u8], offset: usize, width: usize) -> Result<u64, BplistError> {
    if width == 0 || width > 8 || offset.saturating_add(width) > bytes.len() {
        return Err(BplistError::BadTrailer);
    }
    let mut v = 0u64;
    for &b in &bytes[offset..offset + width] {
        v = (v << 8) | u64::from(b);
    }
    Ok(v)
}

pub fn decode(bytes: &[u8]) -> Result<PlistValue, BplistError> {
    if bytes.len() < 40 {
        return Err(BplistError::TooShort(bytes.len()));
    }
    if &bytes[..8] != MAGIC {
        return Err(BplistError::BadMagic);
    }

    let trailer = bytes.len() - 32;
    let offset_size = bytes[trailer + 6] as usize;
    let ref_size = bytes[trailer + 7] as usize;
    if !(1..=8).contains(&offset_size) || !(1..=8).contains(&ref_size) {
        return Err(BplistError::BadTrailer);
    }

    let num_objects = read_be_uint(bytes, trailer + 8, 8)? as usize;
    let top_object = read_be_uint(bytes, trailer + 16, 8)? as usize;
    let offset_table = read_be_uint(bytes, trailer + 24, 8)? as usize;

    if num_objects == 0
        || num_objects > MAX_OBJECTS
        || top_object >= num_objects
        || offset_table < MAGIC.len()
        || offset_table.saturating_add(num_objects.saturating_mul(offset_size)) > trailer
    {
        return Err(BplistError::BadTrailer);
    }

    let mut offsets = Vec::with_capacity(num_objects);
    for i in 0..num_objects {
        let off = read_be_uint(bytes, offset_table + i * offset_size, offset_size)? as usize;
        if off < MAGIC.len() || off >= offset_table {
            return Err(BplistError::BadTrailer);
        }
        offsets.push(off);
    }

    decode_object(bytes, &offsets, ref_size, top_object, 0)
}

fn decode_object(
    bytes: &[u8],
    offsets: &[usize],
    ref_size: usize,
    index: usize,
    depth: usize,
) -> Result<PlistValue, BplistError> {
    if depth > MAX_DEPTH {
        return Err(BplistError::MaxDepthExceeded);
    }
    let mut pos = *offsets
        .get(index)
        .ok_or(BplistError::InvalidReference(index))?;
    let marker = *bytes.get(pos).ok_or(BplistError::BadTrailer)?;
    pos += 1;
    let kind = marker >> 4;
    let nibble = marker & 0x0F;

    let mut read_count = || -> Result<usize, BplistError> {
        if nibble != 0x0F {
            return Ok(nibble as usize);
        }
        let int_marker = *bytes.get(pos).ok_or(BplistError::BadTrailer)?;
        pos += 1;
        let width = 1usize << (int_marker & 0x0F);
        if width > 8 {
            return Err(BplistError::BadTrailer);
        }
        let count = read_be_uint(bytes, pos, width)? as usize;
        pos += width;
        if count > bytes.len().saturating_sub(pos) {
            return Err(BplistError::BadTrailer);
        }
        Ok(count)
    };

    match kind {
        0x0 => match nibble {
            0x00 => Ok(PlistValue::Null),
            0x08 => Ok(PlistValue::Bool(false)),
            0x09 => Ok(PlistValue::Bool(true)),
            _ => Err(BplistError::UnsupportedMarker(marker)),
        },
        0x1 => {
            let width = 1usize << nibble;
            if width == 16 {
                // Apple 128-bit unsigned int representation for > i64::MAX u64 values: upper 8 bytes are 0
                if pos + 16 > bytes.len() {
                    return Err(BplistError::BadTrailer);
                }
                let lo = read_be_uint(bytes, pos + 8, 8)?;
                Ok(PlistValue::Uint(lo))
            } else if width <= 8 {
                let val = read_be_uint(bytes, pos, width)?;
                Ok(PlistValue::Uint(val))
            } else {
                Err(BplistError::UnsupportedMarker(marker))
            }
        }
        0x2 => {
            let width = 1usize << nibble;
            match width {
                4 => {
                    let bits = read_be_uint(bytes, pos, 4)? as u32;
                    Ok(PlistValue::Real(f64::from(f32::from_bits(bits))))
                }
                8 => {
                    let bits = read_be_uint(bytes, pos, 8)?;
                    Ok(PlistValue::Real(f64::from_bits(bits)))
                }
                _ => Err(BplistError::UnsupportedMarker(marker)),
            }
        }
        0x3 => {
            // Date: 8-byte float seconds since 2001-01-01
            let bits = read_be_uint(bytes, pos, 8)?;
            Ok(PlistValue::Real(f64::from_bits(bits)))
        }
        0x4 => {
            let count = read_count()?;
            if pos + count > bytes.len() {
                return Err(BplistError::BadTrailer);
            }
            Ok(PlistValue::Data(bytes[pos..pos + count].to_vec()))
        }
        0x5 => {
            let count = read_count()?;
            if pos + count > bytes.len() {
                return Err(BplistError::BadTrailer);
            }
            let s = String::from_utf8_lossy(&bytes[pos..pos + count]).into_owned();
            Ok(PlistValue::String(s))
        }
        0x6 => {
            let count = read_count()?;
            let byte_len = count.checked_mul(2).ok_or(BplistError::BadTrailer)?;
            if pos + byte_len > bytes.len() {
                return Err(BplistError::BadTrailer);
            }
            let units: Vec<u16> = bytes[pos..pos + byte_len]
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            let s = String::from_utf16(&units).map_err(|_| BplistError::InvalidString)?;
            Ok(PlistValue::String(s))
        }
        0x8 => {
            let width = (nibble as usize) + 1;
            let val = read_be_uint(bytes, pos, width)?;
            Ok(PlistValue::Uint(val))
        }
        0xA | 0xC => {
            let count = read_count()?;
            let needed = count.checked_mul(ref_size).ok_or(BplistError::BadTrailer)?;
            if pos + needed > bytes.len() {
                return Err(BplistError::BadTrailer);
            }
            let mut arr = Vec::with_capacity(count.min(256));
            for i in 0..count {
                let r = read_be_uint(bytes, pos + i * ref_size, ref_size)? as usize;
                arr.push(decode_object(bytes, offsets, ref_size, r, depth + 1)?);
            }
            Ok(PlistValue::Array(arr))
        }
        0xD => {
            let count = read_count()?;
            let needed = count
                .checked_mul(2)
                .and_then(|n| n.checked_mul(ref_size))
                .ok_or(BplistError::BadTrailer)?;
            if pos + needed > bytes.len() {
                return Err(BplistError::BadTrailer);
            }
            let mut dict = IndexMap::with_capacity(count.min(256));
            for i in 0..count {
                let kr = read_be_uint(bytes, pos + i * ref_size, ref_size)? as usize;
                let vr = read_be_uint(bytes, pos + (count + i) * ref_size, ref_size)? as usize;
                let key_obj = decode_object(bytes, offsets, ref_size, kr, depth + 1)?;
                let PlistValue::String(key) = key_obj else {
                    return Err(BplistError::NonStringKey);
                };
                let val_obj = decode_object(bytes, offsets, ref_size, vr, depth + 1)?;
                dict.insert(key, val_obj);
            }
            Ok(PlistValue::Dict(dict))
        }
        _ => Err(BplistError::UnsupportedMarker(marker)),
    }
}

/// Convenience helper macro for building ordered `PlistValue::Dict` maps cleanly.
#[macro_export]
macro_rules! plist_dict {
    ($($k:expr => $v:expr),* $(,)?) => {{
        #[allow(unused_mut)]
        let mut map = indexmap::IndexMap::new();
        $(
            map.insert(($k).to_string(), $crate::bplist::PlistValue::from($v));
        )*
        $crate::bplist::PlistValue::Dict(map)
    }};
}
