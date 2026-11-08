//! USB CDC-NCM 16-bit NCM Transfer Block (`NTB16`: `NTH16` + `NDP16`) encoder and decoder.
//! CarPlay over wired USB carries Ethernet II IPv6 frames inside NTB16 transfers.

use thiserror::Error;

/// `"NCMH"` in little-endian (`0x484D434E`).
pub const NTH16_SIGNATURE: u32 = 0x484D_434E;
/// `"NCM0"` without CRC in little-endian (`0x304D434E`).
pub const NDP16_SIGNATURE_NOCRC: u32 = 0x304D_434E;
/// `"NCM1"` with CRC in little-endian (`0x314D434E`).
pub const NDP16_SIGNATURE_CRC: u32 = 0x314D_434E;

const NTH16_LEN: usize = 12;
const NDP16_MIN_LEN: usize = 16;

#[derive(Debug, Error)]
pub enum Ntb16Error {
    #[error("NTB16 transfer shorter than NTH16 header ({0} bytes)")]
    TooShort(usize),
    #[error("invalid NTH16 signature: 0x{0:08x}")]
    BadNthSignature(u32),
    #[error("invalid NDP16 signature: 0x{0:08x}")]
    BadNdpSignature(u32),
    #[error("NTB16 pointer/length out of bounds")]
    OutOfBounds,
}

/// Encodes one or more Ethernet II frames into a single USB CDC-NCM `NTB16` block.
pub fn encode_ntb16(sequence: u16, ethernet_frames: &[&[u8]]) -> Vec<u8> {
    // Layout: [12B NTH16] [4B pad -> 16] [NDP16 header + (N+1)*4B datagram pointers] [aligned frames...]
    let ndp_offset = 16usize;
    let pointer_entries = ethernet_frames.len() + 1; // +1 terminating (0, 0) entry
    let ndp_len = 8 + pointer_entries * 4;
    let mut payload_cursor = align4(ndp_offset + ndp_len);

    let mut frame_offsets = Vec::with_capacity(ethernet_frames.len());
    for f in ethernet_frames {
        frame_offsets.push((payload_cursor as u16, f.len() as u16));
        payload_cursor = align4(payload_cursor + f.len());
    }

    let total_block_len = payload_cursor;
    let mut out = vec![0u8; total_block_len];

    // Write NTH16 (12 bytes)
    out[0..4].copy_from_slice(&NTH16_SIGNATURE.to_le_bytes());
    out[4..6].copy_from_slice(&(NTH16_LEN as u16).to_le_bytes());
    out[6..8].copy_from_slice(&sequence.to_le_bytes());
    out[8..10].copy_from_slice(&(total_block_len as u16).to_le_bytes());
    out[10..12].copy_from_slice(&(ndp_offset as u16).to_le_bytes());

    // Write NDP16
    out[ndp_offset..ndp_offset + 4].copy_from_slice(&NDP16_SIGNATURE_NOCRC.to_le_bytes());
    out[ndp_offset + 4..ndp_offset + 6].copy_from_slice(&(ndp_len as u16).to_le_bytes());
    out[ndp_offset + 6..ndp_offset + 8].copy_from_slice(&0u16.to_le_bytes()); // wNextNdpIndex = 0

    let mut ptr_pos = ndp_offset + 8;
    for &(off, len) in &frame_offsets {
        out[ptr_pos..ptr_pos + 2].copy_from_slice(&off.to_le_bytes());
        out[ptr_pos + 2..ptr_pos + 4].copy_from_slice(&len.to_le_bytes());
        ptr_pos += 4;
        // Terminating 4 zero bytes are already zero-initialized
    }

    for (f, &(off, len)) in ethernet_frames.iter().zip(frame_offsets.iter()) {
        let start = off as usize;
        out[start..start + (len as usize)].copy_from_slice(f);
    }

    out
}

/// Decodes all Ethernet II frames from an incoming `NTB16` USB bulk transfer (following chained `wNextNdpIndex` tables).
pub fn decode_ntb16(ntb: &[u8]) -> Result<Vec<Vec<u8>>, Ntb16Error> {
    if ntb.len() < NTH16_LEN {
        return Err(Ntb16Error::TooShort(ntb.len()));
    }
    let sig = u32::from_le_bytes(ntb[0..4].try_into().unwrap());
    if sig != NTH16_SIGNATURE {
        return Err(Ntb16Error::BadNthSignature(sig));
    }
    let header_len = u16::from_le_bytes([ntb[4], ntb[5]]) as usize;
    if header_len != NTH16_LEN {
        return Err(Ntb16Error::OutOfBounds);
    }
    let mut ndp_index = u16::from_le_bytes([ntb[10], ntb[11]]) as usize;
    let mut frames = Vec::new();
    let mut hops = 0usize;

    while ndp_index != 0 {
        hops += 1;
        if hops > 32 || ndp_index + NDP16_MIN_LEN > ntb.len() {
            return Err(Ntb16Error::OutOfBounds);
        }
        let ndp_sig = u32::from_le_bytes(ntb[ndp_index..ndp_index + 4].try_into().unwrap());
        if ndp_sig != NDP16_SIGNATURE_NOCRC && ndp_sig != NDP16_SIGNATURE_CRC {
            return Err(Ntb16Error::BadNdpSignature(ndp_sig));
        }
        let ndp_len = u16::from_le_bytes([ntb[ndp_index + 4], ntb[ndp_index + 5]]) as usize;
        if ndp_len < NDP16_MIN_LEN || ndp_index + ndp_len > ntb.len() {
            return Err(Ntb16Error::OutOfBounds);
        }
        let next_ndp = u16::from_le_bytes([ntb[ndp_index + 6], ntb[ndp_index + 7]]) as usize;

        let mut pos = ndp_index + 8;
        let end = ndp_index + ndp_len;
        while pos + 4 <= end {
            let dgram_idx = u16::from_le_bytes([ntb[pos], ntb[pos + 1]]) as usize;
            let dgram_len = u16::from_le_bytes([ntb[pos + 2], ntb[pos + 3]]) as usize;
            pos += 4;
            if dgram_idx == 0 && dgram_len == 0 {
                break;
            }
            let payload_len = if ndp_sig == NDP16_SIGNATURE_CRC {
                dgram_len.saturating_sub(4)
            } else {
                dgram_len
            };
            if dgram_idx + dgram_len > ntb.len() {
                return Err(Ntb16Error::OutOfBounds);
            }
            frames.push(ntb[dgram_idx..dgram_idx + payload_len].to_vec());
        }

        ndp_index = next_ndp;
    }

    Ok(frames)
}

const fn align4(v: usize) -> usize {
    (v + 3) & !3
}
