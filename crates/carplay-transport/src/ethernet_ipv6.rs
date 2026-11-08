//! Ethernet II (`0x86DD`) IPv6 codec and ICMPv6 Neighbor Solicitation / Neighbor Advertisement
//! link-layer MAC address rewrite + checksum recomputation for userspace USB-NCM bridging.

pub const ETH_HEADER_LEN: usize = 14;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;
const IPV6_HEADER_LEN: usize = 40;
const NEXT_HEADER_ICMPV6: u8 = 58;
const ICMPV6_NEIGHBOR_SOLICITATION: u8 = 135;
const ICMPV6_NEIGHBOR_ADVERTISEMENT: u8 = 136;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetIpv6Frame {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ipv6_packet: Vec<u8>,
}

impl EthernetIpv6Frame {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ETH_HEADER_LEN + self.ipv6_packet.len());
        out.extend_from_slice(&self.dst_mac);
        out.extend_from_slice(&self.src_mac);
        out.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        out.extend_from_slice(&self.ipv6_packet);
        out
    }

    pub fn decode(frame: &[u8]) -> Option<Self> {
        if frame.len() < ETH_HEADER_LEN + IPV6_HEADER_LEN {
            return None;
        }
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        if ethertype != ETHERTYPE_IPV6 {
            return None;
        }
        let mut dst_mac = [0u8; 6];
        let mut src_mac = [0u8; 6];
        dst_mac.copy_from_slice(&frame[0..6]);
        src_mac.copy_from_slice(&frame[6..12]);
        Some(Self {
            dst_mac,
            src_mac,
            ipv6_packet: frame[ETH_HEADER_LEN..].to_vec(),
        })
    }
}

/// Computes the IPv6 multicast MAC (`33:33:xx:xx:xx:xx`) for a multicast destination IPv6 address.
pub fn ipv6_multicast_mac(dst_ipv6: &[u8; 16]) -> [u8; 6] {
    [
        0x33,
        0x33,
        dst_ipv6[12],
        dst_ipv6[13],
        dst_ipv6[14],
        dst_ipv6[15],
    ]
}

/// Rewrites ICMPv6 Source/Target Link-Layer Address options (`type 1` on NS `135`, `type 2` on NA `136`)
/// and recomputes the ICMPv6 pseudo-header checksum in place.
pub fn rewrite_ndp_link_layer_mac(ipv6_pkt: &mut [u8], new_mac: &[u8; 6]) -> bool {
    if ipv6_pkt.len() < IPV6_HEADER_LEN + 24 {
        return false;
    }
    if (ipv6_pkt[0] >> 4) != 6 || ipv6_pkt[6] != NEXT_HEADER_ICMPV6 {
        return false;
    }
    let payload_len = u16::from_be_bytes([ipv6_pkt[4], ipv6_pkt[5]]) as usize;
    if IPV6_HEADER_LEN + payload_len > ipv6_pkt.len() || payload_len < 24 {
        return false;
    }

    let icmp_type = ipv6_pkt[IPV6_HEADER_LEN];
    let target_opt_type = match icmp_type {
        ICMPV6_NEIGHBOR_SOLICITATION => 1u8,
        ICMPV6_NEIGHBOR_ADVERTISEMENT => 2u8,
        _ => return false,
    };

    let icmp_end = IPV6_HEADER_LEN + payload_len;
    let mut opt_pos = IPV6_HEADER_LEN + 24;
    let mut modified = false;

    while opt_pos + 8 <= icmp_end {
        let opt_type = ipv6_pkt[opt_pos];
        let opt_units = ipv6_pkt[opt_pos + 1] as usize;
        if opt_units == 0 {
            break;
        }
        let opt_bytes = opt_units * 8;
        if opt_pos + opt_bytes > icmp_end {
            break;
        }
        if opt_type == target_opt_type && opt_bytes >= 8 {
            ipv6_pkt[opt_pos + 2..opt_pos + 8].copy_from_slice(new_mac);
            modified = true;
        }
        opt_pos += opt_bytes;
    }

    if modified {
        let mut src_ip = [0u8; 16];
        let mut dst_ip = [0u8; 16];
        src_ip.copy_from_slice(&ipv6_pkt[8..24]);
        dst_ip.copy_from_slice(&ipv6_pkt[24..40]);
        // Zero checksum field before recomputing
        ipv6_pkt[IPV6_HEADER_LEN + 2] = 0;
        ipv6_pkt[IPV6_HEADER_LEN + 3] = 0;
        let cksum = icmpv6_checksum(&src_ip, &dst_ip, &ipv6_pkt[IPV6_HEADER_LEN..icmp_end]);
        ipv6_pkt[IPV6_HEADER_LEN + 2..IPV6_HEADER_LEN + 4].copy_from_slice(&cksum.to_be_bytes());
    }

    modified
}

/// Computes the RFC 4443 / RFC 8200 16-bit one's-complement ICMPv6 checksum over the IPv6 pseudo-header.
pub fn icmpv6_checksum(src_ip: &[u8; 16], dst_ip: &[u8; 16], icmp_payload: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in src_ip.chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    for chunk in dst_ip.chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    let len = icmp_payload.len() as u32;
    sum += len >> 16;
    sum += len & 0xFFFF;
    sum += u32::from(NEXT_HEADER_ICMPV6);

    let mut chunks = icmp_payload.chunks_exact(2);
    for c in &mut chunks {
        sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    if let Some(&rem) = chunks.remainder().first() {
        sum += u32::from(rem) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let folded = !(sum as u16);
    if folded == 0 {
        0xFFFF
    } else {
        folded
    }
}
