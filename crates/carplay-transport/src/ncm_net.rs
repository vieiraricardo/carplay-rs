//! Cross-platform (`macOS` `AppleUSBNCM` `enX` and `Linux` `cdc_ncm` `usb0`/`enx*`)
//! USB CDC-NCM network interface & IPv6 link-local (`fe80::...`) discovery.

use std::collections::BTreeMap;
use std::ffi::CStr;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone)]
pub struct NcmInterfaceCandidate {
    pub name: String,
    pub ipv6_link_local: Vec<String>,
    pub has_link_local_ipv4: bool,
    pub mac_address: Option<[u8; 6]>,
    pub score: i32,
}

impl NcmInterfaceCandidate {
    pub fn mac_colon_uppercase(&self) -> Option<String> {
        self.mac_address.map(|m| {
            format!(
                "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                m[0], m[1], m[2], m[3], m[4], m[5]
            )
        })
    }
}

fn is_excluded_interface(name: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "lo", "awdl", "llw", "utun", "nan", "anpi", "anri", "bridge", "gif", "stf", "ap", "p2p",
        "wlan", "wlp", "docker", "veth", "virbr", "tun", "tap", "wg",
    ];
    PREFIXES.iter().any(|p| name.starts_with(p))
}

fn is_unicast_link_local_v6(ip: &Ipv6Addr) -> bool {
    let seg0 = ip.segments()[0];
    (seg0 & 0xFFC0) == 0xFE80
}

/// Enumerates active OS network interfaces via `getifaddrs` and returns candidate USB CDC-NCM
/// interfaces ordered from highest to lowest CarPlay NCM confidence.
pub fn discover_ncm_interfaces() -> Vec<NcmInterfaceCandidate> {
    #[derive(Default)]
    struct RawIf {
        up: bool,
        loopback: bool,
        ipv6_ll: Vec<String>,
        has_ipv4_ll: bool,
        has_routable_ipv4: bool,
        mac: Option<[u8; 6]>,
    }

    let mut map: BTreeMap<String, RawIf> = BTreeMap::new();

    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 || ifap.is_null() {
            return Vec::new();
        }

        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_name.is_null() {
                if let Ok(name_str) = CStr::from_ptr(ifa.ifa_name).to_str() {
                    let entry = map.entry(name_str.to_string()).or_default();
                    let flags = ifa.ifa_flags as i32;
                    if (flags & libc::IFF_UP) != 0 {
                        entry.up = true;
                    }
                    if (flags & libc::IFF_LOOPBACK) != 0 {
                        entry.loopback = true;
                    }

                    if !ifa.ifa_addr.is_null() {
                        let family = i32::from((*ifa.ifa_addr).sa_family);
                        if family == libc::AF_INET {
                            let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                            if ip.octets()[0] == 169 && ip.octets()[1] == 254 {
                                entry.has_ipv4_ll = true;
                            } else if !ip.is_loopback() && !ip.is_unspecified() {
                                entry.has_routable_ipv4 = true;
                            }
                        } else if family == libc::AF_INET6 {
                            let sin6 = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                            let mut octets = sin6.sin6_addr.s6_addr;
                            // Clear KAME embedded scope ID in octets[2..4] if present on BSD/macOS
                            if octets[0] == 0xFE && (octets[1] & 0xC0) == 0x80 {
                                octets[2] = 0;
                                octets[3] = 0;
                            }
                            let ip6 = Ipv6Addr::from(octets);
                            if is_unicast_link_local_v6(&ip6) {
                                let text = ip6.to_string();
                                if !entry.ipv6_ll.contains(&text) {
                                    entry.ipv6_ll.push(text);
                                }
                            }
                        } else {
                            #[cfg(target_os = "macos")]
                            if family == libc::AF_LINK {
                                let sdl = &*(ifa.ifa_addr as *const libc::sockaddr_dl);
                                if sdl.sdl_alen == 6 {
                                    let base = sdl.sdl_data.as_ptr() as *const u8;
                                    let lladdr = base.add(usize::from(sdl.sdl_nlen));
                                    let mut mac = [0u8; 6];
                                    std::ptr::copy_nonoverlapping(lladdr, mac.as_mut_ptr(), 6);
                                    if mac != [0u8; 6] && mac != [0x02, 0, 0, 0, 0, 0] {
                                        entry.mac = Some(mac);
                                    }
                                }
                            }
                            #[cfg(target_os = "linux")]
                            if family == libc::AF_PACKET {
                                let sll = &*(ifa.ifa_addr as *const libc::sockaddr_ll);
                                if sll.sll_halen == 6 {
                                    let mut mac = [0u8; 6];
                                    mac.copy_from_slice(&sll.sll_addr[..6]);
                                    if mac != [0u8; 6] {
                                        entry.mac = Some(mac);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
    }

    let mut out = Vec::new();
    for (name, info) in map {
        if !info.up || info.loopback || info.ipv6_ll.is_empty() || is_excluded_interface(&name) {
            continue;
        }

        let mut mac = info.mac;
        #[cfg(target_os = "macos")]
        if mac.is_none() && name != "en0" && name.starts_with("en") {
            mac = read_macos_ifconfig_mac(&name);
        }

        let mut score = 0i32;
        if name.starts_with("usb") || name.starts_with("ncm") || name.starts_with("enx") {
            score += 50;
        }
        if info.has_ipv4_ll && !info.has_routable_ipv4 {
            // USB CDC-NCM links use 169.254.x.y IPv4 + fe80:: IPv6 without DHCP LAN gateway
            score += 40;
        }
        if let Some(m) = mac {
            if (m[0] & 0x02) != 0 {
                // Locally-administered MAC (used by AppleUSBNCM & Linux cdc_ncm)
                score += 25;
            }
        }
        if name == "en0" {
            // Primary Wi-Fi/Ethernet on macOS; penalize so USB NCM `enX` always wins
            score -= 30;
        } else if name.starts_with("en") || name.starts_with("eth") {
            score += 10;
        }

        out.push(NcmInterfaceCandidate {
            name,
            ipv6_link_local: info.ipv6_ll,
            has_link_local_ipv4: info.has_ipv4_ll,
            mac_address: mac,
            score,
        });
    }

    out.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.name.cmp(&b.name)));
    out
}

#[cfg(target_os = "macos")]
fn read_macos_ifconfig_mac(ifname: &str) -> Option<[u8; 6]> {
    let out = std::process::Command::new("/sbin/ifconfig")
        .arg(ifname)
        .output()
        .ok()?;
    let text = std::str::from_utf8(&out.stdout).ok()?;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("ether ") {
            let mac_str = rest.split_whitespace().next()?;
            let mut mac = [0u8; 6];
            let mut count = 0usize;
            for part in mac_str.split(':') {
                if count >= 6 {
                    return None;
                }
                mac[count] = u8::from_str_radix(part, 16).ok()?;
                count += 1;
            }
            if count == 6 && mac != [0u8; 6] {
                return Some(mac);
            }
        }
    }
    None
}

/// Returns `(ipv6_addresses_for_0x4301, preferred_interface_summary)` for `CarPlayStartSession`.
pub fn select_wired_ipv6_addresses() -> (Vec<String>, Option<NcmInterfaceCandidate>) {
    let candidates = discover_ncm_interfaces();
    let Some(best) = candidates.first().cloned() else {
        return (Vec::new(), None);
    };

    // Advertise ONLY the top USB NCM candidate(s) (never include penalized Wi-Fi `en0` when USB `enX` exists,
    // otherwise iOS wastes 5-10s timing out on the wrong interface before connecting over USB NCM!).
    let threshold = if best.score > 0 { best.score } else { i32::MIN };
    let mut addrs = Vec::new();
    for cand in &candidates {
        if cand.score >= threshold {
            for ip in &cand.ipv6_link_local {
                if !addrs.contains(ip) {
                    addrs.push(ip.clone());
                }
            }
        }
    }
    (addrs, Some(best))
}

/// Discovers local Wi-Fi / LAN IP addresses and optional MAC address for Wireless CarPlay onboarding.
pub fn discover_wifi_host_addresses() -> (Vec<String>, Option<[u8; 6]>) {
    #[derive(Default)]
    struct IfInfo {
        up: bool,
        loopback: bool,
        ipv4_routable: Vec<String>,
        ipv6_addrs: Vec<String>,
        mac: Option<[u8; 6]>,
    }

    let mut map: BTreeMap<String, IfInfo> = BTreeMap::new();

    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 || ifap.is_null() {
            return (Vec::new(), None);
        }

        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            if !ifa.ifa_name.is_null() {
                if let Ok(name_str) = CStr::from_ptr(ifa.ifa_name).to_str() {
                    let entry = map.entry(name_str.to_string()).or_default();
                    let flags = ifa.ifa_flags as i32;
                    if (flags & libc::IFF_UP) != 0 {
                        entry.up = true;
                    }
                    if (flags & libc::IFF_LOOPBACK) != 0 {
                        entry.loopback = true;
                    }

                    if !ifa.ifa_addr.is_null() {
                        let family = i32::from((*ifa.ifa_addr).sa_family);
                        if family == libc::AF_INET {
                            let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                            let oct = ip.octets();
                            if !ip.is_loopback() && !ip.is_unspecified() && !(oct[0] == 169 && oct[1] == 254) {
                                let s = ip.to_string();
                                if !entry.ipv4_routable.contains(&s) {
                                    entry.ipv4_routable.push(s);
                                }
                            }
                        } else if family == libc::AF_INET6 {
                            let sin6 = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                            let mut octets = sin6.sin6_addr.s6_addr;
                            if octets[0] == 0xFE && (octets[1] & 0xC0) == 0x80 {
                                octets[2] = 0;
                                octets[3] = 0;
                            }
                            let ip6 = Ipv6Addr::from(octets);
                            if !ip6.is_loopback() && !ip6.is_unspecified() {
                                let s = ip6.to_string();
                                if !entry.ipv6_addrs.contains(&s) {
                                    entry.ipv6_addrs.push(s);
                                }
                            }
                        } else {
                            #[cfg(target_os = "macos")]
                            if family == libc::AF_LINK {
                                let sdl = &*(ifa.ifa_addr as *const libc::sockaddr_dl);
                                if sdl.sdl_alen == 6 {
                                    let base = sdl.sdl_data.as_ptr() as *const u8;
                                    let lladdr = base.add(usize::from(sdl.sdl_nlen));
                                    let mut mac = [0u8; 6];
                                    std::ptr::copy_nonoverlapping(lladdr, mac.as_mut_ptr(), 6);
                                    if mac != [0u8; 6] {
                                        entry.mac = Some(mac);
                                    }
                                }
                            }
                            #[cfg(target_os = "linux")]
                            if family == libc::AF_PACKET {
                                let sll = &*(ifa.ifa_addr as *const libc::sockaddr_ll);
                                if sll.sll_halen == 6 {
                                    let mut mac = [0u8; 6];
                                    mac.copy_from_slice(&sll.sll_addr[..6]);
                                    if mac != [0u8; 6] {
                                        entry.mac = Some(mac);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
    }

    // Prefer Wi-Fi interface:
    // macOS: "en0" or an interface with "en" that has routable IPv4
    // Linux: "wlan0", "wlan1", "wlp*", or first interface with routable IPv4
    let mut chosen_name = None;
    for (name, info) in &map {
        if !info.up || info.loopback || info.ipv4_routable.is_empty() {
            continue;
        }
        if name.starts_with("wlan") || name.starts_with("wlp") || name == "en0" {
            chosen_name = Some(name.clone());
            break;
        }
    }

    if chosen_name.is_none() {
        for (name, info) in &map {
            if info.up && !info.loopback && !info.ipv4_routable.is_empty() && !is_excluded_interface(name) {
                chosen_name = Some(name.clone());
                break;
            }
        }
    }

    let mut addrs = Vec::new();
    let mut mac = None;

    if let Some(name) = chosen_name {
        if let Some(info) = map.get(&name) {
            mac = info.mac;
            #[cfg(target_os = "macos")]
            if mac.is_none() {
                mac = read_macos_ifconfig_mac(&name);
            }
            for v4 in &info.ipv4_routable {
                addrs.push(v4.clone());
                addrs.push(format!("::ffff:{v4}"));
            }
            for v6 in &info.ipv6_addrs {
                if !addrs.contains(v6) {
                    addrs.push(v6.clone());
                }
            }
        }
    }

    (addrs, mac)
}
