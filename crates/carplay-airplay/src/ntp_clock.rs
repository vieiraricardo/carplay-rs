//! CarPlay UDP timing clock synchronization (`PT_REQUEST = 210`, `PT_RESPONSE = 211`).

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const PT_REQUEST: u8 = 210;
const PT_RESPONSE: u8 = 211;
const NTP_PACKET_BYTES: usize = 32;
const NTP_ORIGINATE_OFFSET: usize = 8;
const NTP_RECEIVE_OFFSET: usize = 16;
const NTP_TRANSMIT_OFFSET: usize = 24;
const NTP_UNIX_OFFSET_SECS: u64 = 2_208_988_800;

struct ClockState {
    origin_instant: Instant,
    base_unix_ns: i128,
    offset_ns: i128,
    pending_t1: Option<u64>,
}

impl ClockState {
    fn new() -> Self {
        let unix_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i128;
        Self {
            origin_instant: Instant::now(),
            base_unix_ns: unix_ns,
            offset_ns: 0,
            pending_t1: None,
        }
    }

    fn synced_ntp64(&self) -> u64 {
        let mono_ns = self.origin_instant.elapsed().as_nanos() as i128;
        let total_unix_ns = (self.base_unix_ns + mono_ns + self.offset_ns).max(0) as u128;
        let secs = (total_unix_ns / 1_000_000_000) as u64 + NTP_UNIX_OFFSET_SECS;
        let nanos = (total_unix_ns % 1_000_000_000) as u64;
        let frac = ((u128::from(nanos) << 32) / 1_000_000_000) as u64;
        (secs << 32) | (frac & 0xFFFF_FFFF)
    }
}

fn ntp64_to_nanos_signed(ntp: u64) -> i128 {
    let secs = (ntp >> 32) as i128;
    let frac = (ntp & 0xFFFF_FFFF) as i128;
    secs * 1_000_000_000 + ((frac * 1_000_000_000) >> 32)
}

/// CarPlay timing-port UDP server & client.
pub struct NtpClock {
    running: Arc<AtomicBool>,
    state: Arc<Mutex<ClockState>>,
    socket: Option<UdpSocket>,
    rx_thread: Option<JoinHandle<()>>,
    tx_thread: Option<JoinHandle<()>>,
}

impl Default for NtpClock {
    fn default() -> Self {
        Self::new()
    }
}

impl NtpClock {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            state: Arc::new(Mutex::new(ClockState::new())),
            socket: None,
            rx_thread: None,
            tx_thread: None,
        }
    }

    pub fn bind_and_start(
        &mut self,
        mut bind_addr: SocketAddr,
        peer: Option<SocketAddr>,
    ) -> std::io::Result<u16> {
        bind_addr.set_port(0);
        let sock = UdpSocket::bind(bind_addr).or_else(|_| UdpSocket::bind("0.0.0.0:0"))?;
        sock.set_read_timeout(Some(Duration::from_millis(250)))?;
        let local_port = sock.local_addr()?.port();
        self.running.store(true, Ordering::SeqCst);

        let rx_sock = sock.try_clone()?;
        let rx_running = Arc::clone(&self.running);
        let rx_state = Arc::clone(&self.state);
        self.rx_thread = Some(thread::spawn(move || {
            let mut buf = [0u8; 128];
            while rx_running.load(Ordering::Relaxed) {
                let Ok((n, src)) = rx_sock.recv_from(&mut buf) else {
                    continue;
                };
                if n < NTP_PACKET_BYTES {
                    continue;
                }
                match buf[1] {
                    PT_REQUEST => {
                        let mut resp = [0u8; NTP_PACKET_BYTES];
                        resp[0] = 0x80;
                        resp[1] = PT_RESPONSE;
                        resp[2..4].copy_from_slice(&7u16.to_be_bytes());
                        resp[NTP_ORIGINATE_OFFSET..NTP_ORIGINATE_OFFSET + 8].copy_from_slice(
                            &buf[NTP_TRANSMIT_OFFSET..NTP_TRANSMIT_OFFSET + 8],
                        );
                        let now = rx_state.lock().unwrap().synced_ntp64();
                        resp[NTP_RECEIVE_OFFSET..NTP_RECEIVE_OFFSET + 8]
                            .copy_from_slice(&now.to_be_bytes());
                        resp[NTP_TRANSMIT_OFFSET..NTP_TRANSMIT_OFFSET + 8]
                            .copy_from_slice(&now.to_be_bytes());
                        let _ = rx_sock.send_to(&resp, src);
                    }
                    PT_RESPONSE => {
                        let mut guard = rx_state.lock().unwrap();
                        let t4 = guard.synced_ntp64();
                        let t1 = u64::from_be_bytes(
                            buf[NTP_ORIGINATE_OFFSET..NTP_ORIGINATE_OFFSET + 8]
                                .try_into()
                                .unwrap(),
                        );
                        let t2 = u64::from_be_bytes(
                            buf[NTP_RECEIVE_OFFSET..NTP_RECEIVE_OFFSET + 8]
                                .try_into()
                                .unwrap(),
                        );
                        let t3 = u64::from_be_bytes(
                            buf[NTP_TRANSMIT_OFFSET..NTP_TRANSMIT_OFFSET + 8]
                                .try_into()
                                .unwrap(),
                        );
                        if guard.pending_t1 == Some(t1) {
                            guard.pending_t1 = None;
                            let d1 = ntp64_to_nanos_signed(t2) - ntp64_to_nanos_signed(t1);
                            let d2 = ntp64_to_nanos_signed(t3) - ntp64_to_nanos_signed(t4);
                            let offset_delta = (d1 + d2) / 2;
                            // Gentle EWMA steering
                            guard.offset_ns += offset_delta / 4;
                        }
                    }
                    _ => {}
                }
            }
        }));

        if let Some(peer_addr) = peer {
            if peer_addr.port() > 0 {
                let tx_sock = sock.try_clone()?;
                let tx_running = Arc::clone(&self.running);
                let tx_state = Arc::clone(&self.state);
                self.tx_thread = Some(thread::spawn(move || {
                    while tx_running.load(Ordering::Relaxed) {
                        let mut pkt = [0u8; NTP_PACKET_BYTES];
                        pkt[0] = 0x80;
                        pkt[1] = PT_REQUEST;
                        pkt[2..4].copy_from_slice(&7u16.to_be_bytes());
                        let t1 = {
                            let mut g = tx_state.lock().unwrap();
                            let t = g.synced_ntp64();
                            g.pending_t1 = Some(t);
                            t
                        };
                        pkt[NTP_TRANSMIT_OFFSET..NTP_TRANSMIT_OFFSET + 8]
                            .copy_from_slice(&t1.to_be_bytes());
                        let _ = tx_sock.send_to(&pkt, peer_addr);
                        for _ in 0..30 {
                            if !tx_running.load(Ordering::Relaxed) {
                                return;
                            }
                            thread::sleep(Duration::from_millis(100));
                        }
                    }
                }));
            }
        }

        self.socket = Some(sock);
        Ok(local_port)
    }

    pub fn synced_ntp64(&self) -> u64 {
        self.state.lock().unwrap().synced_ntp64()
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        self.socket.take();
        if let Some(h) = self.rx_thread.take() {
            let _ = h.join();
        }
        if let Some(h) = self.tx_thread.take() {
            let _ = h.join();
        }
    }
}

impl Drop for NtpClock {
    fn drop(&mut self) {
        self.stop();
    }
}
