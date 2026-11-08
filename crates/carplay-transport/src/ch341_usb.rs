//! USB CH341A (`0x1A86:0x5512`) I2C bridge for Apple MFi Hardware Coprocessors on macOS & Linux.
//!
//! Implements the hardware-verified multi-segment 32-byte CH341 I2C stream protocol so a physical
//! Apple MFi authentication IC (`0x10` or `0x11`) wired to a CH341A USB-I2C dongle can sign iAP2
//! (`0xAA02`) and AirPlay (`/auth-setup`) challenges directly.

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use carplay_mfi::{
    I2cTransport, MfiAuthenticator, MfiError, MfiI2cClient, MFI_I2C_ADDR_HIGH, MFI_I2C_ADDR_LOW,
};
use rusb::{Context, DeviceHandle, Direction, TransferType, UsbContext};

pub const CH341_VID: u16 = 0x1A86;
pub const CH341_PIDS: &[u16] = &[0x5512, 0x5523, 0x7523];

const MAX_STREAM_PACKET_BYTES: usize = 32;
const STREAM_START: u8 = 0xAA;
const STREAM_END: u8 = 0x00;
const I2C_START: u8 = 0x74;
const I2C_STOP: u8 = 0x75;
const I2C_WRITE: u8 = 0x80;
const I2C_READ: u8 = 0xC0;
const I2C_SPEED_100KHZ: u8 = 0x61;
const LENGTH_MASK: u8 = 0x3F;
const ACK_NACK_BIT: u8 = 0x80;
const MAX_READ_BLOCK: usize = 32;

const UIO_STREAM: u8 = 0xAB;
const UIO_OUT: u8 = 0x80;
const UIO_DIR: u8 = 0x40;
const UIO_END: u8 = 0x20;

pub struct Ch341UsbI2cTransport {
    handle: DeviceHandle<Context>,
    ep_in: u8,
    ep_out: u8,
}

impl Ch341UsbI2cTransport {
    pub fn open_first() -> Result<Option<Self>, MfiError> {
        let ctx = Context::new().map_err(|e| MfiError::Transport(format!("rusb init: {e}")))?;
        let devices = ctx
            .devices()
            .map_err(|e| MfiError::Transport(format!("rusb devices: {e}")))?;

        for dev in devices.iter() {
            let Ok(desc) = dev.device_descriptor() else {
                continue;
            };
            if desc.vendor_id() != CH341_VID || !CH341_PIDS.contains(&desc.product_id()) {
                continue;
            }
            let Ok(cfg) = dev.active_config_descriptor() else {
                continue;
            };

            let mut target_iface = None;
            let mut ep_in = None;
            let mut ep_out = None;
            for iface in cfg.interfaces() {
                for idesc in iface.descriptors() {
                    let mut found_in = None;
                    let mut found_out = None;
                    for ep in idesc.endpoint_descriptors() {
                        if ep.transfer_type() == TransferType::Bulk {
                            match ep.direction() {
                                Direction::In => found_in = Some(ep.address()),
                                Direction::Out => found_out = Some(ep.address()),
                            }
                        }
                    }
                    if let (Some(i), Some(o)) = (found_in, found_out) {
                        target_iface = Some(idesc.interface_number());
                        ep_in = Some(i);
                        ep_out = Some(o);
                        break;
                    }
                }
            }

            if let (Some(iface_num), Some(ep_in), Some(ep_out)) = (target_iface, ep_in, ep_out) {
                let handle = dev
                    .open()
                    .map_err(|e| MfiError::Transport(format!("open CH341 USB: {e}")))?;
                let _ = handle.set_auto_detach_kernel_driver(true);
                handle
                    .claim_interface(iface_num)
                    .map_err(|e| MfiError::Transport(format!("claim CH341 interface: {e}")))?;
                let transport = Self {
                    handle,
                    ep_in,
                    ep_out,
                };
                // Pulse D0 active-low reset (leaving high -> selects 0x11 if wired, harmless otherwise)
                let _ = transport.pulse_reset_d0(true);
                return Ok(Some(transport));
            }
        }
        Ok(None)
    }

    pub fn pulse_reset_d0(&self, drive_high: bool) -> Result<(), MfiError> {
        let pin_mask = 1u8;
        let low = [UIO_STREAM, UIO_OUT, UIO_DIR | pin_mask, UIO_END];
        let release = [
            UIO_STREAM,
            if drive_high { UIO_OUT | pin_mask } else { UIO_OUT },
            if drive_high { UIO_DIR | pin_mask } else { UIO_DIR },
            UIO_END,
        ];
        self.bulk_write(&low, Duration::from_millis(500))?;
        thread::sleep(Duration::from_millis(10));
        self.bulk_write(&release, Duration::from_millis(500))?;
        thread::sleep(Duration::from_millis(12));
        Ok(())
    }

    fn bulk_write(&self, data: &[u8], timeout: Duration) -> Result<(), MfiError> {
        let written = self
            .handle
            .write_bulk(self.ep_out, data, timeout)
            .map_err(|e| MfiError::Transport(format!("CH341 bulk_write: {e}")))?;
        if written != data.len() {
            return Err(MfiError::Transport(format!(
                "CH341 short bulk_write ({written}/{})",
                data.len()
            )));
        }
        Ok(())
    }

    fn bulk_read_at_most(
        &self,
        max_len: usize,
        first_timeout: Duration,
        quiet_timeout: Duration,
        allow_empty: bool,
    ) -> Result<Vec<u8>, MfiError> {
        let mut out = Vec::with_capacity(max_len);
        let mut scratch = [0u8; 64];
        let start = Instant::now();
        while out.len() < max_len {
            let timeout = if out.is_empty() {
                first_timeout
            } else {
                quiet_timeout
            };
            match self.handle.read_bulk(self.ep_in, &mut scratch, timeout) {
                Ok(0) => {
                    if !out.is_empty() || start.elapsed() >= timeout {
                        break;
                    }
                }
                Ok(n) => {
                    let take = n.min(max_len - out.len());
                    out.extend_from_slice(&scratch[..take]);
                }
                Err(rusb::Error::Timeout) => {
                    if !out.is_empty() || allow_empty {
                        break;
                    }
                    return Err(MfiError::Transport("CH341 bulk_read timeout".into()));
                }
                Err(e) => return Err(MfiError::Transport(format!("CH341 bulk_read: {e}"))),
            }
        }
        Ok(out)
    }

    fn run_transaction(
        &self,
        addr_7bit: u8,
        write_data: &[u8],
        read_len: usize,
    ) -> Result<Vec<u8>, MfiError> {
        let timeout = Duration::from_millis(1500);
        self.bulk_write(&[STREAM_START, I2C_SPEED_100KHZ, STREAM_END], timeout)?;
        if write_data.is_empty() && read_len > 0 {
            thread::sleep(Duration::from_millis(5));
        }

        let stream = encode_ch341_transaction(addr_7bit, write_data, read_len);
        let mut response = Vec::with_capacity(read_len);
        let mut offset = 0usize;
        while offset < stream.len() {
            let end = (offset + MAX_STREAM_PACKET_BYTES).min(stream.len());
            let seg = &stream[offset..end];
            self.bulk_write(seg, timeout)?;
            let (written_status_bytes, data_bytes) = segment_lengths(seg)?;
            if written_status_bytes + data_bytes > 0 {
                let first_wait = if data_bytes > 0 {
                    timeout
                } else {
                    Duration::from_millis(25)
                };
                let rx = self.bulk_read_at_most(
                    written_status_bytes + data_bytes,
                    first_wait,
                    Duration::from_millis(25),
                    data_bytes == 0,
                )?;
                if rx.len() < data_bytes {
                    return Err(MfiError::Transport(format!(
                        "CH341 short reply ({} < {data_bytes})",
                        rx.len()
                    )));
                }
                let status_count = rx.len() - data_bytes;
                for &st in &rx[..status_count] {
                    if (st & ACK_NACK_BIT) != 0 {
                        return Err(MfiError::Transport("CH341 I2C NACK".into()));
                    }
                }
                if data_bytes > 0 {
                    response.extend_from_slice(&rx[status_count..]);
                }
            }
            offset = end;
        }
        Ok(response)
    }
}

impl I2cTransport for Ch341UsbI2cTransport {
    fn read_register(&mut self, slave_addr: u8, reg: u8, buf: &mut [u8]) -> Result<(), MfiError> {
        let data = self.run_transaction(slave_addr, &[reg], buf.len())?;
        if data.len() != buf.len() {
            return Err(MfiError::Transport(format!(
                "CH341 read_register expected {}B, got {}B",
                buf.len(),
                data.len()
            )));
        }
        buf.copy_from_slice(&data);
        Ok(())
    }

    fn write_register(&mut self, slave_addr: u8, reg: u8, data: &[u8]) -> Result<(), MfiError> {
        let mut payload = Vec::with_capacity(1 + data.len());
        payload.push(reg);
        payload.extend_from_slice(data);
        let _ = self.run_transaction(slave_addr, &payload, 0)?;
        Ok(())
    }
}

fn encode_ch341_transaction(addr_7bit: u8, write_data: &[u8], read_len: usize) -> Vec<u8> {
    struct SegBuilder {
        all: Vec<u8>,
        cur: Vec<u8>,
    }
    impl SegBuilder {
        fn new() -> Self {
            Self {
                all: Vec::new(),
                cur: vec![STREAM_START],
            }
        }
        fn flush_intermediate(&mut self) {
            self.cur.push(STREAM_END);
            while self.cur.len() < MAX_STREAM_PACKET_BYTES {
                self.cur.push(0);
            }
            self.all.extend_from_slice(&self.cur);
            self.cur.clear();
            self.cur.push(STREAM_START);
        }
        fn push_cmd(&mut self, cmd: &[u8]) {
            if self.cur.len() + cmd.len() + 1 > MAX_STREAM_PACKET_BYTES {
                self.flush_intermediate();
            }
            self.cur.extend_from_slice(cmd);
        }
        fn start_and_write(&mut self, addr_byte: u8, data: &[u8]) {
            if self.cur.len() + 3 + 1 > MAX_STREAM_PACKET_BYTES {
                self.flush_intermediate();
            }
            self.cur.push(I2C_START);
            if data.is_empty() {
                self.push_cmd(&[I2C_WRITE | 1, addr_byte]);
            } else {
                self.push_cmd(&[I2C_WRITE, addr_byte]);
                for &b in data {
                    self.push_cmd(&[I2C_WRITE, b]);
                }
            }
        }
        fn read_bytes(&mut self, mut remaining: usize) {
            while remaining > MAX_READ_BLOCK {
                self.push_cmd(&[I2C_READ | (MAX_READ_BLOCK as u8)]);
                self.flush_intermediate();
                remaining -= MAX_READ_BLOCK;
            }
            if remaining > 1 {
                self.push_cmd(&[I2C_READ | ((remaining - 1) as u8)]);
            }
            self.push_cmd(&[I2C_READ]);
        }
        fn finish(mut self) -> Vec<u8> {
            if self.cur.len() + 2 > MAX_STREAM_PACKET_BYTES {
                self.flush_intermediate();
            }
            self.cur.push(I2C_STOP);
            self.cur.push(STREAM_END);
            self.all.extend_from_slice(&self.cur);
            self.all
        }
    }

    let mut b = SegBuilder::new();
    if !write_data.is_empty() {
        b.start_and_write(addr_7bit << 1, write_data);
    }
    if read_len > 0 {
        b.start_and_write((addr_7bit << 1) | 1, &[]);
        b.read_bytes(read_len);
    }
    b.finish()
}

fn segment_lengths(seg: &[u8]) -> Result<(usize, usize), MfiError> {
    let mut idx = 1usize;
    let mut status_bytes = 0usize;
    let mut data_bytes = 0usize;
    while idx < seg.len() {
        let cmd = seg[idx];
        idx += 1;
        if cmd == STREAM_END {
            return Ok((status_bytes, data_bytes));
        } else if cmd == I2C_START || cmd == I2C_STOP || (0x60..=0x63).contains(&cmd) {
            continue;
        } else if (0x80..=0xBF).contains(&cmd) {
            let n = usize::from(cmd & LENGTH_MASK).max(1);
            if (cmd & LENGTH_MASK) == 0 {
                status_bytes += 1;
            }
            idx += n;
        } else if cmd >= 0xC0 {
            let n = usize::from(cmd & LENGTH_MASK).max(1);
            data_bytes += n;
        } else {
            return Err(MfiError::Transport(format!(
                "unexpected CH341 command 0x{cmd:02x}"
            )));
        }
    }
    Ok((status_bytes, data_bytes))
}

/// Probes USB for a CH341A adapter connected to an Apple MFi coprocessor (`0x11` or `0x10`).
pub fn try_open_ch341_mfi() -> Option<(Arc<dyn MfiAuthenticator>, u8)> {
    let transport = Ch341UsbI2cTransport::open_first().ok().flatten()?;
    let client_hi = MfiI2cClient::new(transport, MFI_I2C_ADDR_HIGH);
    if client_hi.protocol_major().is_ok() {
        return Some((Arc::new(client_hi), MFI_I2C_ADDR_HIGH));
    }
    // Re-open with RST low for 0x10
    let transport = Ch341UsbI2cTransport::open_first().ok().flatten()?;
    let _ = transport.pulse_reset_d0(false);
    let client_lo = MfiI2cClient::new(transport, MFI_I2C_ADDR_LOW);
    if client_lo.protocol_major().is_ok() {
        return Some((Arc::new(client_lo), MFI_I2C_ADDR_LOW));
    }
    None
}
