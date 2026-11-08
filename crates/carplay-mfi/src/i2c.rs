//! Apple MFi Hardware Coprocessor (2.0C / 3.0) I2C register protocol, Linux `/dev/i2c-*` transport,
//! and CH341 USB-to-I2C command framing for testing physical MFi chips on macOS or Linux.

use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use crate::{MfiAuthenticator, MfiCertificateType, MfiError};

/// Standard Apple MFi Auth IC 7-bit I2C slave addresses (`0x10` RST=0, `0x11` RST=1).
pub const MFI_I2C_ADDR_LOW: u8 = 0x10;
pub const MFI_I2C_ADDR_HIGH: u8 = 0x11;

const REG_PROTOCOL_MAJOR: u8 = 0x02;
const REG_ERROR_CODE: u8 = 0x05;
const REG_AUTH_CONTROL_STATUS: u8 = 0x10;
const REG_SIG_LEN: u8 = 0x11;
const REG_SIG_DATA: u8 = 0x12;
const REG_CHALLENGE_LEN: u8 = 0x20;
const REG_CHALLENGE_DATA: u8 = 0x21;
const REG_CERT_LEN: u8 = 0x30;
const REG_CERT_DATA_BASE: u8 = 0x31;

const CMD_START_SIGNATURE: u8 = 0x01;
const CERT_PAGE_BYTES: usize = 128;
const MAX_POLL_RETRIES: usize = 40;

/// Low-level I2C register read/write abstraction (implemented by Linux `/dev/i2c-*`, USB-I2C CH341A, or mocks).
pub trait I2cTransport: Send + Sync {
    fn read_register(&mut self, slave_addr: u8, reg: u8, buf: &mut [u8]) -> Result<(), MfiError>;
    fn write_register(&mut self, slave_addr: u8, reg: u8, data: &[u8]) -> Result<(), MfiError>;
}

/// Apple MFi Authentication Coprocessor client over I2C.
pub struct MfiI2cClient<T: I2cTransport> {
    transport: Mutex<T>,
    slave_addr: u8,
    cached_cert: Mutex<Option<Vec<u8>>>,
}

impl<T: I2cTransport> MfiI2cClient<T> {
    pub fn new(transport: T, slave_addr: u8) -> Self {
        Self {
            transport: Mutex::new(transport),
            slave_addr,
            cached_cert: Mutex::new(None),
        }
    }

    fn read_reg_retry(
        transport: &mut T,
        addr: u8,
        reg: u8,
        buf: &mut [u8],
    ) -> Result<(), MfiError> {
        let mut last_err = None;
        for attempt in 0..8 {
            match transport.read_register(addr, reg, buf) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    last_err = Some(e);
                    // Apple MFi IC NACKs while waking from sleep (~500us - 5ms)
                    thread::sleep(Duration::from_millis(2 + attempt * 2));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| MfiError::Transport("I2C read failed".into())))
    }

    fn write_reg_retry(
        transport: &mut T,
        addr: u8,
        reg: u8,
        data: &[u8],
    ) -> Result<(), MfiError> {
        let mut last_err = None;
        for attempt in 0..8 {
            match transport.write_register(addr, reg, data) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    last_err = Some(e);
                    thread::sleep(Duration::from_millis(2 + attempt * 2));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| MfiError::Transport("I2C write failed".into())))
    }
}

impl<T: I2cTransport> MfiAuthenticator for MfiI2cClient<T> {
    fn protocol_major(&self) -> Result<u8, MfiError> {
        let mut guard = self
            .transport
            .lock()
            .map_err(|_| MfiError::Transport("I2C mutex poisoned".into()))?;
        let mut major = [0u8; 1];
        Self::read_reg_retry(&mut *guard, self.slave_addr, REG_PROTOCOL_MAJOR, &mut major)?;
        Ok(major[0])
    }

    fn certificate_type(&self) -> MfiCertificateType {
        MfiCertificateType::Mfi
    }

    fn read_certificate(&self) -> Result<Vec<u8>, MfiError> {
        if let Some(cert) = self
            .cached_cert
            .lock()
            .map_err(|_| MfiError::Transport("cert cache poisoned".into()))?
            .clone()
        {
            return Ok(cert);
        }

        let mut guard = self
            .transport
            .lock()
            .map_err(|_| MfiError::Transport("I2C mutex poisoned".into()))?;
        let mut len_bytes = [0u8; 2];
        Self::read_reg_retry(&mut *guard, self.slave_addr, REG_CERT_LEN, &mut len_bytes)?;
        let cert_len = u16::from_be_bytes(len_bytes) as usize;
        if cert_len == 0 || cert_len > 4096 {
            return Err(MfiError::InvalidCertificateLength(cert_len));
        }

        let mut cert = vec![0u8; cert_len];
        let mut offset = 0usize;
        let mut page = 0u8;
        while offset < cert_len {
            let chunk_len = (cert_len - offset).min(CERT_PAGE_BYTES);
            let reg = REG_CERT_DATA_BASE.wrapping_add(page);
            Self::read_reg_retry(
                &mut *guard,
                self.slave_addr,
                reg,
                &mut cert[offset..offset + chunk_len],
            )?;
            offset += chunk_len;
            page = page.wrapping_add(1);
        }

        drop(guard);
        if let Ok(mut cache) = self.cached_cert.lock() {
            *cache = Some(cert.clone());
        }
        Ok(cert)
    }

    fn sign_challenge(&self, challenge: &[u8]) -> Result<Vec<u8>, MfiError> {
        if challenge.is_empty() || challenge.len() > 128 {
            return Err(MfiError::InvalidChallengeLength(challenge.len()));
        }
        let mut guard = self
            .transport
            .lock()
            .map_err(|_| MfiError::Transport("I2C mutex poisoned".into()))?;

        let ch_len = (challenge.len() as u16).to_be_bytes();
        Self::write_reg_retry(&mut *guard, self.slave_addr, REG_CHALLENGE_LEN, &ch_len)?;
        Self::write_reg_retry(&mut *guard, self.slave_addr, REG_CHALLENGE_DATA, challenge)?;
        Self::write_reg_retry(
            &mut *guard,
            self.slave_addr,
            REG_AUTH_CONTROL_STATUS,
            &[CMD_START_SIGNATURE],
        )?;

        // Poll control/status register until upper nibble is 0x1 (signature ready)
        let mut ready = false;
        for _ in 0..MAX_POLL_RETRIES {
            thread::sleep(Duration::from_millis(10));
            let mut status = [0u8; 1];
            if Self::read_reg_retry(
                &mut *guard,
                self.slave_addr,
                REG_AUTH_CONTROL_STATUS,
                &mut status,
            )
            .is_ok()
            {
                if (status[0] & 0x80) != 0 {
                    let mut err_code = [0u8; 1];
                    let _ = Self::read_reg_retry(
                        &mut *guard,
                        self.slave_addr,
                        REG_ERROR_CODE,
                        &mut err_code,
                    );
                    return Err(MfiError::CoprocessorError {
                        status: status[0],
                        error_code: err_code[0],
                    });
                }
                if ((status[0] >> 4) & 0x07) == 0x01 {
                    ready = true;
                    break;
                }
            }
        }
        if !ready {
            return Err(MfiError::Transport(
                "timed out waiting for MFi signature generation".into(),
            ));
        }

        let mut sig_len_bytes = [0u8; 2];
        Self::read_reg_retry(
            &mut *guard,
            self.slave_addr,
            REG_SIG_LEN,
            &mut sig_len_bytes,
        )?;
        let sig_len = u16::from_be_bytes(sig_len_bytes) as usize;
        if sig_len == 0 || sig_len > 512 {
            return Err(MfiError::Transport(format!(
                "invalid MFi signature length: {sig_len}"
            )));
        }
        let mut sig = vec![0u8; sig_len];
        Self::read_reg_retry(&mut *guard, self.slave_addr, REG_SIG_DATA, &mut sig)?;
        Ok(sig)
    }
}

/// CH341A USB-to-I2C bulk packet encoder (VID `0x1A86`, PID `0x5512`) so a physical Apple MFi chip
/// can be driven from macOS or desktop Linux over a $2 CH341A USB adapter.
pub mod ch341 {
    pub const CH341_VID: u16 = 0x1A86;
    pub const CH341_PID: u16 = 0x5512;

    const CMD_I2C_STREAM: u8 = 0xAA;
    const I2C_STA: u8 = 0x74;
    const I2C_STO: u8 = 0x75;
    const I2C_OUT: u8 = 0x80;
    const I2C_IN: u8 = 0xC0;
    const I2C_SET: u8 = 0x60;
    const I2C_END: u8 = 0x00;

    /// Builds the CH341 command packet to configure I2C bus speed (`0` = 20kHz, `1` = 100kHz, `2` = 400kHz).
    pub fn speed_packet(speed_mode: u8) -> [u8; 3] {
        [CMD_I2C_STREAM, I2C_SET | (speed_mode & 0x03), I2C_END]
    }

    /// Builds a CH341 I2C write stream (`START | addr<<1 | reg | data... | STOP`).
    pub fn build_write_stream(slave_addr_7bit: u8, reg: u8, data: &[u8]) -> Vec<u8> {
        let payload_len = 2 + data.len();
        assert!(payload_len <= 29, "CH341 single stream write max 29 bytes");
        let mut pkt = Vec::with_capacity(5 + payload_len);
        pkt.push(CMD_I2C_STREAM);
        pkt.push(I2C_STA);
        pkt.push(I2C_OUT | (payload_len as u8));
        pkt.push(slave_addr_7bit << 1);
        pkt.push(reg);
        pkt.extend_from_slice(data);
        pkt.push(I2C_STO);
        pkt.push(I2C_END);
        pkt
    }

    /// Builds a CH341 I2C register select + repeated-start read stream.
    pub fn build_read_stream(slave_addr_7bit: u8, reg: u8, read_len: u8) -> Vec<u8> {
        assert!((1..=32).contains(&read_len), "CH341 read chunk must be 1..=32");
        vec![
            CMD_I2C_STREAM,
            I2C_STA,
            I2C_OUT | 2,
            slave_addr_7bit << 1,
            reg,
            I2C_STA,
            I2C_OUT | 1,
            (slave_addr_7bit << 1) | 0x01,
            I2C_IN | read_len,
            I2C_STO,
            I2C_END,
        ]
    }
}

/// Embedded Linux `/dev/i2c-X` transport for Allwinner T113-S3 / Rockchip RK3566 boards.
#[cfg(target_os = "linux")]
pub struct LinuxI2cDevTransport {
    file: std::fs::File,
    current_slave: Option<u8>,
}

#[cfg(target_os = "linux")]
impl LinuxI2cDevTransport {
    const I2C_SLAVE_IOCTL: libc::c_ulong = 0x0703;

    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, MfiError> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path.as_ref())
            .map_err(|e| MfiError::Transport(format!("open {:?}: {e}", path.as_ref())))?;
        Ok(Self {
            file,
            current_slave: None,
        })
    }

    fn select_slave(&mut self, addr: u8) -> Result<(), MfiError> {
        if self.current_slave == Some(addr) {
            return Ok(());
        }
        use std::os::fd::AsRawFd;
        let rc = unsafe {
            libc::ioctl(
                self.file.as_raw_fd(),
                Self::I2C_SLAVE_IOCTL as _,
                libc::c_ulong::from(addr),
            )
        };
        if rc < 0 {
            return Err(MfiError::Transport(format!(
                "ioctl(I2C_SLAVE, 0x{addr:02x}) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        self.current_slave = Some(addr);
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl I2cTransport for LinuxI2cDevTransport {
    fn read_register(&mut self, slave_addr: u8, reg: u8, buf: &mut [u8]) -> Result<(), MfiError> {
        use std::io::{Read, Write};
        self.select_slave(slave_addr)?;
        self.file
            .write_all(&[reg])
            .map_err(|e| MfiError::Transport(format!("i2c write reg 0x{reg:02x}: {e}")))?;
        self.file
            .read_exact(buf)
            .map_err(|e| MfiError::Transport(format!("i2c read reg 0x{reg:02x}: {e}")))?;
        Ok(())
    }

    fn write_register(&mut self, slave_addr: u8, reg: u8, data: &[u8]) -> Result<(), MfiError> {
        use std::io::Write;
        self.select_slave(slave_addr)?;
        let mut tx = Vec::with_capacity(1 + data.len());
        tx.push(reg);
        tx.extend_from_slice(data);
        self.file
            .write_all(&tx)
            .map_err(|e| MfiError::Transport(format!("i2c write reg 0x{reg:02x}: {e}")))?;
        Ok(())
    }
}
