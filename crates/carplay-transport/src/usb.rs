//! Apple iPhone USB discovery (`VID 0x05AC`), CarPlay role-switch / NCM configuration activation,
//! and bulk endpoint inspection via `rusb` (works on both macOS and embedded Linux).

use std::time::Duration;
use rusb::{Context, Device, DeviceHandle, Direction, TransferType, UsbContext};
use thiserror::Error;

pub const APPLE_VID: u16 = 0x05AC;
/// Standard iPhone product IDs (0x12A8..0x12AB normal/mux/NCM modes).
pub const IPHONE_PID_MIN: u16 = 0x1290;
pub const IPHONE_PID_MAX: u16 = 0x12BF;

#[derive(Debug, Error)]
pub enum UsbTransportError {
    #[error("libusb error: {0}")]
    Rusb(#[from] rusb::Error),
    #[error("no Apple iPhone USB device found")]
    IphoneNotFound,
    #[error("required USB interface ({0}) not present in active configuration")]
    InterfaceMissing(&'static str),
}

#[derive(Debug, Clone)]
pub struct BulkEndpoints {
    pub interface_number: u8,
    pub alt_setting: u8,
    pub ep_in: u8,
    pub ep_out: u8,
    pub max_packet_in: u16,
    pub max_packet_out: u16,
}

#[derive(Debug, Clone)]
pub struct DiscoveredIphone {
    pub bus: u8,
    pub address: u8,
    pub vendor_id: u16,
    pub product_id: u16,
    pub serial_number: Option<String>,
    pub product_name: Option<String>,
    pub has_ncm: bool,
    pub has_usbmux: bool,
    pub has_apple_ethernet: bool,
    pub has_direct_iap2: bool,
    pub ncm_control_interface: Option<u8>,
    pub recommended_config_value: Option<u8>,
}

/// Scans connected USB devices on macOS or Linux and returns all detected Apple iPhones and their CarPlay interfaces.
pub fn scan_connected_iphones() -> Result<Vec<DiscoveredIphone>, UsbTransportError> {
    let ctx = Context::new()?;
    let mut found = Vec::new();

    for device in ctx.devices()?.iter() {
        let Ok(desc) = device.device_descriptor() else {
            continue;
        };
        if desc.vendor_id() != APPLE_VID {
            continue;
        }
        // Filter out Apple keyboards/trackpads on MacBooks; keep iOS/iPadOS PIDs (0x1290..=0x12FF)
        if !(0x1290..=0x12FF).contains(&desc.product_id()) {
            continue;
        }

        let mut serial_number = None;
        let mut product_name = None;
        if let Ok(handle) = device.open() {
            let timeout = Duration::from_millis(200);
            if let Ok(langs) = handle.read_languages(timeout) {
                if let Some(&lang) = langs.first() {
                    product_name = handle
                        .read_product_string(lang, &desc, timeout)
                        .ok()
                        .map(|s| s.trim_end_matches('\0').trim().to_string());
                    serial_number = handle
                        .read_serial_number_string(lang, &desc, timeout)
                        .ok()
                        .map(|s| s.trim_end_matches('\0').trim().to_string());
                }
            }
        }

        let mut has_ncm = false;
        let mut has_usbmux = false;
        let mut has_apple_ethernet = false;
        let mut has_direct_iap2 = false;
        let mut ncm_control_interface = None;
        let mut recommended_config_value = None;

        // Check active configuration first for Apple Ethernet (ff/fd/01) and active NCM interface number
        if let Ok(active_cfg) = device.active_config_descriptor() {
            for iface in active_cfg.interfaces() {
                for idesc in iface.descriptors() {
                    match (
                        idesc.class_code(),
                        idesc.sub_class_code(),
                        idesc.protocol_code(),
                    ) {
                        (2, 13, 0) => {
                            ncm_control_interface = Some(idesc.interface_number());
                        }
                        (255, 253, 1) => {
                            has_apple_ethernet = true;
                        }
                        _ => {}
                    }
                }
            }
        }

        for cfg_idx in 0..desc.num_configurations() {
            let Ok(cfg) = device.config_descriptor(cfg_idx) else {
                continue;
            };
            let mut cfg_ncm = false;
            let mut cfg_mux = false;
            let mut cfg_eth = false;
            for iface in cfg.interfaces() {
                for idesc in iface.descriptors() {
                    match (
                        idesc.class_code(),
                        idesc.sub_class_code(),
                        idesc.protocol_code(),
                    ) {
                        (2, 13, 0) => {
                            has_ncm = true;
                            cfg_ncm = true;
                            if ncm_control_interface.is_none() {
                                ncm_control_interface = Some(idesc.interface_number());
                            }
                        }
                        (255, 254, 2) => {
                            has_usbmux = true;
                            cfg_mux = true;
                        }
                        (255, 253, 1) => {
                            cfg_eth = true;
                        }
                        (255, 240, 0) => {
                            has_direct_iap2 = true;
                        }
                        _ => {}
                    }
                }
            }
            if cfg_ncm && cfg_mux && (cfg_eth || recommended_config_value.is_none()) {
                recommended_config_value = Some(cfg.number());
            }
        }

        found.push(DiscoveredIphone {
            bus: device.bus_number(),
            address: device.address(),
            vendor_id: desc.vendor_id(),
            product_id: desc.product_id(),
            serial_number,
            product_name,
            has_ncm,
            has_usbmux,
            has_apple_ethernet,
            has_direct_iap2,
            ncm_control_interface,
            recommended_config_value,
        });
    }

    Ok(found)
}

/// Checks if a connected iPhone is already in Apple CarPlay USB mode (`ff/fd/01` present in active config);
/// if not, sends the non-intrusive EP0 vendor request (`0xC0, 0x52, 0x0000, 0x0004`) so iOS switches to CarPlay NCM mode.
/// Returns `Ok(true)` if the mode-switch vendor transfer was issued (the iPhone may briefly re-enumerate).
pub fn request_carplay_usb_mode_if_needed() -> Result<bool, UsbTransportError> {
    let ctx = Context::new()?;
    for device in ctx.devices()?.iter() {
        let Ok(desc) = device.device_descriptor() else {
            continue;
        };
        if desc.vendor_id() != APPLE_VID || !(0x1290..=0x12FF).contains(&desc.product_id()) {
            continue;
        }
        let mut active_has_apple_eth = false;
        if let Ok(active_cfg) = device.active_config_descriptor() {
            for iface in active_cfg.interfaces() {
                for idesc in iface.descriptors() {
                    if (
                        idesc.class_code(),
                        idesc.sub_class_code(),
                        idesc.protocol_code(),
                    ) == (255, 253, 1)
                    {
                        active_has_apple_eth = true;
                    }
                }
            }
        }
        if active_has_apple_eth {
            return Ok(false);
        }
        if let Ok(handle) = device.open() {
            let mut status_byte = [0u8; 1];
            match handle.read_control(
                0xC0,
                0x52,
                0x0000,
                0x0004,
                &mut status_byte,
                Duration::from_millis(500),
            ) {
                Ok(_) => {
                    tracing::info!(
                        "Sent Apple CarPlay USB mode vendor request (0x52 -> status=0x{:02x})",
                        status_byte[0]
                    );
                    return Ok(true);
                }
                Err(e) => {
                    tracing::debug!("Apple 0x52 vendor control transfer skipped/failed: {e}");
                }
            }
        }
    }
    Ok(false)
}

/// Active USB host session with an iPhone for CarPlay NCM + USBMUX/iAP2 communication.
pub struct IphoneUsbSession {
    handle: DeviceHandle<Context>,
    pub usbmux_eps: Option<BulkEndpoints>,
    pub ncm_data_eps: Option<BulkEndpoints>,
    pub ncm_ctrl_iface: Option<u8>,
}

impl IphoneUsbSession {
    pub fn open_first() -> Result<Self, UsbTransportError> {
        let ctx = Context::new()?;
        for device in ctx.devices()?.iter() {
            let Ok(desc) = device.device_descriptor() else {
                continue;
            };
            if desc.vendor_id() == APPLE_VID && (0x1290..=0x12FF).contains(&desc.product_id()) {
                return Self::open_device(device);
            }
        }
        Err(UsbTransportError::IphoneNotFound)
    }

    pub fn open_device(device: Device<Context>) -> Result<Self, UsbTransportError> {
        let handle = device.open()?;

        // Send Apple CarPlay / NCM configuration unlock vendor control transfer (`0xC0, bRequest=0x52, wIndex=0x0004`)
        let mut status_byte = [0u8; 1];
        let _ = handle.read_control(
            0xC0,
            0x52,
            0x0000,
            0x0004,
            &mut status_byte,
            Duration::from_millis(500),
        );

        let desc = device.device_descriptor()?;
        let mut usbmux_eps = None;
        let mut ncm_data_eps = None;
        let mut ncm_ctrl_iface = None;

        for cfg_idx in 0..desc.num_configurations() {
            let Ok(cfg) = device.config_descriptor(cfg_idx) else {
                continue;
            };
            for iface in cfg.interfaces() {
                for idesc in iface.descriptors() {
                    let triple = (
                        idesc.class_code(),
                        idesc.sub_class_code(),
                        idesc.protocol_code(),
                    );
                    if triple == (2, 13, 0) {
                        ncm_ctrl_iface = Some(idesc.interface_number());
                    } else if triple == (255, 254, 2) {
                        if let Some(eps) = find_bulk_pair(&idesc) {
                            usbmux_eps = Some(eps);
                        }
                    } else if triple == (10, 0, 1) || (triple.0 == 10 && idesc.num_endpoints() >= 2)
                    {
                        if let Some(eps) = find_bulk_pair(&idesc) {
                            ncm_data_eps = Some(eps);
                        }
                    }
                }
            }
            if ncm_data_eps.is_some() && usbmux_eps.is_some() {
                let _ = handle.set_active_configuration(cfg.number());
                break;
            }
        }

        let _ = handle.set_auto_detach_kernel_driver(true);

        Ok(Self {
            handle,
            usbmux_eps,
            ncm_data_eps,
            ncm_ctrl_iface,
        })
    }

    /// Sends Apple USB Role Switch vendor command (`bmRequestType = 0x40, bRequest = 0x51, wValue = 0x0001`).
    /// Used on OTG boards (MangoPi / Radxa Zero 3W) when the iPhone needs CarPlay role negotiation.
    pub fn request_apple_role_switch(&mut self) -> Result<(), UsbTransportError> {
        self.handle
            .write_control(0x40, 0x51, 0x0001, 0x0000, &[], Duration::from_millis(500))?;
        Ok(())
    }

    pub fn claim_ncm(&mut self) -> Result<BulkEndpoints, UsbTransportError> {
        let eps = self
            .ncm_data_eps
            .clone()
            .ok_or(UsbTransportError::InterfaceMissing("CDC-NCM Data"))?;
        if let Some(ctrl) = self.ncm_ctrl_iface {
            let _ = self.handle.claim_interface(ctrl);
        }
        self.handle.claim_interface(eps.interface_number)?;
        self.handle
            .set_alternate_setting(eps.interface_number, eps.alt_setting)?;
        Ok(eps)
    }

    pub fn claim_usbmux(&mut self) -> Result<BulkEndpoints, UsbTransportError> {
        let eps = self
            .usbmux_eps
            .clone()
            .ok_or(UsbTransportError::InterfaceMissing("Apple USBMUX"))?;
        self.handle.claim_interface(eps.interface_number)?;
        if eps.alt_setting != 0 {
            self.handle
                .set_alternate_setting(eps.interface_number, eps.alt_setting)?;
        }
        Ok(eps)
    }

    pub fn bulk_read(&self, ep_in: u8, buf: &mut [u8], timeout: Duration) -> Result<usize, UsbTransportError> {
        Ok(self.handle.read_bulk(ep_in, buf, timeout)?)
    }

    pub fn bulk_write(&self, ep_out: u8, data: &[u8], timeout: Duration) -> Result<usize, UsbTransportError> {
        Ok(self.handle.write_bulk(ep_out, data, timeout)?)
    }
}

fn find_bulk_pair(idesc: &rusb::InterfaceDescriptor<'_>) -> Option<BulkEndpoints> {
    let mut ep_in = None;
    let mut ep_out = None;
    let mut max_in = 512;
    let mut max_out = 512;
    for ep in idesc.endpoint_descriptors() {
        if ep.transfer_type() == TransferType::Bulk {
            match ep.direction() {
                Direction::In => {
                    ep_in = Some(ep.address());
                    max_in = ep.max_packet_size();
                }
                Direction::Out => {
                    ep_out = Some(ep.address());
                    max_out = ep.max_packet_size();
                }
            }
        }
    }
    Some(BulkEndpoints {
        interface_number: idesc.interface_number(),
        alt_setting: idesc.setting_number(),
        ep_in: ep_in?,
        ep_out: ep_out?,
        max_packet_in: max_in,
        max_packet_out: max_out,
    })
}
