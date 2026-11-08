//! CarPlay HID descriptors and binary report encoders (Multitouch 2-finger, Rotary Knob, Media, Telephony).

use crate::bplist::PlistValue;

pub const TOUCH_HID_UID: u32 = 0x2a2a2a2a;
pub const KNOB_HID_UID: u32 = 0x2a2a2a2b;
pub const MEDIA_HID_UID: u32 = 0x2a2a2a2c;
pub const TELEPHONY_HID_UID: u32 = 0x2a2a2a2d;

pub const TOUCH_SLOTS: usize = 2;
const BYTES_PER_FINGER: usize = 6;

/// One normalized (`0.0..=1.0`) or pixel-scaled touch contact.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AirPlayContact {
    pub id: usize,
    pub x: f64,
    pub y: f64,
    pub down: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AirPlayKnobState {
    pub select: bool,
    pub home: bool,
    pub back: bool,
    pub x: i8,
    pub y: i8,
    pub wheel: i8,
}

/// Maps arbitrary OS/evdev pointer IDs into the 2 fixed CarPlay HID multitouch slots (`0` and `1`).
#[derive(Debug, Default)]
pub struct TouchSlotAssigner {
    slots: [Option<usize>; TOUCH_SLOTS],
}

impl TouchSlotAssigner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn assign(&mut self, incoming: &[AirPlayContact]) -> Vec<AirPlayContact> {
        if incoming.is_empty() {
            self.slots = [None; TOUCH_SLOTS];
            return Vec::new();
        }
        let mut out = Vec::with_capacity(TOUCH_SLOTS);
        for c in incoming {
            // Find existing slot or allocate free slot
            let slot_idx = self
                .slots
                .iter()
                .position(|&s| s == Some(c.id))
                .or_else(|| self.slots.iter().position(|s| s.is_none()));
            if let Some(slot) = slot_idx {
                if c.down {
                    self.slots[slot] = Some(c.id);
                } else {
                    self.slots[slot] = None;
                }
                out.push(AirPlayContact {
                    id: slot,
                    x: c.x.clamp(0.0, 1.0),
                    y: c.y.clamp(0.0, 1.0),
                    down: c.down,
                });
            }
        }
        // Clear slots whose pointers disappeared without an explicit up event
        for slot in 0..TOUCH_SLOTS {
            if let Some(pid) = self.slots[slot] {
                if !incoming.iter().any(|c| c.id == pid && c.down) {
                    self.slots[slot] = None;
                }
            }
        }
        out
    }
}

/// Encodes the 12-byte 2-finger HID report (`[slot, down, x_lo, x_hi, y_lo, y_hi] * 2`).
/// Expects pixel coordinates (`0..width_pixels`, `0..height_pixels`).
pub fn encode_touch_report(pixel_contacts: &[AirPlayContact]) -> [u8; BYTES_PER_FINGER * TOUCH_SLOTS] {
    let mut report = [0u8; BYTES_PER_FINGER * TOUCH_SLOTS];
    for slot in 0..TOUCH_SLOTS {
        let offset = slot * BYTES_PER_FINGER;
        report[offset] = slot as u8;
        if let Some(c) = pixel_contacts.iter().find(|c| c.id == slot) {
            report[offset + 1] = u8::from(c.down);
            let x = c.x.max(0.0).round() as u16;
            let y = c.y.max(0.0).round() as u16;
            report[offset + 2..offset + 4].copy_from_slice(&x.to_le_bytes());
            report[offset + 4..offset + 6].copy_from_slice(&y.to_le_bytes());
        }
    }
    report
}

/// Decodes a 12-byte touch report back into pixel contacts (useful for testing & simulator).
pub fn decode_touch_report(report: &[u8]) -> Vec<AirPlayContact> {
    let mut out = Vec::new();
    for chunk in report.chunks_exact(BYTES_PER_FINGER) {
        let slot = chunk[0] as usize;
        let down = chunk[1] != 0;
        let x = f64::from(u16::from_le_bytes([chunk[2], chunk[3]]));
        let y = f64::from(u16::from_le_bytes([chunk[4], chunk[5]]));
        out.push(AirPlayContact {
            id: slot,
            x,
            y,
            down,
        });
    }
    out
}

pub fn encode_knob_report(state: AirPlayKnobState) -> [u8; 4] {
    let buttons = u8::from(state.select)
        | (u8::from(state.home) << 1)
        | (u8::from(state.back) << 2);
    [
        buttons,
        state.x.clamp(-127, 127) as u8,
        state.y.clamp(-127, 127) as u8,
        state.wheel.clamp(-127, 127) as u8,
    ]
}

pub fn encode_media_report(index: u8) -> [u8; 1] {
    [index]
}

pub fn encode_telephony_report(index: u8) -> [u8; 1] {
    [index]
}

pub fn touch_hid_device(x_max: u16, y_max: u16, display_uuid: &str) -> PlistValue {
    hid_entry(
        TOUCH_HID_UID,
        "carplay-rs Touchscreen",
        multitouch_descriptor(x_max, y_max),
        display_uuid,
    )
}

pub fn knob_hid_device(display_uuid: &str) -> PlistValue {
    hid_entry(
        KNOB_HID_UID,
        "carplay-rs Knob",
        KNOB_DESCRIPTOR.to_vec(),
        display_uuid,
    )
}

pub fn media_hid_device(display_uuid: &str) -> PlistValue {
    hid_entry(
        MEDIA_HID_UID,
        "carplay-rs Media",
        MEDIA_DESCRIPTOR.to_vec(),
        display_uuid,
    )
}

pub fn telephony_hid_device(display_uuid: &str) -> PlistValue {
    hid_entry(
        TELEPHONY_HID_UID,
        "carplay-rs Telephony",
        TELEPHONY_DESCRIPTOR.to_vec(),
        display_uuid,
    )
}

fn hid_entry(uid: u32, name: &str, descriptor: Vec<u8>, display_uuid: &str) -> PlistValue {
    plist_dict! {
        "hidProductID" => 1u64,
        "hidVendorID" => 2u64,
        "hidCountryCode" => 0u64,
        "uuid" => format!("{uid:x}"),
        "name" => name,
        "displayUUID" => display_uuid,
        "hidDescriptor" => descriptor,
    }
}

fn multitouch_descriptor(x_max: u16, y_max: u16) -> Vec<u8> {
    let mut d = vec![0x05, 0x0d, 0x09, 0x04, 0xa1, 0x01];
    let x_lo = (x_max & 0xff) as u8;
    let x_hi = (x_max >> 8) as u8;
    let y_lo = (y_max & 0xff) as u8;
    let y_hi = (y_max >> 8) as u8;
    let finger = [
        0x05, 0x0d, 0x09, 0x22, 0xa1, 0x02, 0x09, 0x38, 0x75, 0x08, 0x95, 0x01, 0x81, 0x02, 0x15,
        0x00, 0x25, 0x01, 0x09, 0x33, 0x75, 0x01, 0x95, 0x01, 0x81, 0x02, 0x95, 0x07, 0x81, 0x03,
        0x05, 0x01, 0x26, x_lo, x_hi, 0x09, 0x30, 0x75, 0x10, 0x95, 0x01, 0x81, 0x02, 0x26, y_lo,
        y_hi, 0x09, 0x31, 0x81, 0x02, 0xc0,
    ];
    for _ in 0..TOUCH_SLOTS {
        d.extend_from_slice(&finger);
    }
    d.push(0xc0);
    d
}

const KNOB_DESCRIPTOR: &[u8] = &[
    0x05, 0x01, 0x09, 0x08, 0xa1, 0x01, 0x05, 0x09, 0x09, 0x01, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01,
    0x95, 0x01, 0x81, 0x02, 0x05, 0x0c, 0x0a, 0x23, 0x02, 0x0a, 0x24, 0x02, 0x95, 0x02, 0x81, 0x02,
    0x95, 0x05, 0x81, 0x01, 0x05, 0x01, 0x09, 0x01, 0xa1, 0x00, 0x09, 0x30, 0x09, 0x31, 0x15, 0x81,
    0x25, 0x7f, 0x75, 0x08, 0x95, 0x02, 0x81, 0x02, 0xc0, 0x09, 0x38, 0x15, 0x81, 0x25, 0x7f, 0x75,
    0x08, 0x95, 0x01, 0x81, 0x06, 0xc0,
];

const MEDIA_DESCRIPTOR: &[u8] = &[
    0x05, 0x0c, 0x09, 0x01, 0xa1, 0x01, 0x15, 0x00, 0x25, 0x06, 0x05, 0x0c, 0x0a, 0x00, 0x00, 0x0a,
    0xb0, 0x00, 0x0a, 0xb1, 0x00, 0x0a, 0xcd, 0x00, 0x0a, 0xb5, 0x00, 0x0a, 0xb6, 0x00, 0x0a, 0x9e,
    0x02, 0x75, 0x08, 0x95, 0x01, 0x81, 0x00, 0xc0,
];

const TELEPHONY_DESCRIPTOR: &[u8] = &[
    0x05, 0x0b, 0x09, 0x07, 0xa1, 0x01, 0x15, 0x00, 0x25, 0x11, 0x05, 0x0b, 0x09, 0x00, 0x09, 0x20,
    0x09, 0x21, 0x09, 0x26, 0x09, 0x2f, 0x09, 0xb0, 0x09, 0xb1, 0x09, 0xb2, 0x09, 0xb3, 0x09, 0xb4,
    0x09, 0xb5, 0x09, 0xb6, 0x09, 0xb7, 0x09, 0xb8, 0x09, 0xb9, 0x09, 0xba, 0x09, 0xbb, 0x05, 0x07,
    0x09, 0x2a, 0x75, 0x08, 0x95, 0x01, 0x81, 0x00, 0xc0,
];
