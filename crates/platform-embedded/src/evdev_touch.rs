//! Pure-Rust Linux `evdev` (`/dev/input/event*`) Multitouch Protocol B & single-touch state machine
//! for automotive capacitive touch controllers (Goodix GT911, FocalTech FT5x06/FT5426, Ilitek).

use carplay_airplay::{AirPlayContact, AirPlayControlHandle};

pub const EV_SYN: u16 = 0x00;
pub const EV_KEY: u16 = 0x01;
pub const EV_ABS: u16 = 0x03;

pub const SYN_REPORT: u16 = 0x00;
pub const BTN_TOUCH: u16 = 0x14A;

pub const ABS_X: u16 = 0x00;
pub const ABS_Y: u16 = 0x01;
pub const ABS_MT_SLOT: u16 = 0x2F;
pub const ABS_MT_POSITION_X: u16 = 0x35;
pub const ABS_MT_POSITION_Y: u16 = 0x36;
pub const ABS_MT_TRACKING_ID: u16 = 0x39;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchRotation {
    Deg0,
    Deg90,
    Deg180,
    Deg270,
}

#[derive(Debug, Clone, Copy)]
pub struct TouchCalibration {
    pub x_min: i32,
    pub x_max: i32,
    pub y_min: i32,
    pub y_max: i32,
    pub invert_x: bool,
    pub invert_y: bool,
    pub rotation: TouchRotation,
}

impl Default for TouchCalibration {
    fn default() -> Self {
        Self {
            x_min: 0,
            x_max: 1024,
            y_min: 0,
            y_max: 600,
            invert_x: false,
            invert_y: false,
            rotation: TouchRotation::Deg0,
        }
    }
}

impl TouchCalibration {
    pub fn normalize(&self, raw_x: i32, raw_y: i32) -> (f64, f64) {
        let xr = (self.x_max - self.x_min).max(1) as f64;
        let yr = (self.y_max - self.y_min).max(1) as f64;
        let mut nx = ((raw_x - self.x_min) as f64 / xr).clamp(0.0, 1.0);
        let mut ny = ((raw_y - self.y_min) as f64 / yr).clamp(0.0, 1.0);
        if self.invert_x {
            nx = 1.0 - nx;
        }
        if self.invert_y {
            ny = 1.0 - ny;
        }
        match self.rotation {
            TouchRotation::Deg0 => (nx, ny),
            TouchRotation::Deg90 => (1.0 - ny, nx),
            TouchRotation::Deg180 => (1.0 - nx, 1.0 - ny),
            TouchRotation::Deg270 => (ny, 1.0 - nx),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct SlotData {
    active: bool,
    raw_x: i32,
    raw_y: i32,
    dirty_release: bool,
}

/// Stateful parser turning raw Linux `(type, code, value)` input events into normalized `AirPlayContact` batches on `SYN_REPORT`.
pub struct EvdevMultitouchState {
    cal: TouchCalibration,
    current_slot: usize,
    slots: [SlotData; 10],
    used_mt: bool,
    single_down: bool,
    single_x: i32,
    single_y: i32,
}

impl EvdevMultitouchState {
    pub fn new(cal: TouchCalibration) -> Self {
        Self {
            cal,
            current_slot: 0,
            slots: [SlotData::default(); 10],
            used_mt: false,
            single_down: false,
            single_x: 0,
            single_y: 0,
        }
    }

    /// Feeds one `input_event` triplet; returns `Some(contacts)` when `EV_SYN / SYN_REPORT` commits a touch frame.
    pub fn process_event(
        &mut self,
        ev_type: u16,
        code: u16,
        value: i32,
    ) -> Option<Vec<AirPlayContact>> {
        match (ev_type, code) {
            (EV_ABS, ABS_MT_SLOT) => {
                self.used_mt = true;
                self.current_slot = (value.max(0) as usize).min(self.slots.len() - 1);
                None
            }
            (EV_ABS, ABS_MT_TRACKING_ID) => {
                self.used_mt = true;
                let slot = &mut self.slots[self.current_slot];
                if value < 0 {
                    if slot.active {
                        slot.active = false;
                        slot.dirty_release = true;
                    }
                } else {
                    slot.active = true;
                    slot.dirty_release = false;
                }
                None
            }
            (EV_ABS, ABS_MT_POSITION_X) => {
                self.used_mt = true;
                self.slots[self.current_slot].raw_x = value;
                None
            }
            (EV_ABS, ABS_MT_POSITION_Y) => {
                self.used_mt = true;
                self.slots[self.current_slot].raw_y = value;
                None
            }
            (EV_ABS, ABS_X) => {
                self.single_x = value;
                None
            }
            (EV_ABS, ABS_Y) => {
                self.single_y = value;
                None
            }
            (EV_KEY, BTN_TOUCH) => {
                self.single_down = value != 0;
                None
            }
            (EV_SYN, SYN_REPORT) => {
                if self.used_mt {
                    let mut out = Vec::new();
                    for (idx, s) in self.slots.iter_mut().enumerate() {
                        if s.active || s.dirty_release {
                            let (nx, ny) = self.cal.normalize(s.raw_x, s.raw_y);
                            out.push(AirPlayContact {
                                id: idx,
                                x: nx,
                                y: ny,
                                down: s.active,
                            });
                            s.dirty_release = false;
                        }
                    }
                    Some(out)
                } else {
                    let (nx, ny) = self.cal.normalize(self.single_x, self.single_y);
                    Some(vec![AirPlayContact {
                        id: 0,
                        x: nx,
                        y: ny,
                        down: self.single_down,
                    }])
                }
            }
            _ => None,
        }
    }
}

/// Reads raw `struct input_event` records from `/dev/input/eventX` on Embedded Linux and forwards them to CarPlay.
#[cfg(target_os = "linux")]
pub fn run_linux_evdev_loop(
    device_path: &std::path::Path,
    calibration: TouchCalibration,
    control: AirPlayControlHandle,
    stop: &std::sync::atomic::AtomicBool,
) -> std::io::Result<()> {
    use std::io::Read;
    use std::sync::atomic::Ordering;

    let mut file = std::fs::File::open(device_path)?;
    let mut state = EvdevMultitouchState::new(calibration);
    // sizeof(struct input_event) is 24 bytes on 64-bit Linux (RK3566/H618) and 16 bytes on 32-bit ARM (T113-S3)
    const EVENT_SIZE: usize = std::mem::size_of::<libc::input_event>();
    let mut raw = [0u8; EVENT_SIZE];

    while !stop.load(Ordering::Relaxed) {
        file.read_exact(&mut raw)?;
        let ev: libc::input_event = unsafe { std::ptr::read_unaligned(raw.as_ptr().cast()) };
        if let Some(contacts) = state.process_event(ev.type_, ev.code, ev.value) {
            control.send_touch(&contacts);
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn run_linux_evdev_loop(
    _device_path: &std::path::Path,
    _calibration: TouchCalibration,
    _control: AirPlayControlHandle,
    _stop: &std::sync::atomic::AtomicBool,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Linux evdev touchscreen input is only available on target_os = \"linux\"",
    ))
}
