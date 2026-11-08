//! `platform-embedded`: Fast-boot Embedded Linux appliance support (DRM/`/dev/fb0` zero-compositor video,
//! `evdev` capacitive multitouch input, YUV420->XRGB8888/RGB565 scanout, and Buildroot init helpers).

pub mod drm_fb;
pub mod evdev_touch;

pub use drm_fb::{
    xrgb8888_to_rgb565_le, yuv420_to_xrgb8888, EmbeddedBoardPreset, HardwarePipelineSpec,
    LinuxFbdevSink,
};
pub use evdev_touch::{
    run_linux_evdev_loop, EvdevMultitouchState, TouchCalibration, TouchRotation, ABS_MT_POSITION_X,
    ABS_MT_POSITION_Y, ABS_MT_SLOT, ABS_MT_TRACKING_ID, EV_ABS, EV_SYN, SYN_REPORT,
};

/// Generates a minimal Buildroot / busybox `/etc/init.d/S10carplay` early-boot script (< 2s cold boot).
pub fn generate_fastboot_init_script(
    preset: EmbeddedBoardPreset,
    ap_cfg: &carplay_transport::WirelessApConfig,
) -> String {
    let spec = preset.spec();
    format!(
        "#!/bin/sh\n\
         # Fast-boot CarPlay-RS appliance init for {board} ({soc})\n\
         # Decoder: {dec} | Display: {drm}\n\
         case \"$1\" in\n\
           start)\n\
             ip link set lo up\n\
             if [ -d /sys/class/net/{iface} ]; then\n\
               ip link set {iface} up\n\
               ip -6 addr add fe80::1/64 dev {iface} 2>/dev/null || true\n\
               hostapd -B /etc/hostapd-carplay.conf\n\
             fi\n\
             exec /usr/bin/carplay-appliance --width {w} --height {h} --fps {fps} &\n\
             ;;\n\
           stop)\n\
             killall carplay-appliance hostapd 2>/dev/null || true\n\
             ;;\n\
         esac\n",
        board = spec.board_name,
        soc = spec.soc,
        dec = spec.v4l2_decoder_driver,
        drm = spec.drm_driver,
        iface = ap_cfg.interface,
        w = spec.recommended_resolution.0,
        h = spec.recommended_resolution.1,
        fps = spec.recommended_fps,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evdev_multitouch_type_b_tracks_two_fingers_and_rotation() {
        let cal = TouchCalibration {
            x_min: 0,
            x_max: 1000,
            y_min: 0,
            y_max: 500,
            invert_x: false,
            invert_y: false,
            rotation: TouchRotation::Deg0,
        };
        let mut mt = EvdevMultitouchState::new(cal);

        // Finger 0 down at (500, 250) -> (0.5, 0.5)
        mt.process_event(EV_ABS, ABS_MT_SLOT, 0);
        mt.process_event(EV_ABS, ABS_MT_TRACKING_ID, 10);
        mt.process_event(EV_ABS, ABS_MT_POSITION_X, 500);
        mt.process_event(EV_ABS, ABS_MT_POSITION_Y, 250);

        // Finger 1 down at (1000, 500) -> (1.0, 1.0)
        mt.process_event(EV_ABS, ABS_MT_SLOT, 1);
        mt.process_event(EV_ABS, ABS_MT_TRACKING_ID, 11);
        mt.process_event(EV_ABS, ABS_MT_POSITION_X, 1000);
        mt.process_event(EV_ABS, ABS_MT_POSITION_Y, 500);

        let contacts = mt.process_event(EV_SYN, SYN_REPORT, 0).unwrap();
        assert_eq!(contacts.len(), 2);
        assert!((contacts[0].x - 0.5).abs() < 1e-6);
        assert!((contacts[0].y - 0.5).abs() < 1e-6);
        assert!(contacts[0].down);
        assert!(contacts[1].down);

        // Release finger 0 (`ABS_MT_TRACKING_ID = -1`)
        mt.process_event(EV_ABS, ABS_MT_SLOT, 0);
        mt.process_event(EV_ABS, ABS_MT_TRACKING_ID, -1);
        let contacts = mt.process_event(EV_SYN, SYN_REPORT, 0).unwrap();
        assert_eq!(contacts.len(), 2);
        assert!(!contacts[0].down);
        assert!(contacts[1].down);
    }

    #[test]
    fn yuv420_and_rgb565_conversion_works() {
        let y = [235u8; 4];
        let u = [128u8; 1];
        let v = [128u8; 1];
        let mut xrgb = [0u32; 4];
        yuv420_to_xrgb8888(&y, &u, &v, 2, 1, 1, 2, 2, &mut xrgb);
        assert_eq!(xrgb[0], 0x00FF_FFFF);
        let mut rgb565 = [0u8; 8];
        xrgb8888_to_rgb565_le(&xrgb, &mut rgb565);
        assert_eq!(u16::from_le_bytes([rgb565[0], rgb565[1]]), 0xFFFF);
    }
}
