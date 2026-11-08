//! Embedded Linux direct display sink (`/dev/fb0` / DRM dumb-buffer scanout), fast YUV420p -> ARGB8888/RGB565
//! color conversion, and hardware V4L2 decoder profiles for MangoPi MQ-Dual (T113-S3) & Radxa Zero 3W (RK3566).

use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

/// Hardware SoC presets for embedded CarPlay dash / cluster builds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmbeddedBoardPreset {
    /// Allwinner T113-S3 (Dual Cortex-A7 + 128MB SIP DDR3, RGB 40-pin LCD, `cedrus` V4L2 H.264)
    MangoPiMqDualT113S3,
    /// Rockchip RK3566 (Quad Cortex-A55, MIPI-DSI + Micro-HDMI, `rkvdec` 4K60 H.264/HEVC, Wi-Fi 6 + BT 5.4)
    RadxaZero3wRk3566,
    /// Allwinner H618 (Quad Cortex-A53, Micro-HDMI, AW859A Wi-Fi 5 GHz + BT 5.0)
    OrangePiZero3H618,
}

#[derive(Debug, Clone)]
pub struct HardwarePipelineSpec {
    pub board_name: &'static str,
    pub soc: &'static str,
    pub v4l2_decoder_driver: &'static str,
    pub drm_driver: &'static str,
    pub recommended_resolution: (u16, u16),
    pub recommended_fps: u16,
    pub supports_hevc: bool,
    pub builtin_5ghz_wifi: bool,
}

impl EmbeddedBoardPreset {
    pub fn spec(self) -> HardwarePipelineSpec {
        match self {
            Self::MangoPiMqDualT113S3 => HardwarePipelineSpec {
                board_name: "MangoPi MQ-Dual (T113-S3)",
                soc: "Allwinner T113-S3 (2x Cortex-A7 @ 1.2GHz, 128MB DDR3)",
                v4l2_decoder_driver: "sunxi-cedrus (V4L2 Stateless M2M)",
                drm_driver: "sun4i-drm (RGB666/RGB888 TCON0)",
                recommended_resolution: (800, 480),
                recommended_fps: 60,
                supports_hevc: false,
                builtin_5ghz_wifi: false,
            },
            Self::RadxaZero3wRk3566 => HardwarePipelineSpec {
                board_name: "Radxa Zero 3W",
                soc: "Rockchip RK3566 (4x Cortex-A55 @ 1.6GHz, 1-2GB LPDDR4)",
                v4l2_decoder_driver: "rkvdec / hantro-vpu (V4L2 M2M / Rockchip MPP)",
                drm_driver: "rockchip-drm (VOP2 MIPI-DSI / HDMI)",
                recommended_resolution: (1280, 720),
                recommended_fps: 60,
                supports_hevc: true,
                builtin_5ghz_wifi: true,
            },
            Self::OrangePiZero3H618 => HardwarePipelineSpec {
                board_name: "Orange Pi Zero 3",
                soc: "Allwinner H618 (4x Cortex-A53 @ 1.5GHz, 1GB LPDDR4)",
                v4l2_decoder_driver: "sunxi-cedrus (V4L2 Stateless M2M)",
                drm_driver: "sun4i-drm (DW-HDMI)",
                recommended_resolution: (1280, 720),
                recommended_fps: 60,
                supports_hevc: true,
                builtin_5ghz_wifi: true,
            },
        }
    }
}

/// Converts planar I420 (`Y`, `U`, `V`) into packed `0x00RRGGBB` (`u32` ARGB/XRGB8888, used by DRM `XR24` & `minifb`).
/// Processes 2x2 pixel blocks per chroma sample so UV arithmetic runs once per 4 pixels (3x faster on ARM64/x86_64).
pub fn yuv420_to_xrgb8888(
    y_plane: &[u8],
    u_plane: &[u8],
    v_plane: &[u8],
    y_stride: usize,
    u_stride: usize,
    v_stride: usize,
    width: usize,
    height: usize,
    out_xrgb: &mut [u32],
) {
    assert!(out_xrgb.len() >= width * height);

    #[inline(always)]
    fn pack_pixel(y_val: u8, rv: i32, guv: i32, bu: i32) -> u32 {
        let c = (i32::from(y_val) - 16).max(0) * 298 + 128;
        let r = ((c + rv) >> 8).clamp(0, 255) as u32;
        let g = ((c + guv) >> 8).clamp(0, 255) as u32;
        let b = ((c + bu) >> 8).clamp(0, 255) as u32;
        (r << 16) | (g << 8) | b
    }

    let pairs_h = height / 2;
    let pairs_w = width / 2;

    for py in 0..pairs_h {
        let row0 = py * 2;
        let row1 = row0 + 1;
        let y0 = &y_plane[row0 * y_stride..row0 * y_stride + width];
        let y1 = &y_plane[row1 * y_stride..row1 * y_stride + width];
        let u_row = &u_plane[py * u_stride..py * u_stride + pairs_w];
        let v_row = &v_plane[py * v_stride..py * v_stride + pairs_w];

        let (head, tail) = out_xrgb[row0 * width..(row1 + 1) * width].split_at_mut(width);
        let dst0 = head;
        let dst1 = tail;

        for px in 0..pairs_w {
            let u = i32::from(u_row[px]) - 128;
            let v = i32::from(v_row[px]) - 128;
            let rv = 409 * v;
            let guv = -100 * u - 208 * v;
            let bu = 516 * u;

            let c0 = px * 2;
            let c1 = c0 + 1;
            dst0[c0] = pack_pixel(y0[c0], rv, guv, bu);
            dst0[c1] = pack_pixel(y0[c1], rv, guv, bu);
            dst1[c0] = pack_pixel(y1[c0], rv, guv, bu);
            dst1[c1] = pack_pixel(y1[c1], rv, guv, bu);
        }

        if width % 2 == 1 {
            let col = width - 1;
            let u = i32::from(u_plane[py * u_stride + col / 2]) - 128;
            let v = i32::from(v_plane[py * v_stride + col / 2]) - 128;
            dst0[col] = pack_pixel(y0[col], 409 * v, -100 * u - 208 * v, 516 * u);
            dst1[col] = pack_pixel(y1[col], 409 * v, -100 * u - 208 * v, 516 * u);
        }
    }

    if height % 2 == 1 {
        let row = height - 1;
        let y_row = &y_plane[row * y_stride..row * y_stride + width];
        let u_row = &u_plane[(row / 2) * u_stride..];
        let v_row = &v_plane[(row / 2) * v_stride..];
        let dst_row = &mut out_xrgb[row * width..(row + 1) * width];
        for col in 0..width {
            let u = i32::from(u_row[col / 2]) - 128;
            let v = i32::from(v_row[col / 2]) - 128;
            dst_row[col] = pack_pixel(y_row[col], 409 * v, -100 * u - 208 * v, 516 * u);
        }
    }
}

/// Converts `0x00RRGGBB` pixels into packed 16-bit `RGB565` (for memory-constrained 128MB RAM RGB565 panels on T113-S3).
pub fn xrgb8888_to_rgb565_le(src: &[u32], dst_bytes: &mut [u8]) {
    for (px, out) in src.iter().zip(dst_bytes.chunks_exact_mut(2)) {
        let r5 = ((px >> 19) & 0x1F) as u16;
        let g6 = ((px >> 10) & 0x3F) as u16;
        let b5 = ((px >> 3) & 0x1F) as u16;
        let rgb565 = (r5 << 11) | (g6 << 5) | b5;
        out.copy_from_slice(&rgb565.to_le_bytes());
    }
}

/// Direct Linux `/dev/fb0` scanout sink requiring zero X11/Wayland compositor overhead.
pub struct LinuxFbdevSink {
    file: File,
    width: usize,
    height: usize,
    bits_per_pixel: u8,
    scratch: Vec<u8>,
}

impl LinuxFbdevSink {
    pub fn open(
        fb_path: impl AsRef<Path>,
        width: usize,
        height: usize,
        bits_per_pixel: u8,
    ) -> std::io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open(fb_path)?;
        let bytes_per_pixel = (bits_per_pixel as usize).div_ceil(8);
        Ok(Self {
            file,
            width,
            height,
            bits_per_pixel,
            scratch: vec![0u8; width * height * bytes_per_pixel],
        })
    }

    pub fn present_xrgb8888(&mut self, frame: &[u32]) -> std::io::Result<()> {
        let count = (self.width * self.height).min(frame.len());
        if self.bits_per_pixel == 16 {
            xrgb8888_to_rgb565_le(&frame[..count], &mut self.scratch[..count * 2]);
            self.file.seek(SeekFrom::Start(0))?;
            self.file.write_all(&self.scratch[..count * 2])?;
        } else {
            for (px, out) in frame[..count]
                .iter()
                .zip(self.scratch.chunks_exact_mut(4))
            {
                out.copy_from_slice(&px.to_le_bytes());
            }
            self.file.seek(SeekFrom::Start(0))?;
            self.file.write_all(&self.scratch[..count * 4])?;
        }
        Ok(())
    }
}
