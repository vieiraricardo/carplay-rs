#![cfg(target_os = "macos")]

use std::sync::{Arc, Mutex};
use apple_cf::cm::{CMBlockBuffer, CMFormatDescription, CMSampleBuffer};
use videotoolbox::{DecodedFrame, DecompressionSession};

pub struct VtDecoder {
    format_desc: Option<CMFormatDescription>,
    session: Option<DecompressionSession>,
    latest_frame: Arc<Mutex<Option<Vec<u32>>>>,
    width: usize,
    height: usize,
}

impl VtDecoder {
    pub fn new(width: usize, height: usize) -> Self {
        Self {
            format_desc: None,
            session: None,
            latest_frame: Arc::new(Mutex::new(None)),
            width,
            height,
        }
    }

    pub fn configure_avcc(&mut self, avcc: &[u8]) -> bool {
        if avcc.len() < 7 || avcc[0] != 1 {
            return false;
        }
        let num_sps = (avcc[5] & 0x1F) as usize;
        let mut pos = 6usize;
        let mut sps_list = Vec::new();
        for _ in 0..num_sps {
            if pos + 2 > avcc.len() {
                return false;
            }
            let len = u16::from_be_bytes([avcc[pos], avcc[pos + 1]]) as usize;
            pos += 2;
            if pos + len > avcc.len() {
                return false;
            }
            sps_list.push(&avcc[pos..pos + len]);
            pos += len;
        }
        let mut pps_list = Vec::new();
        if pos < avcc.len() {
            let num_pps = avcc[pos] as usize;
            pos += 1;
            for _ in 0..num_pps {
                if pos + 2 > avcc.len() {
                    return false;
                }
                let len = u16::from_be_bytes([avcc[pos], avcc[pos + 1]]) as usize;
                pos += 2;
                if pos + len > avcc.len() {
                    return false;
                }
                pps_list.push(&avcc[pos..pos + len]);
                pos += len;
            }
        }
        if sps_list.is_empty() || pps_list.is_empty() {
            return false;
        }
        self.configure_h264_sps_pps(sps_list[0], pps_list[0])
    }

    pub fn configure_h264_sps_pps(&mut self, sps: &[u8], pps: &[u8]) -> bool {
        let parameter_sets = [sps.as_ptr(), pps.as_ptr()];
        let parameter_set_sizes = [sps.len(), pps.len()];
        let mut description: videotoolbox::ffi::CMFormatDescriptionRef = core::ptr::null();
        let status = unsafe {
            apple_cf::raw::CMVideoFormatDescriptionCreateFromH264ParameterSets(
                videotoolbox::ffi::kCFAllocatorDefault,
                2,
                parameter_sets.as_ptr(),
                parameter_set_sizes.as_ptr(),
                4,
                &mut description,
            )
        };
        if status != 0 || description.is_null() {
            tracing::warn!("VideoToolbox format description creation failed: status={status}");
            return false;
        }

        let desc = match unsafe { CMFormatDescription::from_raw(description.cast_mut().cast()) } {
            Some(d) => d,
            None => return false,
        };

        let frame_slot = Arc::clone(&self.latest_frame);
        let target_w = self.width;
        let target_h = self.height;

        let session = match DecompressionSession::new(&desc, move |frame: DecodedFrame| {
            if frame.status != 0 {
                return;
            }
            if let Some(pixel_buffer) = frame.image_buffer {
                if let Ok(guard) = pixel_buffer.lock_read_only() {
                    let w = guard.width();
                    let h = guard.height();
                    let mut xrgb = vec![0u32; target_w * target_h];
                    let copy_w = w.min(target_w);
                    let copy_h = h.min(target_h);

                    if pixel_buffer.is_planar() {
                        if let (Some(y_ptr), Some(uv_ptr)) = (
                            guard.base_address_of_plane(0),
                            guard.base_address_of_plane(1),
                        ) {
                            let y_stride = guard.bytes_per_row_of_plane(0);
                            let uv_stride = guard.bytes_per_row_of_plane(1);
                            let y_slice = unsafe {
                                std::slice::from_raw_parts(y_ptr, y_stride * h)
                            };
                            let uv_slice = unsafe {
                                std::slice::from_raw_parts(uv_ptr, uv_stride * (h / 2))
                            };
                            nv12_to_xrgb(
                                y_slice,
                                uv_slice,
                                y_stride,
                                uv_stride,
                                copy_w,
                                copy_h,
                                target_w,
                                &mut xrgb,
                            );
                            if let Ok(mut g) = frame_slot.lock() {
                                *g = Some(xrgb);
                            }
                        }
                    } else if let Some(slice) = unsafe { guard.as_slice() } {
                        let bpr = guard.bytes_per_row();
                        for y in 0..copy_h {
                            let src_row = &slice[y * bpr..y * bpr + copy_w * 4];
                            let dst_row = &mut xrgb[y * target_w..y * target_w + copy_w];
                            for (x, out_px) in dst_row.iter_mut().enumerate() {
                                let b = src_row[x * 4];
                                let g = src_row[x * 4 + 1];
                                let r = src_row[x * 4 + 2];
                                *out_px = (u32::from(r) << 16) | (u32::from(g) << 8) | u32::from(b);
                            }
                        }
                        if let Ok(mut g) = frame_slot.lock() {
                            *g = Some(xrgb);
                        }
                    }
                }
            }
        }) {
            Ok(s) => {
                let _ = s.set_real_time(true);
                s
            }
            Err(e) => {
                tracing::warn!("VideoToolbox session creation failed: {e:?}");
                return false;
            }
        };

        self.format_desc = Some(desc);
        self.session = Some(session);
        tracing::info!(
            "Hardware Apple VideoToolbox H.264 High Profile decoder ativo ({}x{})!",
            self.width,
            self.height
        );
        true
    }

    pub fn decode_frame(&mut self, mut frame_bytes: Vec<u8>) -> Option<Vec<u32>> {
        if self.format_desc.is_none() {
            if let Some((sps, pps)) = extract_sps_pps_from_annex_b(&frame_bytes) {
                self.configure_h264_sps_pps(&sps, &pps);
            }
        }

        let desc = self.format_desc.as_ref()?;
        let session = self.session.as_ref()?;

        ensure_avcc_lengths(&mut frame_bytes);

        let block = CMBlockBuffer::create(&frame_bytes)?;
        let sample_size = frame_bytes.len();
        let mut sample_buf: apple_cf::raw::CMSampleBufferRef = core::ptr::null_mut();
        let status = unsafe {
            apple_cf::raw::CMSampleBufferCreateReady(
                videotoolbox::ffi::kCFAllocatorDefault,
                block.as_ptr().cast(),
                desc.as_ptr().cast(),
                1,
                0,
                core::ptr::null(),
                1,
                &sample_size,
                &mut sample_buf,
            )
        };
        if status != 0 || sample_buf.is_null() {
            return None;
        }

        let sbuf = unsafe { CMSampleBuffer::from_raw(sample_buf.cast()) }?;
        if session.decode(&sbuf).is_ok() {
            let _ = session.wait_for_async_frames();
            if let Ok(mut g) = self.latest_frame.lock() {
                return g.take();
            }
        }
        None
    }
}

fn extract_sps_pps_from_annex_b(annex_b: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut sps = None;
    let mut pps = None;
    let mut pos = 0;
    let mut nal_starts = Vec::new();
    while pos + 4 <= annex_b.len() {
        if annex_b[pos..pos + 4] == [0, 0, 0, 1] {
            nal_starts.push((pos, 4));
            pos += 4;
        } else if pos + 3 <= annex_b.len() && annex_b[pos..pos + 3] == [0, 0, 1] {
            nal_starts.push((pos, 3));
            pos += 3;
        } else {
            pos += 1;
        }
    }
    for idx in 0..nal_starts.len() {
        let (sc_pos, sc_len) = nal_starts[idx];
        let start = sc_pos + sc_len;
        let end = if idx + 1 < nal_starts.len() {
            nal_starts[idx + 1].0
        } else {
            annex_b.len()
        };
        if start < end {
            let nalu = &annex_b[start..end];
            let nalu_type = nalu[0] & 0x1F;
            if nalu_type == 7 && sps.is_none() {
                sps = Some(nalu.to_vec());
            } else if nalu_type == 8 && pps.is_none() {
                pps = Some(nalu.to_vec());
            }
        }
    }
    match (sps, pps) {
        (Some(s), Some(p)) => Some((s, p)),
        _ => None,
    }
}

fn ensure_avcc_lengths(buf: &mut [u8]) {
    if buf.len() < 4 {
        return;
    }
    if buf.starts_with(&[0, 0, 0, 1]) || buf.starts_with(&[0, 0, 1]) {
        let mut starts = Vec::new();
        let mut pos = 0;
        while pos + 4 <= buf.len() {
            if buf[pos..pos + 4] == [0, 0, 0, 1] {
                starts.push((pos, 4));
                pos += 4;
            } else if pos + 3 <= buf.len() && buf[pos..pos + 3] == [0, 0, 1] {
                starts.push((pos, 3));
                pos += 3;
            } else {
                pos += 1;
            }
        }
        for idx in 0..starts.len() {
            let (sc_pos, sc_len) = starts[idx];
            let nalu_start = sc_pos + sc_len;
            let nalu_end = if idx + 1 < starts.len() {
                starts[idx + 1].0
            } else {
                buf.len()
            };
            let nalu_len = (nalu_end - nalu_start) as u32;
            if sc_len == 4 {
                buf[sc_pos..sc_pos + 4].copy_from_slice(&nalu_len.to_be_bytes());
            }
        }
    }
}

fn nv12_to_xrgb(
    y_plane: &[u8],
    uv_plane: &[u8],
    y_stride: usize,
    uv_stride: usize,
    width: usize,
    height: usize,
    target_width: usize,
    out_xrgb: &mut [u32],
) {
    let pairs_h = height / 2;
    let pairs_w = width / 2;

    for py in 0..pairs_h {
        let row0 = py * 2;
        let row1 = row0 + 1;
        let y0 = &y_plane[row0 * y_stride..row0 * y_stride + width];
        let y1 = &y_plane[row1 * y_stride..row1 * y_stride + width];
        let uv_row = &uv_plane[py * uv_stride..py * uv_stride + pairs_w * 2];

        for px in 0..pairs_w {
            let u = i32::from(uv_row[px * 2]) - 128;
            let v = i32::from(uv_row[px * 2 + 1]) - 128;
            let rv = 409 * v;
            let guv = -100 * u - 208 * v;
            let bu = 516 * u;

            let c0 = px * 2;
            let c1 = c0 + 1;

            #[inline(always)]
            fn pack(y_val: u8, rv: i32, guv: i32, bu: i32) -> u32 {
                let c = (i32::from(y_val) - 16).max(0) * 298 + 128;
                let r = ((c + rv) >> 8).clamp(0, 255) as u32;
                let g = ((c + guv) >> 8).clamp(0, 255) as u32;
                let b = ((c + bu) >> 8).clamp(0, 255) as u32;
                (r << 16) | (g << 8) | b
            }

            out_xrgb[row0 * target_width + c0] = pack(y0[c0], rv, guv, bu);
            out_xrgb[row0 * target_width + c1] = pack(y0[c1], rv, guv, bu);
            out_xrgb[row1 * target_width + c0] = pack(y1[c0], rv, guv, bu);
            out_xrgb[row1 * target_width + c1] = pack(y1[c1], rv, guv, bu);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openh264::encoder::Encoder;
    use openh264::formats::YUVBuffer;

    #[test]
    fn test_vt_decoder_with_openh264_stream() {
        let mut enc = Encoder::new().unwrap();
        let mut vt = VtDecoder::new(64, 64);

        for i in 0..5 {
            let yuv = YUVBuffer::from_vec(vec![(i * 30) as u8; 64 * 64 * 3 / 2], 64, 64);
            let bitstream = enc.encode(&yuv).unwrap();
            let annex_b = bitstream.to_vec();

            let out = vt.decode_frame(annex_b);
            eprintln!("frame {i}: is_some={}", out.is_some());
            assert!(out.is_some(), "VideoToolbox should have decoded frame {i}!");
        }
    }

    #[test]
    fn test_vt_decoder_configure_avcc() {
        let mut enc = Encoder::new().unwrap();
        let yuv = YUVBuffer::from_vec(vec![128; 64 * 64 * 3 / 2], 64, 64);
        let bitstream = enc.encode(&yuv).unwrap();
        let annex_b = bitstream.to_vec();
        let (sps, pps) = extract_sps_pps_from_annex_b(&annex_b).expect("should extract sps and pps");

        // Construct valid AVCC record
        let mut avcc = vec![
            1, // version
            sps[1], sps[2], sps[3], // profile, compat, level
            0xFF, // 6 bits reserved + 2 bits NALU size length - 1 (3 -> 4 bytes)
            0xE1, // 3 bits reserved + 5 bits num SPS (1)
        ];
        avcc.extend_from_slice(&(sps.len() as u16).to_be_bytes());
        avcc.extend_from_slice(&sps);
        avcc.push(1); // num PPS
        avcc.extend_from_slice(&(pps.len() as u16).to_be_bytes());
        avcc.extend_from_slice(&pps);

        let mut vt = VtDecoder::new(64, 64);
        assert!(vt.configure_avcc(&avcc), "configure_avcc should succeed");
        assert!(vt.format_desc.is_some());
    }


}

