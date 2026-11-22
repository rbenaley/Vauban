//! H.264 video encoder for RDP display streaming.
//!
//! Wraps OpenH264 to encode RGBA framebuffer data into H.264 NAL units.
//! Designed for adaptive framerate: the caller controls when frames are
//! encoded (typically via a dirty flag + timer).

use crate::error::{SessionError, SessionResult};
use openh264::Timestamp;
use openh264::encoder::{
    BitRate, Encoder, EncoderConfig, FrameRate, FrameType, RateControlMode, UsageType,
};
use openh264::formats::{RgbaSliceU8, YUVBuffer};
use std::time::Instant;
use tracing::debug;

/// Encoded H.264 frame ready for IPC transmission.
pub struct VideoFrame {
    /// Monotonic timestamp in microseconds from session start.
    pub timestamp_us: u64,
    /// true = I-frame (keyframe), false = P-frame (delta).
    pub is_keyframe: bool,
    /// Frame width in pixels.
    pub width: u16,
    /// Frame height in pixels.
    pub height: u16,
    /// H.264 NAL unit(s) for this frame.
    pub data: Vec<u8>,
    /// Auxiliary chroma frame, present only when the encoder was built
    /// with [`VideoEncoder::with_aux`].
    pub aux: Option<AuxFrame>,
}

/// Auxiliary H.264 frame of an AVC444 pair.
///
/// It belongs to a second, independent H.264 stream whose pictures carry
/// the chroma samples that 4:2:0 subsampling dropped from the main frame
/// (see [`build_aux_yuv`]).
pub struct AuxFrame {
    /// true = keyframe of the auxiliary stream.
    pub is_keyframe: bool,
    /// H.264 NAL unit(s) for this frame.
    pub data: Vec<u8>,
}

/// Share of the main bitrate given to the auxiliary chroma stream.
const AUX_BITRATE_DIVISOR: u32 = 2;

/// BT.601 limited-range U of one RGBA pixel, same integer formula as the
/// `openh264` crate uses for the main stream.
#[inline(always)]
fn chroma_u(px: &[u8]) -> u8 {
    let (r, g, b) = (i32::from(px[0]), i32::from(px[1]), i32::from(px[2]));
    (((-38 * r - 74 * g + 112 * b) >> 8) + 128) as u8
}

/// BT.601 limited-range V of one RGBA pixel.
#[inline(always)]
fn chroma_v(px: &[u8]) -> u8 {
    let (r, g, b) = (i32::from(px[0]), i32::from(px[1]), i32::from(px[2]));
    (((112 * r - 94 * g - 18 * b) >> 8) + 128) as u8
}

/// Build the auxiliary 4:2:0 picture of an AVC444 pair.
///
/// The main picture keeps one chroma sample per 2x2 block (the average).
/// The auxiliary picture carries three of the four full-resolution chroma
/// samples of each block; the viewer derives the fourth from the average.
///
/// Layout, for a `w` x `h` frame (both even), with `U(x, y)` and `V(x, y)`
/// the full-resolution chroma of pixel `(x, y)`:
///
/// - Y plane (`w` x `h`): rows `0..h/2` hold `U(x, 2j+1)`, rows `h/2..h`
///   hold `V(x, 2j+1)` (the odd rows of U, then the odd rows of V);
/// - U plane (`w/2` x `h/2`): `U(2i+1, 2j)`;
/// - V plane (`w/2` x `h/2`): `V(2i+1, 2j)`.
///
/// `rgba` must hold at least `w * h * 4` bytes.
pub fn build_aux_yuv(rgba: &[u8], w: usize, h: usize) -> Vec<u8> {
    let (hw, hh) = (w / 2, h / 2);
    let mut out = vec![0u8; w * h + 2 * hw * hh];
    let (y_plane, uv) = out.split_at_mut(w * h);
    let (u_plane, v_plane) = uv.split_at_mut(hw * hh);
    let (y_top, y_bottom) = y_plane.split_at_mut(w * hh);

    for j in 0..hh {
        let even = &rgba[(2 * j) * w * 4..(2 * j + 1) * w * 4];
        let odd = &rgba[(2 * j + 1) * w * 4..(2 * j + 2) * w * 4];

        let dst_u = &mut y_top[j * w..(j + 1) * w];
        let dst_v = &mut y_bottom[j * w..(j + 1) * w];
        for ((px, du), dv) in odd.as_chunks::<4>().0.iter().zip(dst_u).zip(dst_v) {
            *du = chroma_u(px);
            *dv = chroma_v(px);
        }

        let dst_u = &mut u_plane[j * hw..(j + 1) * hw];
        let dst_v = &mut v_plane[j * hw..(j + 1) * hw];
        for ((pair, du), dv) in even.as_chunks::<8>().0.iter().zip(dst_u).zip(dst_v) {
            let px = &pair[4..8];
            *du = chroma_u(px);
            *dv = chroma_v(px);
        }
    }
    out
}

/// H.264 encoder wrapping OpenH264 for RDP framebuffer encoding.
pub struct VideoEncoder {
    encoder: Encoder,
    width: u16,
    height: u16,
    frame_count: u64,
    session_start: Instant,
    max_bitrate_bps: u32,
    /// Second encoder, for the auxiliary chroma stream.
    aux_encoder: Option<Encoder>,
}

const DEFAULT_MAX_BITRATE_BPS: u32 = 5_000_000;

fn build_config(max_bitrate_bps: u32) -> EncoderConfig {
    EncoderConfig::new()
        .max_frame_rate(FrameRate::from_hz(60.0))
        .bitrate(BitRate::from_bps(max_bitrate_bps))
        .skip_frames(false)
        .rate_control_mode(RateControlMode::Quality)
        .usage_type(UsageType::ScreenContentRealTime)
        .adaptive_quantization(false)
        .background_detection(false)
}

impl VideoEncoder {
    /// Create a new H.264 encoder for the given dimensions.
    pub fn new(width: u16, height: u16, max_bitrate_bps: u32) -> SessionResult<Self> {
        let config = build_config(max_bitrate_bps);
        let encoder = Encoder::with_api_config(openh264::OpenH264API::from_source(), config)
            .map_err(|e| {
                SessionError::SessionFailed(format!("Failed to create H.264 encoder: {e}"))
            })?;

        debug!(width, height, max_bitrate_bps, "H.264 encoder initialized");

        Ok(Self {
            encoder,
            width,
            height,
            frame_count: 0,
            session_start: Instant::now(),
            max_bitrate_bps,
            aux_encoder: None,
        })
    }

    fn new_aux_encoder(max_bitrate_bps: u32) -> SessionResult<Encoder> {
        let config = build_config(max_bitrate_bps / AUX_BITRATE_DIVISOR);
        Encoder::with_api_config(openh264::OpenH264API::from_source(), config).map_err(|e| {
            SessionError::SessionFailed(format!("Failed to create auxiliary H.264 encoder: {e}"))
        })
    }

    /// Add the auxiliary chroma stream: every encoded frame then carries
    /// an [`AuxFrame`].
    pub fn with_aux(mut self) -> SessionResult<Self> {
        self.aux_encoder = Some(Self::new_aux_encoder(self.max_bitrate_bps)?);
        Ok(self)
    }

    /// Create with default bitrate (5 Mbps).
    pub fn with_defaults(width: u16, height: u16) -> SessionResult<Self> {
        Self::new(width, height, DEFAULT_MAX_BITRATE_BPS)
    }

    /// Encode the RGBA framebuffer into an H.264 frame.
    ///
    /// The framebuffer must be `width * height * 4` bytes (RGBA32).
    /// OpenH264 handles dimension changes dynamically via `encode()`.
    pub fn encode_frame(&mut self, rgba_data: &[u8]) -> SessionResult<VideoFrame> {
        let w = usize::from(self.width);
        let h = usize::from(self.height);
        let expected_len = w * h * 4;

        if rgba_data.len() < expected_len {
            return Err(SessionError::SessionFailed(format!(
                "RGBA buffer too small: {} < {}",
                rgba_data.len(),
                expected_len
            )));
        }

        let rgba_source = RgbaSliceU8::new(&rgba_data[..expected_len], (w, h));
        // Contiguous RGBA8 path: row-ordered and SIMD-accelerated. The generic
        // `from_rgb_source` converts pixel by pixel in floating point and
        // costs more than the H.264 encoding itself.
        let yuv = YUVBuffer::from_rgba8_source(rgba_source);

        let elapsed = self.session_start.elapsed();
        let timestamp_us = elapsed.as_micros() as u64;
        let timestamp = Timestamp::from_millis(elapsed.as_millis() as u64);

        let bitstream = self
            .encoder
            .encode_at(&yuv, timestamp)
            .map_err(|e| SessionError::SessionFailed(format!("H.264 encode failed: {e}")))?;

        let is_keyframe = matches!(
            bitstream.frame_type(),
            FrameType::IDR | FrameType::I | FrameType::IPMixed
        );
        let data = bitstream.to_vec();

        let aux = match self.aux_encoder.as_mut() {
            Some(aux_encoder) => {
                let aux_yuv = YUVBuffer::from_vec(build_aux_yuv(rgba_data, w, h), w, h);
                let aux_bitstream = aux_encoder.encode_at(&aux_yuv, timestamp).map_err(|e| {
                    SessionError::SessionFailed(format!("Auxiliary H.264 encode failed: {e}"))
                })?;
                Some(AuxFrame {
                    is_keyframe: matches!(
                        aux_bitstream.frame_type(),
                        FrameType::IDR | FrameType::I | FrameType::IPMixed
                    ),
                    data: aux_bitstream.to_vec(),
                })
            }
            None => None,
        };

        self.frame_count += 1;

        Ok(VideoFrame {
            timestamp_us,
            is_keyframe,
            width: self.width,
            height: self.height,
            data,
            aux,
        })
    }

    /// Force the next encoded frame to be a keyframe (I-frame).
    pub fn force_keyframe(&mut self) {
        self.encoder.force_intra_frame();
        if let Some(aux_encoder) = self.aux_encoder.as_mut() {
            aux_encoder.force_intra_frame();
        }
    }

    /// Recreate the encoder for new dimensions.
    /// OpenH264 can handle dimension changes via `encode()` automatically,
    /// but this ensures a clean state and correct bitrate allocation.
    pub fn reconfigure(&mut self, width: u16, height: u16) -> SessionResult<()> {
        let config = build_config(self.max_bitrate_bps);
        self.encoder = Encoder::with_api_config(openh264::OpenH264API::from_source(), config)
            .map_err(|e| {
                SessionError::SessionFailed(format!("Failed to reconfigure H.264 encoder: {e}"))
            })?;
        if self.aux_encoder.is_some() {
            self.aux_encoder = Some(Self::new_aux_encoder(self.max_bitrate_bps)?);
        }
        self.width = width;
        self.height = height;
        debug!(width, height, "H.264 encoder reconfigured");
        Ok(())
    }

    /// Number of frames encoded so far.
    #[allow(dead_code)]
    pub fn frame_count(&self) -> u64 {
        self.frame_count
    }

    /// Current encoder dimensions.
    #[allow(dead_code)]
    pub fn dimensions(&self) -> (u16, u16) {
        (self.width, self.height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn black_rgba(width: u16, height: u16) -> Vec<u8> {
        vec![0u8; usize::from(width) * usize::from(height) * 4]
    }

    fn gradient_rgba(width: u16, height: u16) -> Vec<u8> {
        let w = usize::from(width);
        let h = usize::from(height);
        let mut buf = vec![0u8; w * h * 4];
        for y in 0..h {
            for x in 0..w {
                let idx = (y * w + x) * 4;
                buf[idx] = (x % 256) as u8;
                buf[idx + 1] = (y % 256) as u8;
                buf[idx + 2] = ((x + y) % 256) as u8;
                buf[idx + 3] = 255;
            }
        }
        buf
    }

    #[test]
    fn test_encoder_creation() {
        let enc = VideoEncoder::with_defaults(640, 480);
        assert!(enc.is_ok());
        let enc = enc.unwrap_or_else(|e| panic!("encoder creation failed: {e}"));
        assert_eq!(enc.dimensions(), (640, 480));
        assert_eq!(enc.frame_count(), 0);
    }

    #[test]
    fn test_encode_black_frame() {
        let mut enc = VideoEncoder::with_defaults(320, 240).unwrap_or_else(|e| panic!("{e}"));
        let rgba = black_rgba(320, 240);
        let frame = enc.encode_frame(&rgba).unwrap_or_else(|e| panic!("{e}"));

        assert!(!frame.data.is_empty(), "encoded frame must not be empty");
        assert_eq!(frame.width, 320);
        assert_eq!(frame.height, 240);
        assert_eq!(enc.frame_count(), 1);
    }

    #[test]
    fn test_first_frame_is_keyframe() {
        let mut enc = VideoEncoder::with_defaults(320, 240).unwrap_or_else(|e| panic!("{e}"));
        let rgba = gradient_rgba(320, 240);
        let frame = enc.encode_frame(&rgba).unwrap_or_else(|e| panic!("{e}"));

        assert!(frame.is_keyframe, "first frame must be a keyframe");
    }

    #[test]
    fn test_subsequent_frames_are_delta() {
        let mut enc = VideoEncoder::with_defaults(320, 240).unwrap_or_else(|e| panic!("{e}"));
        let rgba = gradient_rgba(320, 240);

        let first = enc.encode_frame(&rgba).unwrap_or_else(|e| panic!("{e}"));
        let second = enc.encode_frame(&rgba).unwrap_or_else(|e| panic!("{e}"));

        assert!(
            !second.is_keyframe,
            "second identical frame should be a P-frame"
        );
        assert!(
            second.data.len() < first.data.len(),
            "P-frame of identical content should be smaller than I-frame ({} >= {})",
            second.data.len(),
            first.data.len()
        );
    }

    #[test]
    fn test_force_keyframe() {
        let mut enc = VideoEncoder::with_defaults(320, 240).unwrap_or_else(|e| panic!("{e}"));
        let rgba = gradient_rgba(320, 240);

        let _first = enc.encode_frame(&rgba).unwrap_or_else(|e| panic!("{e}"));

        enc.force_keyframe();
        let forced = enc.encode_frame(&rgba).unwrap_or_else(|e| panic!("{e}"));

        assert!(forced.is_keyframe, "forced keyframe must be an I-frame");
    }

    #[test]
    fn test_reconfigure_dimensions() {
        let mut enc = VideoEncoder::with_defaults(640, 480).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(enc.dimensions(), (640, 480));

        enc.reconfigure(1280, 720).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(enc.dimensions(), (1280, 720));

        let rgba = black_rgba(1280, 720);
        let frame = enc.encode_frame(&rgba).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(frame.width, 1280);
        assert_eq!(frame.height, 720);
    }

    #[test]
    fn test_buffer_too_small() {
        let mut enc = VideoEncoder::with_defaults(320, 240).unwrap_or_else(|e| panic!("{e}"));
        let small_buf = vec![0u8; 100];
        let result = enc.encode_frame(&small_buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_timestamps_increase() {
        let mut enc = VideoEncoder::with_defaults(320, 240).unwrap_or_else(|e| panic!("{e}"));
        let rgba = black_rgba(320, 240);

        let f1 = enc.encode_frame(&rgba).unwrap_or_else(|e| panic!("{e}"));
        std::thread::sleep(std::time::Duration::from_millis(5));
        let f2 = enc.encode_frame(&rgba).unwrap_or_else(|e| panic!("{e}"));

        assert!(
            f2.timestamp_us > f1.timestamp_us,
            "timestamps must be monotonically increasing"
        );
    }

    #[test]
    fn test_frame_count_increments() {
        let mut enc = VideoEncoder::with_defaults(320, 240).unwrap_or_else(|e| panic!("{e}"));
        let rgba = black_rgba(320, 240);

        for i in 0..5 {
            assert_eq!(enc.frame_count(), i);
            let _f = enc.encode_frame(&rgba).unwrap_or_else(|e| panic!("{e}"));
        }
        assert_eq!(enc.frame_count(), 5);
    }

    #[test]
    fn test_custom_bitrate() {
        let enc = VideoEncoder::new(640, 480, 2_000_000);
        assert!(enc.is_ok());
    }

    // ==================== AVC444 auxiliary stream ====================

    /// Full-resolution chroma of pixel `(x, y)`.
    fn true_uv(rgba: &[u8], w: usize, x: usize, y: usize) -> (u8, u8) {
        let px = &rgba[(y * w + x) * 4..(y * w + x) * 4 + 4];
        (chroma_u(px), chroma_v(px))
    }

    /// Colored 1-pixel detail: the content 4:2:0 subsampling blurs.
    fn colored_detail_rgba(width: u16, height: u16) -> Vec<u8> {
        let w = usize::from(width);
        let h = usize::from(height);
        let mut buf = vec![0u8; w * h * 4];
        for y in 0..h {
            for x in 0..w {
                let idx = (y * w + x) * 4;
                let (r, g, b) = match (x + 2 * y) % 5 {
                    0 => (255, 0, 0),
                    1 => (0, 0, 255),
                    2 => (0, 0, 0),
                    3 => (0, 255, 0),
                    _ => (255, 255, 255),
                };
                buf[idx] = r;
                buf[idx + 1] = g;
                buf[idx + 2] = b;
                buf[idx + 3] = 255;
            }
        }
        buf
    }

    #[test]
    fn test_aux_yuv_layout() {
        let (w, h) = (8usize, 6usize);
        let rgba = colored_detail_rgba(8, 6);
        let aux = build_aux_yuv(&rgba, w, h);
        assert_eq!(aux.len(), w * h * 3 / 2);

        let (hw, hh) = (w / 2, h / 2);
        let (y_plane, uv) = aux.split_at(w * h);
        let (u_plane, v_plane) = uv.split_at(hw * hh);
        for j in 0..hh {
            for x in 0..w {
                let (u, v) = true_uv(&rgba, w, x, 2 * j + 1);
                assert_eq!(y_plane[j * w + x], u, "U of odd row {j} at x={x}");
                assert_eq!(y_plane[(hh + j) * w + x], v, "V of odd row {j} at x={x}");
            }
            for i in 0..hw {
                let (u, v) = true_uv(&rgba, w, 2 * i + 1, 2 * j);
                assert_eq!(u_plane[j * hw + i], u, "U of odd column {i}, even row {j}");
                assert_eq!(v_plane[j * hw + i], v, "V of odd column {i}, even row {j}");
            }
        }
    }

    /// Without compression, the three samples the auxiliary picture
    /// carries are exact, and the fourth is recovered from the block
    /// average. Mirrors the viewer shader (threshold 30).
    #[test]
    fn test_aux_yuv_recovers_full_chroma() {
        let (w, h) = (16usize, 12usize);
        let rgba = colored_detail_rgba(16, 12);
        let aux = build_aux_yuv(&rgba, w, h);
        let main = YUVBuffer::from_rgba8_source(RgbaSliceU8::new(&rgba, (w, h)));
        use openh264::formats::YUVSource;
        let (main_u, main_v) = (main.u(), main.v());

        let (hw, hh) = (w / 2, h / 2);
        let (y_plane, uv) = aux.split_at(w * h);
        let (u_plane, v_plane) = uv.split_at(hw * hh);
        let fourth = |avg: u8, a: u8, b: u8, c: u8| -> u8 {
            let calc =
                (4 * i32::from(avg) - i32::from(a) - i32::from(b) - i32::from(c)).clamp(0, 255);
            if (calc - i32::from(avg)).abs() >= 30 {
                calc as u8
            } else {
                avg
            }
        };
        let mut worst = 0i32;
        for j in 0..hh {
            for i in 0..hw {
                let (x, y) = (2 * i, 2 * j);
                let got_u = fourth(
                    main_u[j * hw + i],
                    u_plane[j * hw + i],
                    y_plane[j * w + x],
                    y_plane[j * w + x + 1],
                );
                let got_v = fourth(
                    main_v[j * hw + i],
                    v_plane[j * hw + i],
                    y_plane[(hh + j) * w + x],
                    y_plane[(hh + j) * w + x + 1],
                );
                let (u, v) = true_uv(&rgba, w, x, y);
                worst = worst
                    .max((i32::from(got_u) - i32::from(u)).abs())
                    .max((i32::from(got_v) - i32::from(v)).abs());
            }
        }
        // Below the threshold the average stands in for the sample; above
        // it only the rounding of the average (x4) remains.
        assert!(worst < 30, "fourth chroma sample off by {worst}");
    }

    #[test]
    fn test_no_aux_frame_by_default() {
        let mut enc = VideoEncoder::with_defaults(320, 240).unwrap_or_else(|e| panic!("{e}"));
        let frame = enc
            .encode_frame(&gradient_rgba(320, 240))
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(
            frame.aux.is_none(),
            "avc420 must not produce an auxiliary frame"
        );
    }

    #[test]
    fn test_aux_stream_is_an_independent_h264_stream() {
        let mut enc = VideoEncoder::with_defaults(320, 240)
            .and_then(VideoEncoder::with_aux)
            .unwrap_or_else(|e| panic!("{e}"));
        let rgba = colored_detail_rgba(320, 240);

        let first = enc.encode_frame(&rgba).unwrap_or_else(|e| panic!("{e}"));
        let first_aux = first
            .aux
            .unwrap_or_else(|| panic!("auxiliary frame expected"));
        assert!(first.is_keyframe);
        assert!(
            first_aux.is_keyframe,
            "first auxiliary frame must be a keyframe"
        );
        assert!(
            first_aux.data.starts_with(&[0, 0, 0, 1]) || first_aux.data.starts_with(&[0, 0, 1]),
            "auxiliary data must begin with a NAL start code"
        );

        let second = enc.encode_frame(&rgba).unwrap_or_else(|e| panic!("{e}"));
        let second_aux = second
            .aux
            .unwrap_or_else(|| panic!("auxiliary frame expected"));
        assert!(!second_aux.is_keyframe);
        assert!(second_aux.data.len() < first_aux.data.len());

        enc.force_keyframe();
        let forced = enc.encode_frame(&rgba).unwrap_or_else(|e| panic!("{e}"));
        assert!(forced.is_keyframe);
        assert!(
            forced.aux.is_some_and(|a| a.is_keyframe),
            "a forced keyframe must restart both streams"
        );
    }

    #[test]
    fn test_aux_survives_reconfigure() {
        let mut enc = VideoEncoder::with_defaults(320, 240)
            .and_then(VideoEncoder::with_aux)
            .unwrap_or_else(|e| panic!("{e}"));
        enc.reconfigure(640, 480).unwrap_or_else(|e| panic!("{e}"));
        let frame = enc
            .encode_frame(&colored_detail_rgba(640, 480))
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(frame.aux.is_some_and(|a| a.is_keyframe));
    }

    /// The main stream of an AVC444 session is the AVC420 stream, byte for
    /// byte: recordings and browsers without AVC444 are unaffected.
    #[test]
    fn test_main_stream_identical_with_and_without_aux() {
        let rgba = colored_detail_rgba(320, 240);
        let mut plain = VideoEncoder::with_defaults(320, 240).unwrap_or_else(|e| panic!("{e}"));
        let mut paired = VideoEncoder::with_defaults(320, 240)
            .and_then(VideoEncoder::with_aux)
            .unwrap_or_else(|e| panic!("{e}"));
        for _ in 0..3 {
            let a = plain.encode_frame(&rgba).unwrap_or_else(|e| panic!("{e}"));
            let b = paired.encode_frame(&rgba).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(a.data, b.data);
        }
    }

    /// Writes the fixture the browser harness reads. Not a check: run it
    /// by hand with `AVC444_FIXTURE_DIR` set.
    #[test]
    #[ignore = "writes fixture files for the browser harness"]
    fn dump_avc444_fixture() {
        let Ok(dir) = std::env::var("AVC444_FIXTURE_DIR") else {
            return;
        };
        let (w, h) = (640u16, 360u16);
        let rgba = fixture_rgba(w, h);
        let mut enc = VideoEncoder::with_defaults(w, h)
            .and_then(VideoEncoder::with_aux)
            .unwrap_or_else(|e| panic!("{e}"));
        let mut main_stream = Vec::new();
        let mut aux_stream = Vec::new();
        let mut index = String::new();
        for _ in 0..30 {
            let f = enc.encode_frame(&rgba).unwrap_or_else(|e| panic!("{e}"));
            let a = f.aux.unwrap_or_else(|| panic!("auxiliary frame expected"));
            index.push_str(&format!(
                "{} {} {} {}\n",
                u8::from(f.is_keyframe),
                f.data.len(),
                u8::from(a.is_keyframe),
                a.data.len()
            ));
            main_stream.extend_from_slice(&f.data);
            aux_stream.extend_from_slice(&a.data);
        }
        let write = |name: &str, data: &[u8]| {
            std::fs::write(format!("{dir}/{name}"), data).unwrap_or_else(|e| panic!("{e}"));
        };
        write("source.rgba", &rgba);
        write("main.h264", &main_stream);
        write("aux.h264", &aux_stream);
        write("index.txt", index.as_bytes());
    }

    /// Desktop-like picture: colored text-like strokes on dark and light
    /// backgrounds, 1-pixel colored lines, and a smooth gradient.
    fn fixture_rgba(width: u16, height: u16) -> Vec<u8> {
        let w = usize::from(width);
        let h = usize::from(height);
        let mut buf = vec![0u8; w * h * 4];
        let palette: [(u8, u8, u8); 6] = [
            (255, 64, 64),
            (64, 160, 255),
            (64, 220, 96),
            (255, 200, 0),
            (220, 80, 255),
            (255, 255, 255),
        ];
        for y in 0..h {
            for x in 0..w {
                let band = y * 4 / h;
                let (r, g, b) = match band {
                    // Text-like strokes on a dark background.
                    0 | 1 => {
                        let bg = if band == 0 {
                            (16, 16, 24)
                        } else {
                            (245, 245, 245)
                        };
                        let glyph = (x / 7 + y / 11) % palette.len();
                        let stroke = (x * 3 + y * 5) % 7 < 2 && (y % 11) > 1 && (x % 7) > 0;
                        if stroke { palette[glyph] } else { bg }
                    }
                    // 1-pixel vertical colored lines.
                    2 => match x % 4 {
                        0 => (255, 0, 0),
                        1 => (0, 0, 0),
                        2 => (0, 0, 255),
                        _ => (0, 0, 0),
                    },
                    // Smooth gradient.
                    _ => ((x * 255 / w) as u8, (y * 255 / h) as u8, 128),
                };
                let idx = (y * w + x) * 4;
                buf[idx] = r;
                buf[idx + 1] = g;
                buf[idx + 2] = b;
                buf[idx + 3] = 255;
            }
        }
        buf
    }

    #[test]
    fn test_h264_nal_start_code() {
        let mut enc = VideoEncoder::with_defaults(320, 240).unwrap_or_else(|e| panic!("{e}"));
        let rgba = gradient_rgba(320, 240);
        let frame = enc.encode_frame(&rgba).unwrap_or_else(|e| panic!("{e}"));

        assert!(
            frame.data.len() >= 4,
            "H.264 data must contain at least one NAL unit"
        );
        let has_start_code =
            frame.data.starts_with(&[0, 0, 0, 1]) || frame.data.starts_with(&[0, 0, 1]);
        assert!(
            has_start_code,
            "H.264 data must begin with a NAL start code"
        );
    }
}
