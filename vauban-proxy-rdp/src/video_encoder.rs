//! H.264 video encoder for RDP display streaming.
//!
//! Wraps OpenH264 to encode RGBA framebuffer data into H.264 NAL units.
//! Designed for adaptive framerate: the caller controls when frames are
//! encoded (typically via a dirty flag + timer).

use crate::error::{SessionError, SessionResult};
use openh264::encoder::{
    BitRate, Encoder, EncoderConfig, FrameRate, FrameType, RateControlMode, UsageType,
};
use openh264::formats::{RgbaSliceU8, YUVBuffer};
use openh264::Timestamp;
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
}

/// H.264 encoder wrapping OpenH264 for RDP framebuffer encoding.
pub struct VideoEncoder {
    encoder: Encoder,
    width: u16,
    height: u16,
    frame_count: u64,
    session_start: Instant,
    max_bitrate_bps: u32,
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
        })
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
        let yuv = YUVBuffer::from_rgb_source(rgba_source);

        let elapsed = self.session_start.elapsed();
        let timestamp_us = elapsed.as_micros() as u64;
        let timestamp = Timestamp::from_millis(elapsed.as_millis() as u64);

        let bitstream = self.encoder.encode_at(&yuv, timestamp).map_err(|e| {
            SessionError::SessionFailed(format!("H.264 encode failed: {e}"))
        })?;

        let is_keyframe = matches!(
            bitstream.frame_type(),
            FrameType::IDR | FrameType::I | FrameType::IPMixed
        );
        let data = bitstream.to_vec();

        self.frame_count += 1;

        Ok(VideoFrame {
            timestamp_us,
            is_keyframe,
            width: self.width,
            height: self.height,
            data,
        })
    }

    /// Force the next encoded frame to be a keyframe (I-frame).
    pub fn force_keyframe(&mut self) {
        self.encoder.force_intra_frame();
    }

    /// Recreate the encoder for new dimensions.
    /// OpenH264 can handle dimension changes via `encode()` automatically,
    /// but this ensures a clean state and correct bitrate allocation.
    pub fn reconfigure(&mut self, width: u16, height: u16) -> SessionResult<()> {
        let config = build_config(self.max_bitrate_bps);
        self.encoder =
            Encoder::with_api_config(openh264::OpenH264API::from_source(), config).map_err(
                |e| SessionError::SessionFailed(format!("Failed to reconfigure H.264 encoder: {e}")),
            )?;
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
        let mut enc = VideoEncoder::with_defaults(320, 240)
            .unwrap_or_else(|e| panic!("{e}"));
        let rgba = black_rgba(320, 240);
        let frame = enc.encode_frame(&rgba)
            .unwrap_or_else(|e| panic!("{e}"));

        assert!(!frame.data.is_empty(), "encoded frame must not be empty");
        assert_eq!(frame.width, 320);
        assert_eq!(frame.height, 240);
        assert_eq!(enc.frame_count(), 1);
    }

    #[test]
    fn test_first_frame_is_keyframe() {
        let mut enc = VideoEncoder::with_defaults(320, 240)
            .unwrap_or_else(|e| panic!("{e}"));
        let rgba = gradient_rgba(320, 240);
        let frame = enc.encode_frame(&rgba)
            .unwrap_or_else(|e| panic!("{e}"));

        assert!(frame.is_keyframe, "first frame must be a keyframe");
    }

    #[test]
    fn test_subsequent_frames_are_delta() {
        let mut enc = VideoEncoder::with_defaults(320, 240)
            .unwrap_or_else(|e| panic!("{e}"));
        let rgba = gradient_rgba(320, 240);

        let first = enc.encode_frame(&rgba)
            .unwrap_or_else(|e| panic!("{e}"));
        let second = enc.encode_frame(&rgba)
            .unwrap_or_else(|e| panic!("{e}"));

        assert!(!second.is_keyframe, "second identical frame should be a P-frame");
        assert!(
            second.data.len() < first.data.len(),
            "P-frame of identical content should be smaller than I-frame ({} >= {})",
            second.data.len(),
            first.data.len()
        );
    }

    #[test]
    fn test_force_keyframe() {
        let mut enc = VideoEncoder::with_defaults(320, 240)
            .unwrap_or_else(|e| panic!("{e}"));
        let rgba = gradient_rgba(320, 240);

        let _first = enc.encode_frame(&rgba)
            .unwrap_or_else(|e| panic!("{e}"));

        enc.force_keyframe();
        let forced = enc.encode_frame(&rgba)
            .unwrap_or_else(|e| panic!("{e}"));

        assert!(forced.is_keyframe, "forced keyframe must be an I-frame");
    }

    #[test]
    fn test_reconfigure_dimensions() {
        let mut enc = VideoEncoder::with_defaults(640, 480)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(enc.dimensions(), (640, 480));

        enc.reconfigure(1280, 720)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(enc.dimensions(), (1280, 720));

        let rgba = black_rgba(1280, 720);
        let frame = enc.encode_frame(&rgba)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(frame.width, 1280);
        assert_eq!(frame.height, 720);
    }

    #[test]
    fn test_buffer_too_small() {
        let mut enc = VideoEncoder::with_defaults(320, 240)
            .unwrap_or_else(|e| panic!("{e}"));
        let small_buf = vec![0u8; 100];
        let result = enc.encode_frame(&small_buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_timestamps_increase() {
        let mut enc = VideoEncoder::with_defaults(320, 240)
            .unwrap_or_else(|e| panic!("{e}"));
        let rgba = black_rgba(320, 240);

        let f1 = enc.encode_frame(&rgba)
            .unwrap_or_else(|e| panic!("{e}"));
        std::thread::sleep(std::time::Duration::from_millis(5));
        let f2 = enc.encode_frame(&rgba)
            .unwrap_or_else(|e| panic!("{e}"));

        assert!(
            f2.timestamp_us > f1.timestamp_us,
            "timestamps must be monotonically increasing"
        );
    }

    #[test]
    fn test_frame_count_increments() {
        let mut enc = VideoEncoder::with_defaults(320, 240)
            .unwrap_or_else(|e| panic!("{e}"));
        let rgba = black_rgba(320, 240);

        for i in 0..5 {
            assert_eq!(enc.frame_count(), i);
            let _f = enc.encode_frame(&rgba)
                .unwrap_or_else(|e| panic!("{e}"));
        }
        assert_eq!(enc.frame_count(), 5);
    }

    #[test]
    fn test_custom_bitrate() {
        let enc = VideoEncoder::new(640, 480, 2_000_000);
        assert!(enc.is_ok());
    }

    #[test]
    fn test_h264_nal_start_code() {
        let mut enc = VideoEncoder::with_defaults(320, 240)
            .unwrap_or_else(|e| panic!("{e}"));
        let rgba = gradient_rgba(320, 240);
        let frame = enc.encode_frame(&rgba)
            .unwrap_or_else(|e| panic!("{e}"));

        assert!(
            frame.data.len() >= 4,
            "H.264 data must contain at least one NAL unit"
        );
        let has_start_code = frame.data.starts_with(&[0, 0, 0, 1])
            || frame.data.starts_with(&[0, 0, 1]);
        assert!(has_start_code, "H.264 data must begin with a NAL start code");
    }
}
