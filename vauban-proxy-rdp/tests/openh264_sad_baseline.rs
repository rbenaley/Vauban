//! Baseline test for OpenH264 encoder correctness.
//!
//! Validates that the encoder produces valid H.264 output with various
//! frame patterns that exercise SAD (Sum of Absolute Differences) functions
//! during inter-frame prediction / motion estimation.
//!
//! Run BEFORE and AFTER AVX2 SAD modifications to ensure no regression.

use openh264::encoder::Encoder;
use openh264::formats::YUVBuffer;

fn create_gradient_yuv(width: usize, height: usize, frame_offset: u8) -> YUVBuffer {
    let y_size = width * height;
    let uv_size = (width / 2) * (height / 2);
    let total = y_size + 2 * uv_size;
    let mut yuv = vec![0u8; total];

    for row in 0..height {
        for col in 0..width {
            yuv[row * width + col] =
                ((col.wrapping_add(row).wrapping_add(frame_offset as usize)) % 256) as u8;
        }
    }
    for i in 0..uv_size {
        yuv[y_size + i] = ((i * 2 + frame_offset as usize) % 256) as u8;
        yuv[y_size + uv_size + i] = ((i * 3 + frame_offset as usize) % 256) as u8;
    }

    YUVBuffer::from_vec(yuv, width, height)
}

#[test]
fn test_encoder_produces_valid_h264_single_frame() {
    let width = 320;
    let height = 240;
    let mut encoder = Encoder::new().unwrap_or_else(|e| panic!("Failed to create encoder: {e:?}"));

    let yuv = create_gradient_yuv(width, height, 0);
    let bitstream = encoder
        .encode(&yuv)
        .unwrap_or_else(|e| panic!("Failed to encode frame: {e:?}"));

    let raw = bitstream.to_vec();
    assert!(!raw.is_empty(), "Encoded frame must not be empty");
    assert!(
        raw.len() > 4,
        "Encoded frame too small: {} bytes",
        raw.len()
    );
}

#[test]
fn test_encoder_inter_prediction_exercises_sad() {
    let width = 320;
    let height = 240;
    let mut encoder = Encoder::new().unwrap_or_else(|e| panic!("Failed to create encoder: {e:?}"));

    let mut total_bytes = 0usize;
    for i in 0u8..5 {
        let yuv = create_gradient_yuv(width, height, i * 10);
        let bitstream = encoder
            .encode(&yuv)
            .unwrap_or_else(|e| panic!("Failed to encode frame {i}: {e:?}"));

        let raw = bitstream.to_vec();
        assert!(
            !raw.is_empty(),
            "Frame {i} encoded output must not be empty"
        );
        total_bytes += raw.len();
    }

    assert!(
        total_bytes > 100,
        "Total encoded size should be substantial: {total_bytes} bytes"
    );
}

#[test]
fn test_encoder_with_motion_pattern() {
    let width = 160;
    let height = 128;
    let mut encoder = Encoder::new().unwrap_or_else(|e| panic!("Failed to create encoder: {e:?}"));

    for frame_idx in 0u8..10 {
        let y_size = width * height;
        let uv_size = (width / 2) * (height / 2);
        let mut yuv_data = vec![16u8; y_size + 2 * uv_size];

        let block_x = (frame_idx as usize * 4) % (width - 32);
        let block_y = (frame_idx as usize * 3) % (height - 32);
        for row in block_y..block_y + 32 {
            for col in block_x..block_x + 32 {
                yuv_data[row * width + col] = 235;
            }
        }
        for i in y_size..y_size + 2 * uv_size {
            yuv_data[i] = 128;
        }

        let yuv = YUVBuffer::from_vec(yuv_data, width, height);
        let bitstream = encoder
            .encode(&yuv)
            .unwrap_or_else(|e| panic!("Failed to encode frame {frame_idx}: {e:?}"));
        assert!(
            !bitstream.to_vec().is_empty(),
            "Frame {frame_idx} must produce output"
        );
    }
}
