//! Magic-byte sniffing for tenant images (architecture §6.3).

use super::ids::normalize_image_ext;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageKind {
    Png,
    Jpeg,
    Webp,
}

impl ImageKind {
    pub const fn ext(self) -> &'static str {
        match self {
            Self::Png => "png",
            Self::Jpeg => "jpeg",
            Self::Webp => "webp",
        }
    }

    pub const fn content_type(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Webp => "image/webp",
        }
    }
}

/// Sniff image kind from the start of a blob. Rejects SVG and unknowns.
pub fn sniff_image(bytes: &[u8]) -> Option<ImageKind> {
    if bytes.starts_with(&[0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n']) {
        return Some(ImageKind::Png);
    }
    if bytes.len() >= 3 && bytes[0] == 0xff && bytes[1] == 0xd8 && bytes[2] == 0xff {
        return Some(ImageKind::Jpeg);
    }
    if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return Some(ImageKind::Webp);
    }
    // SVG / XML never accepted (stored-XSS).
    if looks_like_svg(bytes) {
        return None;
    }
    None
}

fn looks_like_svg(bytes: &[u8]) -> bool {
    let head = std::str::from_utf8(bytes.get(..256).unwrap_or(bytes))
        .unwrap_or("")
        .trim_start()
        .to_ascii_lowercase();
    head.starts_with("<?xml") || head.starts_with("<svg")
}

/// Declared ext must match sniffed kind.
pub fn sniff_matches_ext(bytes: &[u8], declared_ext: &str) -> Result<ImageKind, &'static str> {
    let Some(kind) = sniff_image(bytes) else {
        return Err("bad_image");
    };
    let Some(norm) = normalize_image_ext(declared_ext) else {
        return Err("bad_image");
    };
    if kind.ext() != norm {
        return Err("bad_image");
    }
    Ok(kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PNG: &[u8] = &[
        0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n', 0, 0, 0, 0,
    ];
    const JPEG: &[u8] = &[0xff, 0xd8, 0xff, 0xe0, 0, 0];
    const WEBP: &[u8] = b"RIFF\x00\x00\x00\x00WEBPxxxx";
    const SVG: &[u8] = b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>";

    #[test]
    fn sniffs_known_types() {
        assert_eq!(sniff_image(PNG), Some(ImageKind::Png));
        assert_eq!(sniff_image(JPEG), Some(ImageKind::Jpeg));
        assert_eq!(sniff_image(WEBP), Some(ImageKind::Webp));
    }

    #[test]
    fn rejects_svg_and_mismatched_ext() {
        assert!(sniff_image(SVG).is_none());
        assert!(sniff_matches_ext(PNG, "jpeg").is_err());
        assert!(sniff_matches_ext(PNG, "png").is_ok());
        assert!(sniff_matches_ext(SVG, "png").is_err());
    }
}
