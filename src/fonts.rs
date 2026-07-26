//! Concept typefaces via Fontsource (compile-time catalog checks).

use topcoat::font::{Font, fontsource::fontsource_font};

pub const HANKEN_GROTESK: Font =
    fontsource_font!(HANKEN_GROTESK, weight: [400, 500, 600, 700, 800]);

pub const JETBRAINS_MONO: Font = fontsource_font!(JETBRAINS_MONO, weight: [400, 500, 600, 700]);
