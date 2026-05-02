//! Bastion Watch dashboard widgets -- pure-Rust SVG geometry helpers.
//!
//! The dashboard renders SVG without any client-side JavaScript.
//! These helpers compute the strings that Askama partials interpolate
//! verbatim into `<polyline points="...">`, `<path d="...">`, etc.
//! Keeping the math out of the templates means we can unit-test it,
//! audit its bounds, and produce stable snapshot diffs.
//!
//! Naming convention: helpers return owned `String`s ready to be
//! injected via Askama's auto-escape-aware `{{ }}` -- which we
//! complement here with a strict whitespace + numeric format so the
//! injected text never carries HTML-sensitive characters.

use std::fmt::Write as _;

/// Default sparkline viewport. Wide enough to feel like a real chart
/// on desktop, short enough to fit in a hero tile on mobile.
pub const SPARK_W: u32 = 160;
pub const SPARK_H: u32 = 40;

/// A computed sparkline ready for inline SVG rendering.
///
/// `points` is suitable for `<polyline points="...">`. Empty / single-
/// sample series render as a flat midline so the tile never collapses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sparkline {
    pub points: String,
    pub width: u32,
    pub height: u32,
    pub last_x: u32,
    pub last_y: u32,
}

impl Sparkline {
    /// Build a sparkline from a series of samples. Auto-scales Y to
    /// the observed [min..max] range; X is uniformly distributed
    /// across the viewport. Robust to NaN (treated as 0) and
    /// arbitrary length.
    pub fn from_series(samples: &[f32]) -> Self {
        Self::with_size(samples, SPARK_W, SPARK_H)
    }

    pub fn with_size(samples: &[f32], width: u32, height: u32) -> Self {
        let w = width.max(2);
        let h = height.max(2);
        if samples.is_empty() {
            let mid_y = h / 2;
            return Self {
                points: format!("0,{} {},{}", mid_y, w, mid_y),
                width: w,
                height: h,
                last_x: w,
                last_y: mid_y,
            };
        }
        let xs: Vec<f32> = samples.iter().map(|s| if s.is_nan() { 0.0 } else { *s }).collect();
        let min = xs.iter().cloned().fold(f32::INFINITY, f32::min);
        let max = xs.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
        let range = (max - min).max(f32::EPSILON);
        let n = xs.len() as f32;
        let mut s = String::with_capacity(xs.len() * 8);
        let mut last_x = 0u32;
        let mut last_y = h / 2;
        for (i, v) in xs.iter().enumerate() {
            let x = if n <= 1.0 {
                w / 2
            } else {
                ((i as f32) * (w as f32 - 1.0) / (n - 1.0)).round() as u32
            };
            // SVG Y axis grows downwards: invert.
            let normalised = (v - min) / range;
            let y = (h as f32 - 1.0 - normalised * (h as f32 - 1.0)).round().max(0.0) as u32;
            if i > 0 {
                s.push(' ');
            }
            let _ = write!(s, "{},{}", x, y);
            last_x = x;
            last_y = y;
        }
        Self {
            points: s,
            width: w,
            height: h,
            last_x,
            last_y,
        }
    }
}

/// A 270-degree gauge (-135deg to +135deg) ready for inline SVG.
///
/// `arc_path` is a single SVG path expression for the *filled*
/// portion. The unfilled track is a separate full-arc path that the
/// template hard-codes -- it does not depend on the percent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gauge {
    pub percent: u8,
    pub arc_path: String,
    pub label_inner: String,
    pub label_outer: String,
    pub viewbox_size: u32,
}

impl Gauge {
    pub fn new(percent: u8, label_inner: impl Into<String>, label_outer: impl Into<String>) -> Self {
        let p = percent.min(100);
        let path = arc_path_for_percent(p);
        Self {
            percent: p,
            arc_path: path,
            label_inner: label_inner.into(),
            label_outer: label_outer.into(),
            viewbox_size: 100,
        }
    }
}

/// Build a 270-degree arc path that starts at -135deg and rotates
/// clockwise by `percent` of 270deg.
fn arc_path_for_percent(percent: u8) -> String {
    let p = (percent.min(100) as f32) / 100.0;
    let total_sweep = 270.0_f32.to_radians();
    let sweep = p * total_sweep;

    // Centre at (50,50), radius 40, start angle -135deg from East.
    let cx = 50.0_f32;
    let cy = 50.0_f32;
    let r = 40.0_f32;
    let start_angle = (-135.0_f32 - 90.0).to_radians();
    let end_angle = start_angle + sweep;
    let (x0, y0) = (cx + r * start_angle.cos(), cy + r * start_angle.sin());
    let (x1, y1) = (cx + r * end_angle.cos(), cy + r * end_angle.sin());
    let large_arc = if sweep > std::f32::consts::PI { 1 } else { 0 };
    if percent == 0 {
        // Empty gauge: a single move-to so the path is valid SVG.
        return format!("M {x0:.2} {y0:.2}");
    }
    format!(
        "M {x0:.2} {y0:.2} A {r:.2} {r:.2} 0 {large_arc} 1 {x1:.2} {y1:.2}",
        x0 = x0,
        y0 = y0,
        r = r,
        large_arc = large_arc,
        x1 = x1,
        y1 = y1
    )
}

/// One donut segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DonutSegment {
    pub label: String,
    pub value: u64,
    /// Tailwind CSS class for the segment stroke.
    pub stroke_class: String,
    /// `stroke-dasharray` value: "{visible} {invisible}".
    pub dasharray: String,
    /// `stroke-dashoffset` to position the segment on the circle.
    pub dashoffset: String,
}

/// Donut chart helper.
///
/// Donut is rendered as a single `<circle>` per segment with custom
/// `stroke-dasharray` and `stroke-dashoffset`. Circumference is fixed
/// at 100 so percentages map 1:1 to dash lengths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Donut {
    pub segments: Vec<DonutSegment>,
    pub total: u64,
}

impl Donut {
    /// Build a donut from `(label, value, css_class)` triples.
    /// Empty / all-zero series returns a single placeholder segment
    /// with full circumference and a neutral colour.
    pub fn from_segments<I, S>(items: I) -> Self
    where
        I: IntoIterator<Item = (S, u64, S)>,
        S: Into<String>,
    {
        let raw: Vec<(String, u64, String)> = items
            .into_iter()
            .map(|(l, v, c)| (l.into(), v, c.into()))
            .collect();
        let total: u64 = raw.iter().map(|(_, v, _)| *v).sum();
        if total == 0 || raw.is_empty() {
            return Donut {
                segments: vec![DonutSegment {
                    label: "no data".to_string(),
                    value: 0,
                    stroke_class: "stroke-gray-200".to_string(),
                    dasharray: "100 0".to_string(),
                    dashoffset: "25".to_string(),
                }],
                total,
            };
        }
        let mut offset = 25u32; // start at 12 o'clock (circle origin is 3 o'clock)
        let mut segments = Vec::with_capacity(raw.len());
        for (label, value, class) in raw {
            let pct = (value as f64 * 100.0 / total as f64).round() as u32;
            let pct = pct.min(100);
            let dasharray = format!("{} {}", pct, 100 - pct);
            let dashoffset = format!("{}", offset);
            segments.push(DonutSegment {
                label,
                value,
                stroke_class: class,
                dasharray,
                dashoffset,
            });
            offset = (offset + 100 - pct) % 100;
        }
        Donut { segments, total }
    }
}

/// Activity heatmap (14 days x 24 hours).
///
/// Each cell carries a count and a 0..=4 intensity bucket so the
/// template can render a 5-step palette without computing maxima.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heatmap {
    pub rows: Vec<HeatmapRow>,
    pub max: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeatmapRow {
    pub label: String,
    pub cells: Vec<HeatmapCell>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeatmapCell {
    pub count: u32,
    /// 0..=4 intensity bucket.
    pub intensity: u8,
}

impl Heatmap {
    /// Build a heatmap from a `Vec<Vec<u32>>` of size [rows][24].
    /// `labels` is matched 1:1 to the outer Vec.
    pub fn from_grid(grid: &[Vec<u32>], labels: &[String]) -> Self {
        let max = grid.iter().flatten().copied().max().unwrap_or(0);
        let rows: Vec<HeatmapRow> = grid
            .iter()
            .enumerate()
            .map(|(i, row)| {
                let label = labels.get(i).cloned().unwrap_or_default();
                let cells = row
                    .iter()
                    .map(|&c| HeatmapCell {
                        count: c,
                        intensity: bucket(c, max),
                    })
                    .collect();
                HeatmapRow { label, cells }
            })
            .collect();
        Heatmap { rows, max }
    }
}

fn bucket(c: u32, max: u32) -> u8 {
    if max == 0 {
        return 0;
    }
    let pct = (c as f32 / max as f32 * 100.0).round() as u32;
    match pct {
        0 => 0,
        1..=20 => 1,
        21..=50 => 2,
        51..=80 => 3,
        _ => 4,
    }
}

/// Horizontal bar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bar {
    pub width_pct: u8,
    pub color_class: String,
    pub label: String,
    pub value_label: String,
}

impl Bar {
    pub fn new(value: u64, max: u64, color_class: impl Into<String>, label: impl Into<String>, value_label: impl Into<String>) -> Self {
        let pct = if max == 0 {
            0
        } else {
            ((value as f64 / max as f64) * 100.0).round() as u8
        }
        .min(100);
        Self {
            width_pct: pct,
            color_class: color_class.into(),
            label: label.into(),
            value_label: value_label.into(),
        }
    }
}

/// Status dot: ok / warn / err semantics, used to indicate live
/// health of a sub-system on the SYSTEM HEALTH tile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusLevel {
    Ok,
    Warn,
    Err,
}

impl StatusLevel {
    pub fn css_class(self) -> &'static str {
        match self {
            StatusLevel::Ok => "bg-emerald-500",
            StatusLevel::Warn => "bg-amber-500",
            StatusLevel::Err => "bg-rose-500",
        }
    }

    pub fn aria_label(self) -> &'static str {
        match self {
            StatusLevel::Ok => "ok",
            StatusLevel::Warn => "warning",
            StatusLevel::Err => "error",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparkline_empty_renders_a_flat_midline() {
        let s = Sparkline::from_series(&[]);
        assert!(s.points.contains(','));
        assert_eq!(s.width, SPARK_W);
        assert_eq!(s.height, SPARK_H);
    }

    #[test]
    fn sparkline_handles_constant_series_without_div_by_zero() {
        let s = Sparkline::from_series(&[5.0, 5.0, 5.0]);
        // No NaN / inf in the points string.
        assert!(!s.points.contains("NaN"));
        assert!(!s.points.contains("inf"));
        // 3 points -> 2 spaces.
        assert_eq!(s.points.matches(' ').count(), 2);
    }

    #[test]
    fn sparkline_endpoint_is_within_viewport() {
        let s = Sparkline::from_series(&[1.0, 2.0, 4.0, 8.0, 16.0]);
        assert!(s.last_x <= s.width);
        assert!(s.last_y < s.height);
    }

    #[test]
    fn gauge_zero_percent_uses_move_only_path() {
        let g = Gauge::new(0, "0", "%");
        assert!(g.arc_path.starts_with("M "));
        assert!(!g.arc_path.contains(" A "));
    }

    #[test]
    fn gauge_full_percent_uses_arc_command() {
        let g = Gauge::new(100, "MAX", "%");
        assert!(g.arc_path.contains(" A "));
    }

    #[test]
    fn gauge_caps_percent_at_100() {
        let g = Gauge::new(250, "OVER", "%");
        assert_eq!(g.percent, 100);
    }

    #[test]
    fn donut_empty_returns_neutral_segment() {
        let d = Donut::from_segments::<_, String>(vec![]);
        assert_eq!(d.total, 0);
        assert_eq!(d.segments.len(), 1);
        assert!(d.segments[0].stroke_class.contains("gray"));
    }

    #[test]
    fn donut_three_segments_sum_to_circle() {
        let d = Donut::from_segments(vec![
            ("ssh", 30u64, "stroke-blue-500"),
            ("rdp", 70u64, "stroke-purple-500"),
        ]);
        assert_eq!(d.total, 100);
        assert_eq!(d.segments.len(), 2);
        // Each dasharray is "<visible> <invisible>" and visible should
        // sum to 100 across all segments.
        let visible_sum: u32 = d
            .segments
            .iter()
            .map(|s| s.dasharray.split_whitespace().next().unwrap_or("0").parse().unwrap_or(0))
            .sum();
        assert_eq!(visible_sum, 100);
    }

    #[test]
    fn heatmap_buckets_intensities_by_relative_max() {
        let grid = vec![
            vec![0, 5, 10, 50, 100],
            vec![0, 0, 0, 0, 0],
        ];
        let h = Heatmap::from_grid(&grid, &["d0".to_string(), "d1".to_string()]);
        assert_eq!(h.max, 100);
        assert_eq!(h.rows[0].cells[0].intensity, 0);
        assert!(h.rows[0].cells[1].intensity >= 1);
        assert_eq!(h.rows[0].cells[4].intensity, 4);
        assert!(h.rows[1].cells.iter().all(|c| c.intensity == 0));
    }

    #[test]
    fn bar_caps_at_100_percent() {
        let b = Bar::new(500, 100, "bg-blue-500", "label", "value");
        assert_eq!(b.width_pct, 100);
    }

    #[test]
    fn bar_zero_max_renders_zero_width() {
        let b = Bar::new(7, 0, "bg-blue-500", "label", "value");
        assert_eq!(b.width_pct, 0);
    }

    #[test]
    fn status_level_classes_are_distinct() {
        assert_ne!(StatusLevel::Ok.css_class(), StatusLevel::Warn.css_class());
        assert_ne!(StatusLevel::Warn.css_class(), StatusLevel::Err.css_class());
    }
}
