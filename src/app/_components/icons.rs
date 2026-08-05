//! Geometric SVG icons (currentColor). Prefer these over Unicode glyphs.

use topcoat::{Result, context::Cx, view::view};

/// Stroke weight for rail / navigation icons (outline set).
pub const RAIL_STROKE: &str = "1.6";
/// Stroke weight for controls (close, chevrons, plus, check, …).
pub const CONTROL_STROKE: &str = "1.8";

fn box_style(size: u32) -> String {
    format!("width:{size}px;height:{size}px")
}

pub async fn ico_home(cx: &Cx, size: u32) -> Result {
    let s = size.to_string();
    let style = box_style(size);
    let stroke = RAIL_STROKE;
    view! {
        cx =>
        <span class="vb-ico" aria-hidden="true" style=(style)>
            <svg
                width=(s.clone())
                height=(s)
                viewBox="0 0 17 17"
                fill="none"
                stroke="currentColor"
                stroke-width=(stroke)
            >
                <rect x="2" y="2" width="5.5" height="5.5" rx="0.6"></rect>
                <rect x="9.5" y="2" width="5.5" height="5.5" rx="0.6"></rect>
                <rect x="2" y="9.5" width="5.5" height="5.5" rx="0.6"></rect>
                <rect x="9.5" y="9.5" width="5.5" height="5.5" rx="0.6"></rect>
            </svg>
        </span>
    }
}

pub async fn ico_docs(cx: &Cx, size: u32) -> Result {
    let s = size.to_string();
    let style = box_style(size);
    let stroke = RAIL_STROKE;
    view! {
        cx =>
        <span class="vb-ico" aria-hidden="true" style=(style)>
            <svg
                width=(s.clone())
                height=(s)
                viewBox="0 0 17 17"
                fill="none"
                stroke="currentColor"
                stroke-width=(stroke)
            >
                <rect x="3.2" y="2.8" width="10.6" height="11.4" rx="1.2"></rect>
                <path d="M10.2 2.8 V6.2 H13.8"></path>
            </svg>
        </span>
    }
}

pub async fn ico_builds(cx: &Cx, size: u32) -> Result {
    let s = size.to_string();
    let style = box_style(size);
    let stroke = RAIL_STROKE;
    view! {
        cx =>
        <span class="vb-ico" aria-hidden="true" style=(style)>
            <svg
                width=(s.clone())
                height=(s)
                viewBox="0 0 17 17"
                fill="none"
                stroke="currentColor"
                stroke-width=(stroke)
                stroke-linejoin="round"
            >
                <path d="M8.5 2.2 L14.2 5.5 L14.2 11.5 L8.5 14.8 L2.8 11.5 L2.8 5.5 Z"></path>
            </svg>
        </span>
    }
}

pub async fn ico_issues(cx: &Cx, size: u32) -> Result {
    let s = size.to_string();
    let style = box_style(size);
    let stroke = RAIL_STROKE;
    view! {
        cx =>
        <span class="vb-ico" aria-hidden="true" style=(style)>
            <svg
                width=(s.clone())
                height=(s)
                viewBox="0 0 17 17"
                fill="none"
                stroke="currentColor"
                stroke-width=(stroke)
                stroke-linejoin="round"
            >
                <path d="M4.9 2.4 V14.6"></path>
                <path d="M4.9 2.6 H12.4 L10.8 5.6 L12.4 8.6 H4.9 Z"></path>
            </svg>
        </span>
    }
}

pub async fn ico_edit(cx: &Cx, size: u32) -> Result {
    let s = size.to_string();
    let style = box_style(size);
    let stroke = RAIL_STROKE;
    view! {
        cx =>
        <span class="vb-ico" aria-hidden="true" style=(style)>
            <svg
                width=(s.clone())
                height=(s)
                viewBox="0 0 17 17"
                fill="none"
                stroke="currentColor"
                stroke-width=(stroke)
                stroke-linecap="round"
                stroke-linejoin="round"
            >
                <path d="M9.6 3.4 L13.6 7.4 L6.2 14.8 H2.2 V10.8 Z"></path>
                <path d="M8.2 4.8 L12.2 8.8"></path>
            </svg>
        </span>
    }
}

pub async fn ico_release(cx: &Cx, size: u32) -> Result {
    let s = size.to_string();
    let style = box_style(size);
    let stroke = RAIL_STROKE;
    view! {
        cx =>
        <span class="vb-ico" aria-hidden="true" style=(style)>
            <svg
                width=(s.clone())
                height=(s)
                viewBox="0 0 17 17"
                fill="none"
                stroke="currentColor"
                stroke-width=(stroke)
                stroke-linejoin="round"
            >
                <path d="M8.5 2.2 L13.8 8.2 H10.6 V14.8 H6.4 V8.2 H3.2 Z"></path>
            </svg>
        </span>
    }
}

pub async fn ico_orgs(cx: &Cx, size: u32) -> Result {
    let s = size.to_string();
    let style = box_style(size);
    let stroke = RAIL_STROKE;
    view! {
        cx =>
        <span class="vb-ico" aria-hidden="true" style=(style)>
            <svg
                width=(s.clone())
                height=(s)
                viewBox="0 0 17 17"
                fill="none"
                stroke="currentColor"
                stroke-width=(stroke)
                stroke-linejoin="round"
            >
                <path d="M2.8 14.4 H14.2 V7.8 L8.5 2.8 L2.8 7.8 Z"></path>
                <path d="M7 14.4 V10.2 H10 V14.4"></path>
            </svg>
        </span>
    }
}

/// Security key (KEY / WebAuthn) — round head, toothed shaft.
pub async fn ico_key(cx: &Cx, size: u32) -> Result {
    let s = size.to_string();
    let style = box_style(size);
    let stroke = RAIL_STROKE;
    view! {
        cx =>
        <span class="vb-ico" aria-hidden="true" style=(style)>
            <svg
                width=(s.clone())
                height=(s)
                viewBox="0 0 17 17"
                fill="none"
                stroke="currentColor"
                stroke-width=(stroke)
                stroke-linecap="round"
                stroke-linejoin="round"
            >
                <circle cx="6" cy="6" r="3.2"></circle>
                <path d="M8.3 8.3 L14.4 14.4"></path>
                <path d="M11.2 11.2 L13 9.4"></path>
                <path d="M13.3 13.3 L15.1 11.5"></path>
            </svg>
        </span>
    }
}

pub async fn ico_arrow_down(cx: &Cx, size: u32) -> Result {
    let s = size.to_string();
    let style = box_style(size);
    let stroke = CONTROL_STROKE;
    view! {
        cx =>
        <span class="vb-ico" aria-hidden="true" style=(style)>
            <svg
                width=(s.clone())
                height=(s)
                viewBox="0 0 17 17"
                fill="none"
                stroke="currentColor"
                stroke-width=(stroke)
                stroke-linecap="round"
                stroke-linejoin="round"
            >
                <path d="M8.5 3.5 V13"></path>
                <path d="M4.5 9.5 L8.5 13.5 L12.5 9.5"></path>
            </svg>
        </span>
    }
}

pub async fn ico_chevron_right(cx: &Cx, size: u32) -> Result {
    let s = size.to_string();
    let style = box_style(size);
    let stroke = CONTROL_STROKE;
    view! {
        cx =>
        <span class="vb-ico" aria-hidden="true" style=(style)>
            <svg
                width=(s.clone())
                height=(s)
                viewBox="0 0 17 17"
                fill="none"
                stroke="currentColor"
                stroke-width=(stroke)
                stroke-linecap="round"
                stroke-linejoin="round"
            >
                <path d="M6.5 3.5 L11.5 8.5 L6.5 13.5"></path>
            </svg>
        </span>
    }
}

pub async fn ico_chevron_down(cx: &Cx, size: u32) -> Result {
    let s = size.to_string();
    let style = box_style(size);
    let stroke = CONTROL_STROKE;
    view! {
        cx =>
        <span class="vb-ico" aria-hidden="true" style=(style)>
            <svg
                width=(s.clone())
                height=(s)
                viewBox="0 0 17 17"
                fill="none"
                stroke="currentColor"
                stroke-width=(stroke)
                stroke-linecap="round"
                stroke-linejoin="round"
            >
                <path d="M3.5 6.5 L8.5 11.5 L13.5 6.5"></path>
            </svg>
        </span>
    }
}

pub async fn ico_close(cx: &Cx, size: u32) -> Result {
    let s = size.to_string();
    let style = box_style(size);
    let stroke = CONTROL_STROKE;
    view! {
        cx =>
        <span class="vb-ico" aria-hidden="true" style=(style)>
            <svg
                width=(s.clone())
                height=(s)
                viewBox="0 0 17 17"
                fill="none"
                stroke="currentColor"
                stroke-width=(stroke)
                stroke-linecap="round"
            >
                <path d="M4 4 L13 13"></path>
                <path d="M13 4 L4 13"></path>
            </svg>
        </span>
    }
}

pub async fn ico_plus(cx: &Cx, size: u32) -> Result {
    let s = size.to_string();
    let style = box_style(size);
    let stroke = CONTROL_STROKE;
    view! {
        cx =>
        <span class="vb-ico" aria-hidden="true" style=(style)>
            <svg
                width=(s.clone())
                height=(s)
                viewBox="0 0 17 17"
                fill="none"
                stroke="currentColor"
                stroke-width=(stroke)
                stroke-linecap="round"
            >
                <path d="M8.5 3.5 V13.5"></path>
                <path d="M3.5 8.5 H13.5"></path>
            </svg>
        </span>
    }
}

pub async fn ico_check(cx: &Cx, size: u32) -> Result {
    let s = size.to_string();
    let style = box_style(size);
    let stroke = CONTROL_STROKE;
    view! {
        cx =>
        <span class="vb-ico" aria-hidden="true" style=(style)>
            <svg
                width=(s.clone())
                height=(s)
                viewBox="0 0 17 17"
                fill="none"
                stroke="currentColor"
                stroke-width=(stroke)
                stroke-linecap="round"
                stroke-linejoin="round"
            >
                <path d="M3.5 9 L7 12.5 L13.5 4.5"></path>
            </svg>
        </span>
    }
}

/// Overlapping rectangles — Concept “copy command” affordance.
pub async fn ico_copy(cx: &Cx, size: u32) -> Result {
    let s = size.to_string();
    let style = box_style(size);
    let stroke = CONTROL_STROKE;
    view! {
        cx =>
        <span class="vb-ico" aria-hidden="true" style=(style)>
            <svg
                width=(s.clone())
                height=(s)
                viewBox="0 0 17 17"
                fill="none"
                stroke="currentColor"
                stroke-width=(stroke)
                stroke-linejoin="round"
            >
                <rect x="5.5" y="5.5" width="8" height="8" rx="1.2"></rect>
                <path d="M3.5 11.5 V4.2 A1.2 1.2 0 0 1 4.7 3 H11.5"></path>
            </svg>
        </span>
    }
}

pub async fn ico_hourglass(cx: &Cx, size: u32) -> Result {
    let s = size.to_string();
    let style = box_style(size);
    let stroke = CONTROL_STROKE;
    view! {
        cx =>
        <span class="vb-ico" aria-hidden="true" style=(style)>
            <svg
                width=(s.clone())
                height=(s)
                viewBox="0 0 17 17"
                fill="none"
                stroke="currentColor"
                stroke-width=(stroke)
                stroke-linejoin="round"
            >
                <path
                    d="M4.5 3.2 H12.5 V5.2 L9.2 8.5 L12.5 11.8 V13.8 H4.5 V11.8 L7.8 8.5 L4.5 5.2 Z"
                ></path>
            </svg>
        </span>
    }
}

pub async fn ico_trash(cx: &Cx, size: u32) -> Result {
    let s = size.to_string();
    let style = box_style(size);
    let stroke = CONTROL_STROKE;
    view! {
        cx =>
        <span class="vb-ico" aria-hidden="true" style=(style)>
            <svg
                width=(s.clone())
                height=(s)
                viewBox="0 0 17 17"
                fill="none"
                stroke="currentColor"
                stroke-width=(stroke)
                stroke-linecap="round"
                stroke-linejoin="round"
            >
                <path d="M3.5 4.5 H13.5"></path>
                <path d="M6.2 4.5 V3.2 H10.8 V4.5"></path>
                <path d="M5.2 4.5 V13.2 H11.8 V4.5"></path>
                <path d="M7.2 7 V11"></path>
                <path d="M9.8 7 V11"></path>
            </svg>
        </span>
    }
}

pub async fn ico_paperclip(cx: &Cx, size: u32) -> Result {
    let s = size.to_string();
    let style = box_style(size);
    let stroke = CONTROL_STROKE;
    view! {
        cx =>
        <span class="vb-ico" aria-hidden="true" style=(style)>
            <svg
                width=(s.clone())
                height=(s)
                viewBox="0 0 17 17"
                fill="none"
                stroke="currentColor"
                stroke-width=(stroke)
                stroke-linecap="round"
                stroke-linejoin="round"
            >
                <path
                    d="M14 8.2 L8.2 14 A3.2 3.2 0 0 1 3.6 9.4 L10.4 2.6 A2.2 2.2 0 0 1 13.5 5.7 L6.8 12.4 A1.1 1.1 0 0 1 5.2 10.8 L11.2 4.8"
                ></path>
            </svg>
        </span>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rail_stroke_is_thinner_than_control() {
        assert_eq!(RAIL_STROKE, "1.6");
        assert_eq!(CONTROL_STROKE, "1.8");
        let rail: f64 = RAIL_STROKE.parse().unwrap();
        let control: f64 = CONTROL_STROKE.parse().unwrap();
        assert!(rail <= control);
    }

    #[test]
    fn ico_home_and_issues_are_stroke_outlines() {
        let src = include_str!("icons.rs");
        let home = src
            .split("pub async fn ico_home")
            .nth(1)
            .and_then(|s| s.split("pub async fn ").next())
            .expect("ico_home");
        assert!(home.contains("stroke=\"currentColor\"") || home.contains("stroke=(stroke)"));
        assert!(home.contains("fill=\"none\""));
        assert!(!home.contains("fill=\"currentColor\""));

        let issues = src
            .split("pub async fn ico_issues")
            .nth(1)
            .and_then(|s| s.split("pub async fn ").next())
            .expect("ico_issues");
        assert!(issues.contains("stroke=\"currentColor\"") || issues.contains("stroke=(stroke)"));
        assert!(issues.contains("fill=\"none\""));
        assert!(!issues.contains("fill=\"currentColor\""));
    }
}
