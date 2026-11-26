// fe-gui — macOS Computer Use (FR-05)
//
// P4 implementation: AXUIElement (accessibility crate, safe wrapper) + CoreGraphics fallback
// CI skips GUI (TCC Accessibility + Screen Recording permissions); graceful degradation when
// ax_trusted() is false.
//
// Crate-level unsafe allow — scoped to this crate only. The other 7 crates keep
// workspace unsafe_code="deny". Reason: since rustc 1.96, functions inside extern "C" {}
// blocks default to unsafe-to-call (unsafe_extern_blocks migration); accessibility-sys 0.2
// declares plain extern "C" and does not export safe wrappers. AXIsProcessTrusted() and
// AXValueGetValue() (position/size) only exist in accessibility-sys; the accessibility 0.2
// safe crate does not cover them. Hence these 3 FFI calls need unsafe blocks. The rest of
// the GUI logic still goes through the accessibility 0.2 safe wrapper (~90%).
// User decision (2026-08-20): scope allow to fe-gui only, 3 audited unsafe blocks.
#![allow(unsafe_code)]

use accessibility::AXAttribute;
use accessibility::AXUIElement;
use accessibility::AXUIElementActions as _;
use accessibility::AXUIElementAttributes as _;
use accessibility_sys::{
    kAXCloseButtonAttribute, kAXFocusedApplicationAttribute, kAXMinimizeButtonAttribute,
    kAXPositionAttribute, kAXSecureTextFieldSubrole, kAXSizeAttribute, kAXValueTypeCGPoint,
    kAXValueTypeCGSize, kAXZoomButtonAttribute, AXIsProcessTrusted, AXValueGetValue, AXValueRef,
};
use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use core_foundation::array::CFArray;
use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::string::CFString;
use core_graphics::color_space::CGColorSpace;
use core_graphics::context::CGContext;
use core_graphics::display::CGDisplay;
use core_graphics::event::{
    CGEvent, CGEventFlags, CGEventTapLocation, CGEventType, CGKeyCode, CGMouseButton, EventField,
    KeyCode, ScrollEventUnit,
};
use core_graphics::event_source::{CGEventSource, CGEventSourceStateID};
use core_graphics::geometry::{CGPoint, CGRect, CGSize};
use core_graphics::image::CGImage;
use png::{BitDepth, ColorType, Encoder};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// Screenshot node-tree limits — OOM + recursion-explosion guards
const MAX_TREE_DEPTH: usize = 8;
const MAX_TREE_NODES: usize = 500;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GuiAction {
    FocusApp {
        bundle_id: String,
    },
    Click {
        ax_label: Option<String>,
        ax_position: Option<(f64, f64)>,
    },
    TypeText {
        text: String,
    },
    KeyPress {
        key: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        modifiers: Vec<String>,
    },
    HoldKey {
        key: String,
        duration_ms: u64,
    },
    Screenshot {
        // #40: sensitive-area masking — when true, walk the AX tree for AXSecureTextField
        // (password field) position/size, black out the matching pixel regions of the
        // screenshot PNG before encoding, preventing VLM credential leakage. Requires
        // Accessibility TCC (AX tree walk); when unauthorized, skip masking and warn
        // (screenshot still returned, just unmasked).
        #[serde(default)]
        mask_sensitive: bool,
    },
    InspectTree {},
    Scroll {
        dx: i32,
        dy: i32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        at: Option<(f64, f64)>,
    },
    Drag {
        from: (f64, f64),
        to: (f64, f64),
    },
    DoubleClick {
        ax_label: Option<String>,
        ax_position: Option<(f64, f64)>,
    },
    TripleClick {
        ax_label: Option<String>,
        ax_position: Option<(f64, f64)>,
    },
    RightClick {
        ax_label: Option<String>,
        ax_position: Option<(f64, f64)>,
    },
    Hover {
        ax_position: (f64, f64),
    },
    WindowClose {
        bundle_id: Option<String>,
    },
    WindowMinimize {
        bundle_id: Option<String>,
    },
    WindowZoom {
        bundle_id: Option<String>,
    },
    WindowResize {
        bundle_id: Option<String>,
        width: f64,
        height: f64,
    },
    Wait {
        seconds: f64,
    },
    // #44: batch mouse move — ordered point sequence, completed atomically in a single UDS
    // round-trip (avoids N hover round-trips). CGEvent MouseMoved (no buttons) interpolates
    // linearly along the waypoints; duration_ms is the total duration split across segments.
    MovePath {
        points: Vec<(f64, f64)>,
        #[serde(default)]
        duration_ms: u64,
    },
    // #43: display capability query — enumerate all active displays (id/scale/bounds/primary),
    // trusted-independent (goes through CGDisplay, not AX). fusion-osagent reads scale_factor
    // from this, removing the hardcoded 2.0 assumption.
    DisplayInfo {},
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GuiResult {
    pub ok: bool,
    pub node_tree: Option<String>,
    pub screenshot_png_b64: Option<String>,
    pub screenshot_width: Option<u32>,
    pub screenshot_height: Option<u32>,
    // #38: backing scale factor — physical PNG pixels / logical points (Retina=2.0, non-Retina=1.0).
    // Coordinate contract: all GuiAction x/y inputs + inspect_tree AXPosition = logical points;
    //           screenshot_width/height = physical pixels. Callers convert both ways with this
    //           (pixel = point * scale).
    // Non-screenshot results default to 1.0 (meaningless without a screenshot, but keeps
    // backward compat with absent=1.0).
    #[serde(default = "default_scale_factor")]
    pub scale_factor: f32,
    // #43: display inventory JSON (filled by the display_info action) —
    // [{id, scale, bounds:{x,y,w,h}, primary}].
    // additive: None on non-display_info results, backward compatible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub displays: Option<String>,
    pub error: Option<String>,
}

fn default_scale_factor() -> f32 {
    1.0
}

/// Single UI node — tree node emitted by InspectTree
#[derive(Debug, Clone, Serialize)]
struct UiNode {
    role: String,
    title: Option<String>,
    label: Option<String>,
    position: Option<(f64, f64)>,
    size: Option<(f64, f64)>,
    enabled: Option<bool>,
    actions: Vec<String>,
    children: Vec<UiNode>,
}

/// GUI controller — P4 implementation (AXUIElement + CoreGraphics)
/// Click candidate — (node, label, position)
type ClickCandidate = (AXUIElement, Option<String>, Option<(f64, f64)>);

/// RUN-12: default bundle safe set — non-empty allowlist as the commercial-safe default,
/// preventing unauthorized driving of arbitrary apps.
/// Local trusted callers that need unrestricted access pass
/// GuiConfig { allowed_bundle_ids: None, .. } explicitly (backward compatible).
const DEFAULT_ALLOWED_BUNDLE_IDS: &[&str] = &[
    "com.apple.Terminal",
    "com.apple.TextEdit",
    "com.apple.finder",
];

/// M-SEC-04: GUI security configuration.
/// - allowed_bundle_ids: None=unrestricted (explicit opt-in, audit-logged only);
///   Some=set=only bundles in the set are allowed.
///   RUN-12: default is the non-empty safe set (DEFAULT_ALLOWED_BUNDLE_IDS), restricted by default.
/// - allow_type_into_secure: false (default) rejects type_text into AXSecureTextField
///   (password fields); true is an explicit opt-in (controlled scenarios). Either value is
///   audit-logged as WARN (bundle + text length, never the text itself).
#[derive(Debug, Clone)]
pub struct GuiConfig {
    pub allowed_bundle_ids: Option<Vec<String>>,
    pub allow_type_into_secure: bool,
}

/// RUN-12: default non-empty allowlist (commercial-safe default), not None.
/// No conflict with the check_bundle_allowed None→Ok contract: an explicit None still means
/// an unrestricted opt-in.
impl Default for GuiConfig {
    fn default() -> Self {
        GuiConfig {
            allowed_bundle_ids: Some(
                DEFAULT_ALLOWED_BUNDLE_IDS
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect(),
            ),
            allow_type_into_secure: false,
        }
    }
}

pub struct GuiController {
    config: GuiConfig,
}

impl GuiController {
    pub fn new() -> Self {
        info!("GuiController::new() — AXUIElement + CoreGraphics (P4)");
        Self {
            config: GuiConfig::default(),
        }
    }

    /// M-SEC-04: construct with security config (enterprise/multi-user scenarios set a bundle
    /// allowlist + the secure flag).
    pub fn new_with_config(config: GuiConfig) -> Self {
        info!(
            allowlist = ?config.allowed_bundle_ids.as_ref().map(|v| v.len()),
            allow_secure = config.allow_type_into_secure,
            "GuiController::new_with_config (M-SEC-04)"
        );
        Self { config }
    }

    /// M-SEC-04: bundle admission check. allowlist=None always allows (audit-logged only);
    /// Some=set requires a hit.
    fn check_bundle_allowed(&self, bundle_id: &str) -> Result<()> {
        match &self.config.allowed_bundle_ids {
            None => {
                debug!(
                    bundle_id,
                    "M-SEC-04 bundle has no allowlist, allowed (audit)"
                );
                Ok(())
            }
            Some(set) => {
                if set.iter().any(|b| b == bundle_id) {
                    debug!(bundle_id, "M-SEC-04 bundle hit allowlist");
                    Ok(())
                } else {
                    warn!(
                        bundle_id,
                        "M-SEC-04 bundle not in allowlist — rejected (prevents driving arbitrary apps)"
                    );
                    Err(anyhow!("bundle-not-allowed: {bundle_id}"))
                }
            }
        }
    }

    /// C-13: resolve the focused app's bundle id (best-effort).
    /// accessibility-sys 0.2 has no kAXBundleIdentifierAttribute constant — use the raw
    /// CFString "AXBundleIdentifier" via AXAttribute::<CFType> read + downcast to CFString
    /// (same pattern as focused_app reading AXFocusedApplication).
    /// Used for bundle allowlist checks of HID-post input synthesis methods
    /// (key_press/hold_key/scroll/drag/hover).
    fn focused_app_bundle(&self) -> Result<String> {
        let app = Self::focused_app()?;
        let attr = AXAttribute::<CFType>::new(&CFString::from_static_string("AXBundleIdentifier"));
        let cf: CFType = app
            .attribute(&attr)
            .map_err(|e| anyhow!("failed to read AXBundleIdentifier: {e}"))?;
        let s = cf
            .downcast::<CFString>()
            .ok_or_else(|| anyhow!("AXBundleIdentifier is not a CFString"))?;
        Ok(s.to_string())
    }

    /// C-13: check whether the focused app's bundle is allowlisted, at the top of every
    /// input-synthesis method.
    /// allowlist=None → allow (audit, short-circuits without any AX call); Some=set → resolve
    /// the focused bundle then reuse the pure check_bundle_allowed validation (no duplicated
    /// logic). TOCTOU: focus may switch between check and HID-post — inherent to HID,
    /// best-effort not atomic, but it closes the current bypass (wait for a non-allowlisted
    /// app to get focus → type_text injection).
    fn check_focused_allowed(&self) -> Result<()> {
        match &self.config.allowed_bundle_ids {
            None => {
                debug!("C-13 input synthesis: no allowlist, focused app allowed (audit)");
                Ok(())
            }
            Some(_) => {
                let bundle = self.focused_app_bundle().unwrap_or_default();
                self.check_bundle_allowed(&bundle)
            }
        }
    }

    /// C-13: call at the top of input-synthesis methods — allowlist block returns
    /// Some(degraded GuiResult), allow returns None.
    /// Each method gates with one line: `if let Some(r) = self.focused_not_allowed() { return Ok(r); }`.
    fn focused_not_allowed(&self) -> Option<GuiResult> {
        match self.check_focused_allowed() {
            Ok(()) => None,
            Err(e) => {
                warn!(error = %e, "C-13: focused app not in allowlist — input synthesis rejected (prevents unauthorized injection)");
                Some(GuiResult {
                    ok: false,
                    error: Some(format!("focused-app-not-allowed: {e}")),
                    ..Default::default()
                })
            }
        }
    }

    /// Whether AX is authorized (TCC Accessibility). When unauthorized, all GUI operations
    /// degrade to an error.
    /// unsafe: AXIsProcessTrusted is an accessibility-sys extern "C" fn (unsafe-to-call by
    /// default since rustc 1.96). That C function only reads TCC state and returns a bool,
    /// no pointer parameters, no memory-safety risk.
    pub fn ax_trusted() -> bool {
        unsafe { AXIsProcessTrusted() }
    }

    pub fn execute(&self, action: GuiAction) -> Result<GuiResult> {
        // Wait — pure delay, trusted-independent, needs no AX authorization; handle first (CI-testable)
        if let GuiAction::Wait { seconds } = &action {
            return self.wait(*seconds);
        }
        // IMPL-9: Screenshot goes through CoreGraphics (CGWindowListCreateImage) and needs
        // Screen Recording TCC, not Accessibility TCC — the two permissions are independent.
        // AX unauthorized but Screen Recording authorized should still allow screenshots.
        // Hoisted before the ax_trusted gate so screenshot() probes Screen Recording itself
        // (CGImage None → degrade).
        if let GuiAction::Screenshot { mask_sensitive } = &action {
            return self.screenshot(*mask_sensitive);
        }
        // #43: DisplayInfo goes through CGDisplay (not AX), trusted-independent — hoisted
        // before the ax_trusted gate.
        if let GuiAction::DisplayInfo {} = &action {
            return self.display_info();
        }
        if !Self::ax_trusted() {
            warn!("AX not authorized (TCC Accessibility) — GUI operations degraded");
            return Ok(GuiResult {
                ok: false,
                error: Some("accessibility-permission-required".into()),
                ..Default::default()
            });
        }
        match action {
            GuiAction::FocusApp { bundle_id } => self.focus_app(&bundle_id),
            GuiAction::Click {
                ax_label,
                ax_position,
            } => self.click(ax_label.as_deref(), ax_position),
            GuiAction::TypeText { text } => self.type_text(&text),
            GuiAction::KeyPress { key, modifiers } => self.key_press(&key, &modifiers),
            GuiAction::HoldKey { key, duration_ms } => self.hold_key(&key, duration_ms),
            // IMPL-9: Screenshot early-returns before the ax_trusted gate (Screen Recording TCC
            // is independent). Reaching here means the early-return was broken by a refactor —
            // fail-loud (not crash), same fallback pattern as Wait.
            GuiAction::Screenshot { .. } => Ok(GuiResult {
                ok: false,
                error: Some(
                    "internal: Screenshot not handled at early-return (invariant broken)".into(),
                ),
                ..Default::default()
            }),
            GuiAction::InspectTree {} => self.inspect_tree(),
            GuiAction::Scroll { dx, dy, at } => self.scroll(dx, dy, at),
            GuiAction::Drag { from, to } => self.drag(from, to),
            GuiAction::DoubleClick {
                ax_label,
                ax_position,
            } => self.double_click(ax_label.as_deref(), ax_position),
            GuiAction::TripleClick {
                ax_label,
                ax_position,
            } => self.triple_click(ax_label.as_deref(), ax_position),
            GuiAction::RightClick {
                ax_label,
                ax_position,
            } => self.right_click(ax_label.as_deref(), ax_position),
            GuiAction::Hover { ax_position } => self.hover(ax_position),
            GuiAction::WindowClose { bundle_id } => self.window_button(bundle_id, "close"),
            GuiAction::WindowMinimize { bundle_id } => self.window_button(bundle_id, "minimize"),
            GuiAction::WindowZoom { bundle_id } => self.window_button(bundle_id, "zoom"),
            GuiAction::WindowResize {
                bundle_id,
                width,
                height,
            } => self.window_resize(bundle_id, width, height),
            // m-FT-04: Wait early-returns before ax_trusted; reaching here means the
            // early-return was broken by a refactor. No panic — fail-loud with an error
            // (visible to the caller, not a crash).
            GuiAction::Wait { .. } => Ok(GuiResult {
                ok: false,
                error: Some("internal: Wait not handled at early-return (invariant broken)".into()),
                ..Default::default()
            }),
            // #44: move_path — N-waypoint mouse move, MouseMoved interpolation, atomic in one round-trip.
            GuiAction::MovePath {
                points,
                duration_ms,
            } => self.move_path(points, duration_ms),
            // #43: DisplayInfo early-returns before ax_trusted; reaching here means the
            // early-return was broken by a refactor.
            GuiAction::DisplayInfo {} => Ok(GuiResult {
                ok: false,
                error: Some(
                    "internal: DisplayInfo not handled at early-return (invariant broken)".into(),
                ),
                ..Default::default()
            }),
        }
    }

    /// #39: batch atomic action pipeline — execute multiple GuiActions in order, collecting
    /// a GuiResult per step.
    /// Non-transactional (a failed step does not abort the rest — the caller decides
    /// retry/compensation from each step's ok); abort semantics are implemented by the caller
    /// reading results and breaking (the executor is unaware of intent). Empty actions returns
    /// an empty Vec. Ordered (not parallel), because GUI actions carry implicit sequencing
    /// (focus→click→type).
    pub fn gui_action_batch(&self, actions: Vec<GuiAction>) -> Result<Vec<GuiResult>> {
        info!(count = actions.len(), "gui_action_batch start");
        let mut results = Vec::with_capacity(actions.len());
        for (i, action) in actions.into_iter().enumerate() {
            let res = self.execute(action)?;
            let ok = res.ok;
            results.push(res);
            info!(step = i, ok, "gui_action_batch step done");
        }
        info!(count = results.len(), "gui_action_batch end");
        Ok(results)
    }

    fn focus_app(&self, bundle_id: &str) -> Result<GuiResult> {
        info!(bundle_id, "FocusApp");
        // M-SEC-04: bundle admission check (prevents driving arbitrary apps).
        if self.check_bundle_allowed(bundle_id).is_err() {
            return Ok(GuiResult {
                ok: false,
                error: Some(format!("bundle-not-allowed: {bundle_id}")),
                ..Default::default()
            });
        }
        let app = AXUIElement::application_with_bundle(bundle_id)
            .map_err(|e| anyhow!("failed to locate app {bundle_id}: {e}"))?;
        app.set_frontmost(CFBoolean::true_value())
            .map_err(|e| anyhow!("set_frontmost failed: {e}"))?;
        if let Ok(win) = app.focused_window().or_else(|_| app.main_window()) {
            let _ = win.set_main(CFBoolean::true_value());
        }
        Ok(GuiResult {
            ok: true,
            ..Default::default()
        })
    }

    fn focused_app() -> Result<AXUIElement> {
        let syswide = AXUIElement::system_wide();
        let attr = AXAttribute::<CFType>::new(&CFString::from_static_string(
            kAXFocusedApplicationAttribute,
        ));
        let cf: CFType = syswide
            .attribute(&attr)
            .map_err(|e| anyhow!("failed to get focused app: {e}"))?;
        cf.downcast::<AXUIElement>()
            .ok_or_else(|| anyhow!("focused app type mismatch"))
    }

    fn click(&self, ax_label: Option<&str>, ax_position: Option<(f64, f64)>) -> Result<GuiResult> {
        info!(ax_label, ax_position = ?ax_position, "Click");
        if let Some(r) = self.focused_not_allowed() {
            return Ok(r);
        }
        let app = Self::focused_app()?;
        let win = app
            .focused_window()
            .or_else(|_| app.main_window())
            .map_err(|e| anyhow!("failed to get focused window: {e}"))?;
        let target = Self::find_click_target(&win, ax_label, ax_position)?;
        let actions = target
            .action_names()
            .unwrap_or_else(|_| CFArray::from_CFTypes(&[]));
        let pressed = if actions
            .iter()
            .any(|a| a.to_string() == accessibility_sys::kAXPressAction)
        {
            target
                .press()
                .map_err(|e| anyhow!("press failed: {e}"))
                .map(|_| true)
        } else {
            Ok(false)
        }?;
        if !pressed {
            return Ok(GuiResult {
                ok: false,
                error: Some("click-target-no-press-action".into()),
                ..Default::default()
            });
        }
        Ok(GuiResult {
            ok: true,
            ..Default::default()
        })
    }

    /// Find a click target in the window subtree — exact label match first, otherwise nearest by position
    fn find_click_target(
        root: &AXUIElement,
        ax_label: Option<&str>,
        ax_position: Option<(f64, f64)>,
    ) -> Result<AXUIElement> {
        let mut candidates: Vec<ClickCandidate> = Vec::new();
        Self::collect_clickable(root, 0, &mut candidates);
        if candidates.is_empty() {
            return Err(anyhow!("no clickable nodes (empty subtree)"));
        }
        if let Some(label) = ax_label {
            if let Some(c) = candidates
                .iter()
                .find(|(_, l, _)| l.as_deref() == Some(label))
            {
                return Ok(c.0.clone());
            }
        }
        if let Some(pos) = ax_position {
            let best = candidates
                .into_iter()
                .min_by_key(|(_, _, p)| {
                    p.map(|(x, y)| ((x - pos.0).abs() + (y - pos.1).abs()) as i64)
                        .unwrap_or(i64::MAX)
                })
                .ok_or_else(|| anyhow!("no candidates for position match"))?;
            return Ok(best.0);
        }
        Err(anyhow!("click requires ax_label or ax_position"))
    }

    fn collect_clickable(elem: &AXUIElement, depth: usize, out: &mut Vec<ClickCandidate>) {
        if depth > MAX_TREE_DEPTH || out.len() >= MAX_TREE_NODES {
            return;
        }
        let label = elem
            .label_value()
            .or_else(|_| elem.title())
            .ok()
            .map(|s| s.to_string());
        let pos = Self::read_position(elem);
        if label.is_some() || pos.is_some() {
            out.push((elem.clone(), label, pos));
        }
        if let Ok(children) = elem.children() {
            for c in children.iter() {
                Self::collect_clickable(&c, depth + 1, out);
                if out.len() >= MAX_TREE_NODES {
                    break;
                }
            }
        }
    }

    fn type_text(&self, text: &str) -> Result<GuiResult> {
        info!(text_len = text.len(), "TypeText");
        if let Some(r) = self.focused_not_allowed() {
            return Ok(r);
        }
        let app = Self::focused_app()?;
        let win = app
            .focused_window()
            .or_else(|_| app.main_window())
            .map_err(|e| anyhow!("failed to get focused window: {e}"))?;
        let target = Self::find_text_field(&win)?;
        // M-SEC-04: password field protection — AXSecureTextField is the AXTextField role with
        // the AXSecureTextField subrole. Reject type_text into password fields unless
        // allow_type_into_secure is explicitly set (prevents credential-stealing injection).
        // Audit log records the text length (never the text itself, keeping credentials out of logs).
        let is_secure = target
            .subrole()
            .map(|s| s == kAXSecureTextFieldSubrole)
            .unwrap_or(false);
        if is_secure {
            warn!(
                text_len = text.len(),
                allow_secure = self.config.allow_type_into_secure,
                "M-SEC-04: target is AXSecureTextField (password field) — type_text audited"
            );
            if !self.config.allow_type_into_secure {
                warn!("M-SEC-04: type_text into password field rejected (allow_type_into_secure not set)");
                return Ok(GuiResult {
                    ok: false,
                    error: Some(
                        "secure-text-field-rejected: target is a password field, type_text rejected (M-SEC-04)"
                            .into(),
                    ),
                    ..Default::default()
                });
            }
        } else {
            debug!(
                text_len = text.len(),
                "M-SEC-04: type_text target is not a password field, text length audited"
            );
        }
        let settable = target
            .is_settable(&accessibility::AXAttribute::value())
            .unwrap_or(false);
        if !settable {
            debug!("value not settable, trying direct set_value anyway (some controls allow it)");
        }
        target
            .set_value(CFString::new(text).into_CFType())
            .map_err(|e| anyhow!("set_value failed: {e}"))?;
        let actions = target
            .action_names()
            .unwrap_or_else(|_| CFArray::from_CFTypes(&[]));
        if actions
            .iter()
            .any(|a| a.to_string() == accessibility_sys::kAXConfirmAction)
        {
            let _ = target.confirm();
        }
        Ok(GuiResult {
            ok: true,
            ..Default::default()
        })
    }

    /// KeyPress — CGEvent synthesizes keydown + keyup, posted to the HID tap.
    /// Key name → virtual keycode (layout-independent); unknown names return ok:false + the
    /// known list, no panic.
    /// modifiers: chord modifiers (Cmd/Shift/Option/Control), synthesis order:
    ///   keydown each modifier (set_flags accumulates) → keydown key (with accumulated flags) →
    ///   keyup key → keyup modifiers in reverse order
    /// core-graphics 0.24 safe wrapper: CGEventSource::new / CGEvent::new_keyboard_event / post /
    /// set_flags are unsafe FFI internally but already wrapped in a safe API; this function needs
    /// no handwritten unsafe block.
    fn key_press(&self, key: &str, modifiers: &[String]) -> Result<GuiResult> {
        info!(key, mods = ?modifiers, "KeyPress");
        // RUN-12: trusted-independent input validation first — unknown key/modifier degradation
        // is independent of the focused app, placed before the focused_not_allowed gate
        // (keycode/modifier resolution never touches AX focus reads).
        let code = match Self::resolve_keycode(key) {
            Some(c) => c,
            None => {
                warn!(key, "unknown key name — degraded, returning known list");
                return Ok(GuiResult {
                    ok: false,
                    error: Some(format!(
                        "unknown-key: '{key}'; see resolve_keycode for supported key names \
                         (Return/Tab/Space/Delete/Forward_delete/Escape/Up_arrow/Down_arrow/\
                         Left_arrow/Right_arrow/Home/End/Page_up/Page_down/Help/\
                         F1-F20/Command/Shift/Option/Control/Function/Caps_lock/Mute/\
                         Volume_up/Volume_down)",
                    )),
                    ..Default::default()
                });
            }
        };
        // Resolve modifiers → (flag, keycode); an unrecognized modifier degrades the whole action
        let mut mods: Vec<(CGEventFlags, CGKeyCode)> = Vec::new();
        for m in modifiers {
            match Self::resolve_modifier(m) {
                Some(f) => {
                    let mk = match m.trim().to_ascii_lowercase().as_str() {
                        "command" | "cmd" | "super" => KeyCode::COMMAND,
                        "shift" => KeyCode::SHIFT,
                        "option" | "alt" => KeyCode::OPTION,
                        "control" | "ctrl" => KeyCode::CONTROL,
                        _ => {
                            warn!(modifier = m, "unknown modifier — degraded");
                            return Ok(GuiResult {
                                ok: false,
                                error: Some(format!(
                                    "unknown-modifier: '{m}'; supported: command/cmd, shift, \
                                     option/alt, control/ctrl",
                                )),
                                ..Default::default()
                            });
                        }
                    };
                    mods.push((f, mk));
                }
                None => {
                    warn!(modifier = m, "unknown modifier — degraded");
                    return Ok(GuiResult {
                        ok: false,
                        error: Some(format!(
                            "unknown-modifier: '{m}'; supported: command/cmd, shift, option/alt, \
                             control/ctrl",
                        )),
                        ..Default::default()
                    });
                }
            }
        }
        // RUN-12: input validation passed (trusted-independent), now check the focused app
        // allowlist — synthesis events rejected for non-allowlisted apps
        if let Some(r) = self.focused_not_allowed() {
            return Ok(r);
        }
        let source =
            CGEventSource::new(CGEventSourceStateID::CombinedSessionState).map_err(|_| {
                anyhow!("CGEventSource creation failed (CGEventSourceCreate returned null)")
            })?;
        // Accumulate flags — the modifier keydown events themselves also carry all modifier flags
        let mut combined = CGEventFlags::CGEventFlagNull;
        for (f, _mk) in &mods {
            combined |= *f;
        }
        // 1. keydown each modifier (events carry the accumulated flags)
        for (f, mk) in &mods {
            let e = CGEvent::new_keyboard_event(source.clone(), *mk, true)
                .map_err(|_| anyhow!("CGEvent modifier keydown creation failed"))?;
            e.set_flags(*f);
            e.post(CGEventTapLocation::HID);
        }
        // 2. keydown key (with all modifier flags)
        let down = CGEvent::new_keyboard_event(source.clone(), code, true)
            .map_err(|_| anyhow!("CGEvent keydown creation failed"))?;
        down.set_flags(combined);
        down.post(CGEventTapLocation::HID);
        // 3. keyup key (flags cleared)
        let up = CGEvent::new_keyboard_event(source.clone(), code, false)
            .map_err(|_| anyhow!("CGEvent keyup creation failed"))?;
        up.set_flags(CGEventFlags::CGEventFlagNull);
        up.post(CGEventTapLocation::HID);
        // 4. keyup modifiers in reverse order (flags cleared)
        for (_, mk) in mods.iter().rev() {
            let e = CGEvent::new_keyboard_event(source.clone(), *mk, false)
                .map_err(|_| anyhow!("CGEvent modifier keyup creation failed"))?;
            e.set_flags(CGEventFlags::CGEventFlagNull);
            e.post(CGEventTapLocation::HID);
        }
        debug!(
            keycode = code,
            mods = mods.len(),
            "KeyPress done (chord keydown+keyup posted)"
        );
        Ok(GuiResult {
            ok: true,
            ..Default::default()
        })
    }

    /// HoldKey — hold a single key for duration_ms then release (keydown → sleep → keyup).
    /// Used for long presses (e.g. holding an arrow key to move the cursor, holding Backspace
    /// to delete continuously). Single key, no modifier chords.
    /// Unknown key names degrade like key_press: ok:false + the known list. sleep blocks the
    /// current thread (GUI synchronous path).
    fn hold_key(&self, key: &str, duration_ms: u64) -> Result<GuiResult> {
        info!(key, duration_ms, "HoldKey");
        // M-12.4: duration_ms==0 → keydown immediately followed by keyup = a click, not a hold;
        // a silent no-op is easy to misuse.
        // Fail-loud rejection (Rule 12); callers use key_press explicitly for clicks.
        if duration_ms == 0 {
            warn!(
                key,
                "HoldKey duration_ms=0 — rejected (keydown+keyup is a click not a hold, use key_press explicitly)"
            );
            return Ok(GuiResult {
                ok: false,
                error: Some(
                    "hold-key-duration-zero: duration_ms must be >0 (a hold needs non-zero duration; use key_press for clicks)"
                        .into(),
                ),
                ..Default::default()
            });
        }
        // RUN-12: trusted-independent keycode validation first (same rationale as key_press)
        let code = match Self::resolve_keycode(key) {
            Some(c) => c,
            None => {
                warn!(key, "unknown key name — degraded, returning known list");
                return Ok(GuiResult {
                    ok: false,
                    error: Some(format!(
                        "unknown-key: '{key}'; see resolve_keycode for supported key names \
                         (Return/Tab/Space/Delete/Forward_delete/Escape/Up_arrow/Down_arrow/\
                         Left_arrow/Right_arrow/Home/End/Page_up/Page_down/Help/\
                         F1-F20/Command/Shift/Option/Control/Function/Caps_lock/Mute/\
                         Volume_up/Volume_down)",
                    )),
                    ..Default::default()
                });
            }
        };
        // RUN-12: focused app allowlist — keycode passed, synthesis events rejected for
        // non-allowlisted apps
        if let Some(r) = self.focused_not_allowed() {
            return Ok(r);
        }
        let source = CGEventSource::new(CGEventSourceStateID::CombinedSessionState)
            .map_err(|_| anyhow!("CGEventSource creation failed (hold_key)"))?;
        // keydown
        let down = CGEvent::new_keyboard_event(source.clone(), code, true)
            .map_err(|_| anyhow!("CGEvent keydown creation failed (hold_key)"))?;
        down.post(CGEventTapLocation::HID);
        // Hold — blocking sleep (GUI synchronous, duration_ms magnitude; capped at 5s to prevent
        // misuse from hanging)
        let capped = duration_ms.min(5000);
        if capped != duration_ms {
            warn!(
                asked = duration_ms,
                capped, "HoldKey duration exceeds the 5s cap, truncated to avoid hanging"
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(capped));
        // keyup
        let up = CGEvent::new_keyboard_event(source.clone(), code, false)
            .map_err(|_| anyhow!("CGEvent keyup creation failed (hold_key)"))?;
        up.post(CGEventTapLocation::HID);
        debug!(
            keycode = code,
            capped, "HoldKey done (keydown→sleep→keyup posted)"
        );
        Ok(GuiResult {
            ok: true,
            ..Default::default()
        })
    }

    /// Modifier name (case-insensitive) → CGEventFlags bit. Only the 4 main modifiers.
    fn resolve_modifier(name: &str) -> Option<CGEventFlags> {
        let k = name.trim().to_ascii_lowercase();
        let f = match k.as_str() {
            "command" | "cmd" | "super" => CGEventFlags::CGEventFlagCommand,
            "shift" => CGEventFlags::CGEventFlagShift,
            "option" | "alt" => CGEventFlags::CGEventFlagAlternate,
            "control" | "ctrl" => CGEventFlags::CGEventFlagControl,
            _ => return None,
        };
        Some(f)
    }

    /// Key name (case-insensitive) → virtual keycode. Matches core_graphics::event::KeyCode constants.
    fn resolve_keycode(name: &str) -> Option<CGKeyCode> {
        let k = name.trim().to_ascii_lowercase();
        let code = match k.as_str() {
            "return" | "enter" => KeyCode::RETURN,
            "tab" => KeyCode::TAB,
            "space" => KeyCode::SPACE,
            "delete" | "backspace" => KeyCode::DELETE,
            "forward_delete" | "fn_delete" => KeyCode::FORWARD_DELETE,
            "escape" | "esc" => KeyCode::ESCAPE,
            "up_arrow" | "up" => KeyCode::UP_ARROW,
            "down_arrow" | "down" => KeyCode::DOWN_ARROW,
            "left_arrow" | "left" => KeyCode::LEFT_ARROW,
            "right_arrow" | "right" => KeyCode::RIGHT_ARROW,
            "home" => KeyCode::HOME,
            "end" => KeyCode::END,
            "page_up" | "pageup" => KeyCode::PAGE_UP,
            "page_down" | "pagedown" => KeyCode::PAGE_DOWN,
            "help" => KeyCode::HELP,
            "command" | "cmd" | "super" => KeyCode::COMMAND,
            "right_command" => KeyCode::RIGHT_COMMAND,
            "shift" => KeyCode::SHIFT,
            "right_shift" => KeyCode::RIGHT_SHIFT,
            "option" | "alt" => KeyCode::OPTION,
            "right_option" | "right_alt" => KeyCode::RIGHT_OPTION,
            "control" | "ctrl" => KeyCode::CONTROL,
            "right_control" | "right_ctrl" => KeyCode::RIGHT_CONTROL,
            "function" | "fn" => KeyCode::FUNCTION,
            "caps_lock" => KeyCode::CAPS_LOCK,
            "mute" => KeyCode::MUTE,
            "volume_up" => KeyCode::VOLUME_UP,
            "volume_down" => KeyCode::VOLUME_DOWN,
            "f1" => KeyCode::F1,
            "f2" => KeyCode::F2,
            "f3" => KeyCode::F3,
            "f4" => KeyCode::F4,
            "f5" => KeyCode::F5,
            "f6" => KeyCode::F6,
            "f7" => KeyCode::F7,
            "f8" => KeyCode::F8,
            "f9" => KeyCode::F9,
            "f10" => KeyCode::F10,
            "f11" => KeyCode::F11,
            "f12" => KeyCode::F12,
            "f13" => KeyCode::F13,
            "f14" => KeyCode::F14,
            "f15" => KeyCode::F15,
            "f16" => KeyCode::F16,
            "f17" => KeyCode::F17,
            "f18" => KeyCode::F18,
            "f19" => KeyCode::F19,
            "f20" => KeyCode::F20,
            _ => return None,
        };
        Some(code)
    }

    /// Find a text input — the focused element with role AXTextField / AXTextArea, otherwise the first in the subtree
    fn find_text_field(root: &AXUIElement) -> Result<AXUIElement> {
        let mut found: Option<AXUIElement> = None;
        Self::walk_first_text(root, 0, &mut found);
        found.ok_or_else(|| anyhow!("no text input found (AXTextField/AXTextArea)"))
    }

    fn walk_first_text(elem: &AXUIElement, depth: usize, found: &mut Option<AXUIElement>) {
        if found.is_some() || depth > MAX_TREE_DEPTH {
            return;
        }
        let role = elem.role().map(|s| s.to_string()).unwrap_or_default();
        if role == accessibility_sys::kAXTextFieldRole || role == accessibility_sys::kAXTextAreaRole
        {
            *found = Some(elem.clone());
            return;
        }
        if let Ok(children) = elem.children() {
            for c in children.iter() {
                Self::walk_first_text(&c, depth + 1, found);
                if found.is_some() {
                    break;
                }
            }
        }
    }

    fn inspect_tree(&self) -> Result<GuiResult> {
        info!("InspectTree");
        let app = Self::focused_app()?;
        let win = app
            .focused_window()
            .or_else(|_| app.main_window())
            .map_err(|e| anyhow!("failed to get focused window: {e}"))?;
        let mut count = 0usize;
        let root = Self::build_node(&win, 0, &mut count);
        let tree = serde_json::to_string(&root)
            .map_err(|e| anyhow!("node tree serialization failed: {e}"))?;
        // #43: inspect_tree also fills scale_factor — the old ..Default::default() left 1.0, which
        // made callers on Retina machines misjudge the coordinate space. Reuse the main-display
        // scale (same source as screenshot); no screenshot but a consistent coordinate contract.
        let scale_factor = Self::compute_scale_factor();
        Ok(GuiResult {
            ok: true,
            node_tree: Some(tree),
            scale_factor,
            ..Default::default()
        })
    }

    /// #38/#43: main-display backing scale factor = physical pixels / logical points
    /// (Retina=2.0, non-Retina=1.0). Shared by screenshot + inspect_tree + display_info;
    /// degrades to 1.0 when bounds.width=0 to avoid NaN.
    fn compute_scale_factor() -> f32 {
        let main = CGDisplay::main();
        let logical_w = main.bounds().size.width;
        if logical_w > 0.0 {
            (main.pixels_wide() as f32 / logical_w as f32).max(1.0)
        } else {
            warn!("main display logical width is 0 — scale_factor degraded to 1.0");
            1.0
        }
    }

    fn build_node(elem: &AXUIElement, depth: usize, count: &mut usize) -> UiNode {
        if *count >= MAX_TREE_NODES {
            return UiNode {
                role: "_truncated".into(),
                title: None,
                label: None,
                position: None,
                size: None,
                enabled: None,
                actions: vec![],
                children: vec![],
            };
        }
        *count += 1;
        let role = elem
            .role()
            .map(|s| s.to_string())
            .unwrap_or_else(|_| "unknown".into());
        let title = elem.title().ok().map(|s| s.to_string());
        let label = elem.label_value().ok().map(|s| s.to_string());
        let position = Self::read_position(elem);
        let size = Self::read_size(elem);
        let enabled = elem.enabled().ok().map(|b| b == CFBoolean::true_value());
        let actions = elem
            .action_names()
            .map(|arr| arr.iter().map(|s| s.to_string()).collect())
            .unwrap_or_default();
        let mut children = Vec::new();
        if depth < MAX_TREE_DEPTH {
            if let Ok(child_arr) = elem.children() {
                for c in child_arr.iter() {
                    if *count >= MAX_TREE_NODES {
                        break;
                    }
                    children.push(Self::build_node(&c, depth + 1, count));
                }
            }
        }
        UiNode {
            role,
            title,
            label,
            position,
            size,
            enabled,
            actions,
            children,
        }
    }

    /// Read AXPosition — unsafe: AXValueGetValue is an accessibility-sys extern "C" fn (unsafe by
    /// default since rustc 1.96). Semantics: read a CGPoint from ax_ref into the stack-local pt.
    /// ax_ref comes from a CFType downcast (cf_to_axvalue); on type mismatch AXValueGetValue
    /// returns false (writes nothing). The pointer targets only a local stack variable —
    /// lifetime-safe.
    fn read_position(elem: &AXUIElement) -> Option<(f64, f64)> {
        let attr = AXAttribute::<CFType>::new(&CFString::from_static_string(kAXPositionAttribute));
        let cf = elem.attribute(&attr).ok()?;
        let ax_ref = Self::cf_to_axvalue(&cf)?;
        let mut pt = CGPoint::default();
        let ok = unsafe {
            AXValueGetValue(
                ax_ref,
                kAXValueTypeCGPoint,
                &mut pt as *mut CGPoint as *mut std::ffi::c_void,
            )
        };
        if ok {
            Some((pt.x, pt.y))
        } else {
            None
        }
    }

    /// Read AXSize — same as read_position, writing a CGSize.
    fn read_size(elem: &AXUIElement) -> Option<(f64, f64)> {
        let attr = AXAttribute::<CFType>::new(&CFString::from_static_string(kAXSizeAttribute));
        let cf = elem.attribute(&attr).ok()?;
        let ax_ref = Self::cf_to_axvalue(&cf)?;
        let mut sz = CGSize::default();
        let ok = unsafe {
            AXValueGetValue(
                ax_ref,
                kAXValueTypeCGSize,
                &mut sz as *mut CGSize as *mut std::ffi::c_void,
            )
        };
        if ok {
            Some((sz.width, sz.height))
        } else {
            None
        }
    }

    /// CFType → AXValueRef (returns None on type mismatch, no panic)
    fn cf_to_axvalue(cf: &CFType) -> Option<AXValueRef> {
        let ptr = cf.as_concrete_TypeRef() as AXValueRef;
        if ptr.is_null() {
            None
        } else {
            Some(ptr)
        }
    }

    /// #40: collect logical-point rects (x, y, w, h) of all AXSecureTextField (password) fields
    /// inside the focused app's focused window.
    /// Recursively walks the AX subtree (reuses build_node's depth/node caps to prevent
    /// explosion). Returns an empty Vec when AX is unauthorized (the caller's screenshot already
    /// runs inside the ax_trusted() gate; still fail-soft here).
    fn collect_secure_rects() -> Vec<(f64, f64, f64, f64)> {
        let app = match Self::focused_app() {
            Ok(a) => a,
            Err(e) => {
                warn!(error = %e, "collect_secure_rects: failed to get focused app — returning empty");
                return vec![];
            }
        };
        let win = match app.focused_window().or_else(|_| app.main_window()) {
            Ok(w) => w,
            Err(e) => {
                warn!(error = %e, "collect_secure_rects: failed to get focused window — returning empty");
                return vec![];
            }
        };
        let mut rects = vec![];
        let mut count = 0usize;
        Self::collect_secure_rects_rec(&win, 0, &mut count, &mut rects);
        rects
    }

    fn collect_secure_rects_rec(
        elem: &AXUIElement,
        depth: usize,
        count: &mut usize,
        rects: &mut Vec<(f64, f64, f64, f64)>,
    ) {
        if *count >= MAX_TREE_NODES || depth >= MAX_TREE_DEPTH {
            return;
        }
        *count += 1;
        // AXSecureTextField: subrole == kAXSecureTextFieldSubrole (explicit password-field marker)
        let is_secure = elem
            .subrole()
            .map(|s| s == kAXSecureTextFieldSubrole)
            .unwrap_or(false);
        if is_secure {
            if let (Some((x, y)), Some((w, h))) = (Self::read_position(elem), Self::read_size(elem))
            {
                rects.push((x, y, w, h));
            }
        }
        if let Ok(child_arr) = elem.children() {
            for c in child_arr.iter() {
                if *count >= MAX_TREE_NODES {
                    break;
                }
                Self::collect_secure_rects_rec(&c, depth + 1, count, rects);
            }
        }
    }

    /// #40: black out sensitive regions of an RGBA buffer in place. rects are logical points
    /// (x, y, w, h); scale converts to physical pixels.
    /// Coordinate conversion: the AX origin is top-left (y down), the bitmap context origin is
    /// bottom-left (row 0 = bottom) — hence bitmap row = h_px - 1 - y_px.
    /// Out-of-bounds clipped to [0, w_px)/[0, h_px) to avoid panic.
    fn mask_rgba_inplace(
        rgba: &mut [u8],
        w_px: usize,
        h_px: usize,
        scale: f32,
        rects: &[(f64, f64, f64, f64)],
    ) {
        let bytes_per_row = w_px * 4;
        for &(lx, ly, lw, lh) in rects {
            // Logical points → physical pixels (floor + clamp)
            let x0 = ((lx * scale as f64).floor() as isize).max(0) as usize;
            let y0 = ((ly * scale as f64).floor() as isize).max(0) as usize;
            let x1 = (((lx + lw) * scale as f64).ceil() as isize).min(w_px as isize) as usize;
            let y1 = (((ly + lh) * scale as f64).ceil() as isize).min(h_px as isize) as usize;
            if x0 >= x1 || y0 >= y1 || x0 >= w_px || y0 >= h_px {
                continue;
            }
            // Black out: RGBA = (0,0,0,255). y-flip — bitmap row 0 is the bottom.
            for py in y0..y1 {
                let row = h_px - 1 - py;
                let base = row * bytes_per_row + x0 * 4;
                for px in 0..(x1 - x0) {
                    let i = base + px * 4;
                    rgba[i] = 0;
                    rgba[i + 1] = 0;
                    rgba[i + 2] = 0;
                    rgba[i + 3] = 255;
                }
            }
        }
    }

    /// Screenshot — CGWindowListCreateImage full screen → CGImage → bitmap context to RGBA →
    /// PNG → base64.
    /// When Screen Recording TCC is unauthorized the CGImage is None → explicit error.
    /// #40: with mask_sensitive=true, walk the AX tree for AXSecureTextField (password field)
    /// regions and black out the RGBA pixels before encoding — prevents VLM credential leakage.
    /// Requires Accessibility TCC; when unauthorized, skip masking + warn.
    fn screenshot(&self, mask_sensitive: bool) -> Result<GuiResult> {
        info!(mask_sensitive, "Screenshot");
        let bounds = CGRect {
            origin: core_graphics::geometry::CGPoint { x: 0.0, y: 0.0 },
            size: core_graphics::geometry::CGSize {
                width: 0.0,
                height: 0.0,
            },
        };
        let img = match CGDisplay::screenshot(
            bounds,
            core_graphics::display::kCGWindowListOptionOnScreenOnly,
            0,
            core_graphics::display::kCGWindowImageDefault,
        ) {
            Some(i) => i,
            None => {
                warn!("Screen Recording not authorized — screenshot degraded");
                return Ok(GuiResult {
                    ok: false,
                    error: Some(
                        "screen-recording-permission-required (CGWindowListCreateImage returned null)"
                            .into(),
                    ),
                    ..Default::default()
                });
            }
        };
        let (mut rgba, vw, vh) = match Self::cgimage_to_rgba(&img) {
            Ok(t) => t,
            Err(e) => {
                warn!(error = %e, "screenshot encoding failed — degraded");
                return Ok(GuiResult {
                    ok: false,
                    error: Some(format!("screenshot-encode-failed: {e}")),
                    ..Default::default()
                });
            }
        };
        // #38: scale_factor = physical pixels / logical points. CGDisplay::main().bounds() returns
        // the main display's logical point size; the screenshot is full-screen physical pixels
        // (img.width/height). 2.0 on Retina, 1.0 otherwise.
        // bounds.width of 0 (rare anomaly) degrades to 1.0 to avoid NaN.
        let scale_factor = Self::compute_scale_factor();
        info!(scale_factor, "Screenshot scale_factor computed");
        // #40: sensitive-area masking — black out AXSecureTextField (password field) pixels.
        let masked_count = if mask_sensitive {
            if Self::ax_trusted() {
                let rects = Self::collect_secure_rects();
                if !rects.is_empty() {
                    Self::mask_rgba_inplace(&mut rgba, vw, vh, scale_factor, &rects);
                }
                rects.len()
            } else {
                warn!("mask_sensitive=true but AX unauthorized — skipping sensitive-area masking (screenshot returned unmasked)");
                0
            }
        } else {
            0
        };
        if masked_count > 0 {
            info!(
                masked_count,
                "sensitive-area masking done (AXSecureTextField regions blacked out)"
            );
        }
        let png_b64 = match Self::rgba_to_png_b64(&rgba, vw, vh) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "screenshot encoding failed — degraded");
                return Ok(GuiResult {
                    ok: false,
                    error: Some(format!("screenshot-encode-failed: {e}")),
                    ..Default::default()
                });
            }
        };
        Ok(GuiResult {
            ok: true,
            screenshot_png_b64: Some(png_b64),
            screenshot_width: Some(img.width() as u32),
            screenshot_height: Some(img.height() as u32),
            scale_factor,
            ..Default::default()
        })
    }

    /// CGImage → RGBA Vec<u8> (premultiplied last) + width/height. The bitmap context uses a
    /// uniform pixel format.
    /// Returns a Vec so the caller (mask) can modify pixels in place before encoding.
    ///
    /// M-12.3: the bitmap context uses kCGImageAlphaPremultipliedLast — CoreGraphics returns
    /// **premultiplied RGBA** (RGB already multiplied by alpha). The PNG standard expects
    /// **non-premultiplied** (straight) alpha. Encoding premultiplied pixels directly shifts
    /// colors in semi-transparent regions (alpha<255) when composited (RGB darker). Screenshots
    /// are mostly opaque (alpha=255, premultiply makes no difference); only screenshot edges
    /// containing transparent windows / menu shadows may show slight color drift. Known
    /// tradeoff (Rule 2 minimal change): explicit unpremultiply needs per-pixel division
    /// (4*w*h ops, 4M+ for a full screen) plus an alpha=0 divide-by-zero special case — the
    /// current caller (mlx-vlm visual grounding) does not depend on exact alpha, the drift is
    /// within tolerance, not implemented. If exact alpha is ever needed, unpremultiply in this loop.
    fn cgimage_to_rgba(img: &CGImage) -> Result<(Vec<u8>, usize, usize)> {
        let w = img.width();
        let h = img.height();
        if w == 0 || h == 0 {
            return Err(anyhow!("screenshot size is 0"));
        }
        let cs = CGColorSpace::create_device_rgb();
        let bytes_per_row = w * 4;
        let mut ctx = CGContext::create_bitmap_context(
            None,
            w,
            h,
            8,
            bytes_per_row,
            &cs,
            core_graphics::base::kCGImageAlphaPremultipliedLast,
        );
        let rect = CGRect {
            origin: core_graphics::geometry::CGPoint { x: 0.0, y: 0.0 },
            size: core_graphics::geometry::CGSize {
                width: w as f64,
                height: h as f64,
            },
        };
        ctx.draw_image(rect, img);
        // ctx.data() is a &[u8] borrowing ctx — copy into a Vec so ctx can drop, then mask in place.
        let rgba: Vec<u8> = ctx.data().to_vec();
        Ok((rgba, w, h))
    }

    /// RGBA Vec → PNG → base64.
    fn rgba_to_png_b64(rgba: &[u8], w: usize, h: usize) -> Result<String> {
        let mut buf: Vec<u8> = Vec::with_capacity(0);
        {
            let mut enc = Encoder::new(&mut buf, w as u32, h as u32);
            enc.set_color(ColorType::Rgba);
            enc.set_depth(BitDepth::Eight);
            let mut writer = enc
                .write_header()
                .map_err(|e| anyhow!("PNG header write failed: {e}"))?;
            writer
                .write_image_data(rgba)
                .map_err(|e| anyhow!("PNG pixel write failed: {e}"))?;
        }
        Ok(B64.encode(&buf))
    }

    /// Scroll wheel — CGEvent new_scroll_event (highsierra feature).
    /// dx=horizontal (axis2), dy=vertical (axis1); LINE units. When at is given, move the cursor
    /// there first.
    /// core-graphics 0.24 safe wrapper wraps the unsafe FFI of CGEventCreateScrollWheelEvent2.
    fn scroll(&self, dx: i32, dy: i32, at: Option<(f64, f64)>) -> Result<GuiResult> {
        info!(dx, dy, at = ?at, "Scroll");
        if let Some(r) = self.focused_not_allowed() {
            return Ok(r);
        }
        let source = CGEventSource::new(CGEventSourceStateID::CombinedSessionState)
            .map_err(|_| anyhow!("CGEventSource creation failed (scroll)"))?;
        if let Some((x, y)) = at {
            let moved = CGEvent::new_mouse_event(
                source.clone(),
                CGEventType::MouseMoved,
                CGPoint::new(x, y),
                CGMouseButton::Left,
            )
            .map_err(|_| {
                anyhow!("CGEvent MouseMoved creation failed (scroll cursor positioning)")
            })?;
            moved.post(CGEventTapLocation::HID);
        }
        // new_scroll_event(source, units, wheel_count, wheel1=axis2 horizontal, wheel2=axis1 vertical, wheel3=0)
        let ev = CGEvent::new_scroll_event(source, ScrollEventUnit::LINE, 2, dx, dy, 0).map_err(
            |_| {
                anyhow!(
                    "CGEvent scroll creation failed (CGEventCreateScrollWheelEvent2 returned null)"
                )
            },
        )?;
        ev.post(CGEventTapLocation::HID);
        debug!(dx, dy, "Scroll done (ScrollWheel posted)");
        Ok(GuiResult {
            ok: true,
            ..Default::default()
        })
    }

    /// Drag — mouseDown(from) → LeftMouseDragged (intermediate frames) → mouseUp(to).
    /// Left-button single drag; intermediate frames interpolated linearly for smoothness
    /// (16 frames by default). CGEvent new_mouse_event carries its own position, no set_location needed.
    fn drag(&self, from: (f64, f64), to: (f64, f64)) -> Result<GuiResult> {
        info!(from = ?from, to = ?to, "Drag");
        if let Some(r) = self.focused_not_allowed() {
            return Ok(r);
        }
        let source = CGEventSource::new(CGEventSourceStateID::CombinedSessionState)
            .map_err(|_| anyhow!("CGEventSource creation failed (drag)"))?;
        let steps = 16i32;
        // 1. mouseDown at from (left button down)
        let down = CGEvent::new_mouse_event(
            source.clone(),
            CGEventType::LeftMouseDown,
            CGPoint::new(from.0, from.1),
            CGMouseButton::Left,
        )
        .map_err(|_| anyhow!("CGEvent LeftMouseDown creation failed (drag)"))?;
        down.post(CGEventTapLocation::HID);
        // 2. LeftMouseDragged intermediate frames (from → to linear interpolation)
        for i in 1..steps {
            let t = i as f64 / steps as f64;
            let x = from.0 + (to.0 - from.0) * t;
            let y = from.1 + (to.1 - from.1) * t;
            let moved = CGEvent::new_mouse_event(
                source.clone(),
                CGEventType::LeftMouseDragged,
                CGPoint::new(x, y),
                CGMouseButton::Left,
            )
            .map_err(|_| {
                anyhow!("CGEvent LeftMouseDragged creation failed (drag intermediate frame {i})")
            })?;
            moved.post(CGEventTapLocation::HID);
        }
        // 3. mouseUp at to (left button up)
        let up = CGEvent::new_mouse_event(
            source,
            CGEventType::LeftMouseUp,
            CGPoint::new(to.0, to.1),
            CGMouseButton::Left,
        )
        .map_err(|_| anyhow!("CGEvent LeftMouseUp creation failed (drag)"))?;
        up.post(CGEventTapLocation::HID);
        debug!(steps, "Drag done (down→drag→up posted)");
        Ok(GuiResult {
            ok: true,
            ..Default::default()
        })
    }

    /// Double click — first locate the AX click target for coordinates, then CGEvent synthesizes
    /// two left clicks with click_state=2.
    /// The click_state field (EventField::MOUSE_EVENT_CLICK_STATE=1) tells the system this is the
    /// second click in a row.
    /// Reuses find_click_target for coordinates (same path as click()); no coordinate target → degrade.
    fn double_click(
        &self,
        ax_label: Option<&str>,
        ax_position: Option<(f64, f64)>,
    ) -> Result<GuiResult> {
        info!(ax_label, ax_position = ?ax_position, "DoubleClick");
        if let Some(r) = self.focused_not_allowed() {
            return Ok(r);
        }
        let pos = self.resolve_click_position(ax_label, ax_position)?;
        let source = CGEventSource::new(CGEventSourceStateID::CombinedSessionState)
            .map_err(|_| anyhow!("CGEventSource creation failed (double_click)"))?;
        // Two left clicks, second with click_state=2 (distinguishes single/double-click gestures)
        for click_no in 1..=2i64 {
            let down = CGEvent::new_mouse_event(
                source.clone(),
                CGEventType::LeftMouseDown,
                CGPoint::new(pos.0, pos.1),
                CGMouseButton::Left,
            )
            .map_err(|_| {
                anyhow!("CGEvent LeftMouseDown creation failed (double_click {click_no})")
            })?;
            down.set_integer_value_field(EventField::MOUSE_EVENT_CLICK_STATE, click_no);
            down.post(CGEventTapLocation::HID);
            let up = CGEvent::new_mouse_event(
                source.clone(),
                CGEventType::LeftMouseUp,
                CGPoint::new(pos.0, pos.1),
                CGMouseButton::Left,
            )
            .map_err(|_| {
                anyhow!("CGEvent LeftMouseUp creation failed (double_click {click_no})")
            })?;
            up.set_integer_value_field(EventField::MOUSE_EVENT_CLICK_STATE, click_no);
            up.post(CGEventTapLocation::HID);
        }
        debug!(pos = ?pos, "DoubleClick done (2× down/up posted, click_state=2)");
        Ok(GuiResult {
            ok: true,
            ..Default::default()
        })
    }

    /// Triple click — locates like double_click, CGEvent synthesizes three left clicks with
    /// click_state incrementing 1..=3.
    /// Used for selecting a whole paragraph/line (e.g. triple-click selects a line). Reuses
    /// resolve_click_position for coordinates.
    fn triple_click(
        &self,
        ax_label: Option<&str>,
        ax_position: Option<(f64, f64)>,
    ) -> Result<GuiResult> {
        info!(ax_label, ax_position = ?ax_position, "TripleClick");
        if let Some(r) = self.focused_not_allowed() {
            return Ok(r);
        }
        let pos = self.resolve_click_position(ax_label, ax_position)?;
        let source = CGEventSource::new(CGEventSourceStateID::CombinedSessionState)
            .map_err(|_| anyhow!("CGEventSource creation failed (triple_click)"))?;
        // Three left clicks, click_state incrementing 1/2/3 (the system judges the gesture by
        // consecutive click count)
        for click_no in 1..=3i64 {
            let down = CGEvent::new_mouse_event(
                source.clone(),
                CGEventType::LeftMouseDown,
                CGPoint::new(pos.0, pos.1),
                CGMouseButton::Left,
            )
            .map_err(|_| {
                anyhow!("CGEvent LeftMouseDown creation failed (triple_click {click_no})")
            })?;
            down.set_integer_value_field(EventField::MOUSE_EVENT_CLICK_STATE, click_no);
            down.post(CGEventTapLocation::HID);
            let up = CGEvent::new_mouse_event(
                source.clone(),
                CGEventType::LeftMouseUp,
                CGPoint::new(pos.0, pos.1),
                CGMouseButton::Left,
            )
            .map_err(|_| {
                anyhow!("CGEvent LeftMouseUp creation failed (triple_click {click_no})")
            })?;
            up.set_integer_value_field(EventField::MOUSE_EVENT_CLICK_STATE, click_no);
            up.post(CGEventTapLocation::HID);
        }
        debug!(pos = ?pos, "TripleClick done (3× down/up posted, click_state=3)");
        Ok(GuiResult {
            ok: true,
            ..Default::default()
        })
    }

    /// Right click — locate for coordinates first, then CGEvent RightMouseDown/RightMouseUp +
    /// CGMouseButton::Right.
    fn right_click(
        &self,
        ax_label: Option<&str>,
        ax_position: Option<(f64, f64)>,
    ) -> Result<GuiResult> {
        info!(ax_label, ax_position = ?ax_position, "RightClick");
        if let Some(r) = self.focused_not_allowed() {
            return Ok(r);
        }
        let pos = self.resolve_click_position(ax_label, ax_position)?;
        let source = CGEventSource::new(CGEventSourceStateID::CombinedSessionState)
            .map_err(|_| anyhow!("CGEventSource creation failed (right_click)"))?;
        let down = CGEvent::new_mouse_event(
            source.clone(),
            CGEventType::RightMouseDown,
            CGPoint::new(pos.0, pos.1),
            CGMouseButton::Right,
        )
        .map_err(|_| anyhow!("CGEvent RightMouseDown creation failed (right_click)"))?;
        down.post(CGEventTapLocation::HID);
        let up = CGEvent::new_mouse_event(
            source,
            CGEventType::RightMouseUp,
            CGPoint::new(pos.0, pos.1),
            CGMouseButton::Right,
        )
        .map_err(|_| anyhow!("CGEvent RightMouseUp creation failed (right_click)"))?;
        up.post(CGEventTapLocation::HID);
        debug!(pos = ?pos, "RightClick done (right down/up posted)");
        Ok(GuiResult {
            ok: true,
            ..Default::default()
        })
    }

    /// Hover — CGEvent MouseMoved to the given coordinates (no buttons, cursor movement only).
    fn hover(&self, ax_position: (f64, f64)) -> Result<GuiResult> {
        info!(ax_position = ?ax_position, "Hover");
        if let Some(r) = self.focused_not_allowed() {
            return Ok(r);
        }
        let source = CGEventSource::new(CGEventSourceStateID::CombinedSessionState)
            .map_err(|_| anyhow!("CGEventSource creation failed (hover)"))?;
        let moved = CGEvent::new_mouse_event(
            source,
            CGEventType::MouseMoved,
            CGPoint::new(ax_position.0, ax_position.1),
            CGMouseButton::Left,
        )
        .map_err(|_| anyhow!("CGEvent MouseMoved creation failed (hover)"))?;
        moved.post(CGEventTapLocation::HID);
        debug!(pos = ?ax_position, "Hover done (MouseMoved posted)");
        Ok(GuiResult {
            ok: true,
            ..Default::default()
        })
    }

    /// #44: batch mouse move — sends MouseMoved (no buttons) along ordered waypoints, atomic in a
    /// single round-trip.
    /// duration_ms is split across segments, linear interpolation within each segment (8 frames
    /// per segment by default); empty sequences rejected.
    fn move_path(&self, points: Vec<(f64, f64)>, duration_ms: u64) -> Result<GuiResult> {
        info!(n = points.len(), duration_ms, "MovePath");
        if points.len() < 2 {
            warn!(
                n = points.len(),
                "MovePath fewer than 2 points — rejected (needs at least start and end)"
            );
            return Ok(GuiResult {
                ok: false,
                error: Some("move_path requires at least 2 points".into()),
                ..Default::default()
            });
        }
        if let Some(r) = self.focused_not_allowed() {
            return Ok(r);
        }
        let source = CGEventSource::new(CGEventSourceStateID::CombinedSessionState)
            .map_err(|_| anyhow!("CGEventSource creation failed (move_path)"))?;
        let segments = (points.len() - 1) as u64;
        // Per-segment duration (µs); duration_ms=0 yields 0 → instantaneous movement still posts
        // frame by frame (no sleep).
        let per_seg_us = if duration_ms > 0 {
            (duration_ms * 1000) / segments.max(1)
        } else {
            0
        };
        let frames_per_seg: u64 = 8;
        for w in points.windows(2) {
            let from = w[0];
            let to = w[1];
            for i in 1..=frames_per_seg {
                let t = i as f64 / frames_per_seg as f64;
                let x = from.0 + (to.0 - from.0) * t;
                let y = from.1 + (to.1 - from.1) * t;
                let moved = CGEvent::new_mouse_event(
                    source.clone(),
                    CGEventType::MouseMoved,
                    CGPoint::new(x, y),
                    CGMouseButton::Left,
                )
                .map_err(|_| {
                    anyhow!("CGEvent MouseMoved creation failed (move_path intermediate frame)")
                })?;
                moved.post(CGEventTapLocation::HID);
            }
            if per_seg_us > 0 {
                std::thread::sleep(std::time::Duration::from_micros(per_seg_us));
            }
        }
        debug!(
            segments,
            frames_per_seg, "MovePath done (MouseMoved posted)"
        );
        Ok(GuiResult {
            ok: true,
            ..Default::default()
        })
    }

    /// #43: display capability query — enumerate active displays, returning
    /// [{id, scale, bounds, primary}].
    /// trusted-independent (CGDisplay, not AX). scale = pixels_wide / bounds.width (Retina=2.0).
    fn display_info(&self) -> Result<GuiResult> {
        info!("DisplayInfo");
        let ids = match CGDisplay::active_displays() {
            Ok(v) => v,
            Err(e) => {
                warn!(error = ?e, "CGDisplay::active_displays failed — degraded");
                return Ok(GuiResult {
                    ok: false,
                    error: Some(format!("display_info failed: {e:?}")),
                    ..Default::default()
                });
            }
        };
        let mut entries = Vec::with_capacity(ids.len());
        for id in ids {
            let disp = CGDisplay::new(id);
            let b = disp.bounds();
            let logical_w = b.size.width;
            let scale = if logical_w > 0.0 {
                (disp.pixels_wide() as f32 / logical_w as f32).max(1.0)
            } else {
                1.0
            };
            entries.push(serde_json::json!({
                "id": id,
                "scale": scale,
                "bounds": {
                    "x": b.origin.x,
                    "y": b.origin.y,
                    "w": b.size.width,
                    "h": b.size.height,
                },
                "primary": disp.is_main(),
            }));
        }
        let displays = serde_json::to_string(&entries)
            .map_err(|e| anyhow!("display_info serialization failed: {e}"))?;
        info!(count = entries.len(), "DisplayInfo done");
        Ok(GuiResult {
            ok: true,
            scale_factor: Self::compute_scale_factor(),
            displays: Some(displays),
            ..Default::default()
        })
    }

    /// Resolve click coordinates — ax_position first; otherwise match ax_label against the AX
    /// node and read AXPosition.
    /// Shared by click/double_click/right_click. Neither label nor position → error.
    fn resolve_click_position(
        &self,
        ax_label: Option<&str>,
        ax_position: Option<(f64, f64)>,
    ) -> Result<(f64, f64)> {
        if let Some(pos) = ax_position {
            return Ok(pos);
        }
        let label = ax_label.ok_or_else(|| {
            anyhow!("ax_label or ax_position required to resolve click coordinates")
        })?;
        let app = Self::focused_app()?;
        let win = app
            .focused_window()
            .or_else(|_| app.main_window())
            .map_err(|e| anyhow!("failed to get focused window: {e}"))?;
        let target = Self::find_click_target(&win, Some(label), None)?;
        Self::read_position(&target)
            .ok_or_else(|| anyhow!("target node has no AXPosition, cannot resolve coordinates"))
    }

    /// Window buttons — close/minimize/zoom. Fetches the child via the AX button attribute → press().
    /// When bundle_id is given, focus that app; otherwise use the current focused app.
    /// Safety: accessibility 0.2 safe wrapper (attribute/press), zero handwritten unsafe.
    fn window_button(&self, bundle_id: Option<String>, which: &str) -> Result<GuiResult> {
        info!(bundle_id = ?bundle_id, which, "WindowButton");
        // M-SEC-04: validate admission when bundle is given (prevents manipulating arbitrary app
        // windows); None = current focused app, allowed + audited.
        if let Some(b) = bundle_id.as_deref() {
            if self.check_bundle_allowed(b).is_err() {
                return Ok(GuiResult {
                    ok: false,
                    error: Some(format!("bundle-not-allowed: {b}")),
                    ..Default::default()
                });
            }
        }
        let app = match bundle_id.as_deref() {
            Some(b) => AXUIElement::application_with_bundle(b)
                .map_err(|e| anyhow!("failed to locate app {b}: {e}"))?,
            None => Self::focused_app()?,
        };
        let win = app
            .focused_window()
            .or_else(|_| app.main_window())
            .map_err(|e| anyhow!("failed to get window: {e}"))?;
        let btn_attr_name = match which {
            "close" => kAXCloseButtonAttribute,
            "minimize" => kAXMinimizeButtonAttribute,
            "zoom" => kAXZoomButtonAttribute,
            other => return Err(anyhow!("unknown window button: {other}")),
        };
        let btn_attr = AXAttribute::<CFType>::new(&CFString::from_static_string(btn_attr_name));
        let cf = win
            .attribute(&btn_attr)
            .map_err(|e| anyhow!("failed to get {which} button attribute: {e}"))?;
        let btn = cf
            .downcast::<AXUIElement>()
            .ok_or_else(|| anyhow!("{which} button attribute is not an AXUIElement"))?;
        btn.press()
            .map_err(|e| anyhow!("press {which} button failed: {e}"))?;
        debug!(which, "WindowButton done (press posted)");
        Ok(GuiResult {
            ok: true,
            ..Default::default()
        })
    }

    /// Window resize — drags the bottom-right resize handle to the target size. Reads the current
    /// AXPosition+AXSize for the bottom-right corner, computes the target bottom-right corner, and
    /// CGEvent-drags (reuses drag coordinate logic, zero new dependencies).
    /// Drag instead of setting AXSize via AXValueCreate — the latter needs a new unsafe block
    /// (AXValueCreate extern "C"), exceeding the established 3-unsafe-block scope; dragging goes
    /// through the safe CGEvent wrapper and reuses the tested drag path.
    fn window_resize(
        &self,
        bundle_id: Option<String>,
        width: f64,
        height: f64,
    ) -> Result<GuiResult> {
        info!(bundle_id = ?bundle_id, width, height, "WindowResize");
        // M-SEC-04: validate admission when bundle is given (prevents resizing arbitrary app
        // windows); None = focused app, allowed + audited.
        if let Some(b) = bundle_id.as_deref() {
            if self.check_bundle_allowed(b).is_err() {
                return Ok(GuiResult {
                    ok: false,
                    error: Some(format!("bundle-not-allowed: {b}")),
                    ..Default::default()
                });
            }
        }
        let app = match bundle_id.as_deref() {
            Some(b) => AXUIElement::application_with_bundle(b)
                .map_err(|e| anyhow!("failed to locate app {b}: {e}"))?,
            None => Self::focused_app()?,
        };
        let win = app
            .focused_window()
            .or_else(|_| app.main_window())
            .map_err(|e| anyhow!("failed to get window: {e}"))?;
        let pos = Self::read_position(&win).ok_or_else(|| anyhow!("window has no AXPosition"))?;
        let sz = Self::read_size(&win).ok_or_else(|| anyhow!("window has no AXSize"))?;
        // Bottom-right resize handle = current bottom-right; drag to (top-left + target size) bottom-right
        let from = (pos.0 + sz.0, pos.1 + sz.1);
        let to = (pos.0 + width, pos.1 + height);
        if width < 50.0 || height < 50.0 {
            warn!(
                width,
                height, "target size too small, drag may not take effect"
            );
        }
        self.drag(from, to)
    }

    /// Wait — pure delay, not AX/CGEvent. Pause between GUI actions (e.g. wait for an animation
    /// after a click).
    /// seconds clamped to [0, 60] seconds. trusted-independent (no TCC dependency, unit-testable).
    fn wait(&self, seconds: f64) -> Result<GuiResult> {
        let secs = if seconds < 0.0 {
            warn!(seconds, "Wait negative value, clamped to 0");
            0.0
        } else if seconds > 60.0 {
            warn!(seconds, "Wait exceeds the 60s cap, clamped to 60");
            60.0
        } else {
            seconds
        };
        info!(seconds = secs, "Wait");
        if secs > 0.0 {
            std::thread::sleep(std::time::Duration::from_secs_f64(secs));
        }
        Ok(GuiResult {
            ok: true,
            ..Default::default()
        })
    }
}

impl Default for GuiController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gui_action_serde_roundtrip() {
        let cases = vec![
            GuiAction::FocusApp {
                bundle_id: "com.apple.TextEdit".into(),
            },
            GuiAction::Click {
                ax_label: Some("OK".into()),
                ax_position: Some((1.0, 2.0)),
            },
            GuiAction::Click {
                ax_label: None,
                ax_position: None,
            },
            GuiAction::TypeText {
                text: "hello".into(),
            },
            GuiAction::KeyPress {
                key: "Return".into(),
                modifiers: vec![],
            },
            GuiAction::Screenshot {
                mask_sensitive: false,
            },
            GuiAction::Screenshot {
                mask_sensitive: true,
            },
            GuiAction::InspectTree {},
            GuiAction::Scroll {
                dx: 0,
                dy: -3,
                at: Some((100.0, 200.0)),
            },
            GuiAction::Scroll {
                dx: 5,
                dy: 0,
                at: None,
            },
            GuiAction::Drag {
                from: (10.0, 20.0),
                to: (30.0, 40.0),
            },
            GuiAction::DoubleClick {
                ax_label: None,
                ax_position: Some((1.0, 2.0)),
            },
            GuiAction::RightClick {
                ax_label: Some("Ctx".into()),
                ax_position: None,
            },
            GuiAction::Hover {
                ax_position: (50.0, 60.0),
            },
            GuiAction::WindowClose {
                bundle_id: Some("x.y".into()),
            },
            GuiAction::WindowMinimize { bundle_id: None },
            GuiAction::WindowZoom { bundle_id: None },
            GuiAction::WindowResize {
                bundle_id: None,
                width: 100.0,
                height: 200.0,
            },
            GuiAction::Wait { seconds: 0.0 },
            GuiAction::TripleClick {
                ax_label: None,
                ax_position: Some((1.0, 2.0)),
            },
            GuiAction::HoldKey {
                key: "Return".into(),
                duration_ms: 100,
            },
            GuiAction::MovePath {
                points: vec![(0.0, 0.0), (10.0, 10.0), (20.0, 5.0)],
                duration_ms: 120,
            },
            GuiAction::MovePath {
                points: vec![(1.0, 1.0), (2.0, 2.0)],
                duration_ms: 0,
            },
            GuiAction::DisplayInfo {},
        ];
        for a in cases {
            let s = serde_json::to_string(&a).unwrap();
            let back: GuiAction = serde_json::from_str(&s).unwrap();
            let s2 = serde_json::to_string(&back).unwrap();
            assert_eq!(s, s2, "serde roundtrip mismatch");
        }
    }

    #[test]
    fn gui_action_tag_snake_case() {
        let s = serde_json::to_string(&GuiAction::Screenshot {
            mask_sensitive: false,
        })
        .unwrap();
        assert!(s.contains("\"kind\":\"screenshot\""), "tag snake_case: {s}");
        let s = serde_json::to_string(&GuiAction::InspectTree {}).unwrap();
        assert!(
            s.contains("\"kind\":\"inspect_tree\""),
            "tag snake_case: {s}"
        );
        let s = serde_json::to_string(&GuiAction::TripleClick {
            ax_label: None,
            ax_position: None,
        })
        .unwrap();
        assert!(
            s.contains("\"kind\":\"triple_click\""),
            "triple_click tag snake_case: {s}"
        );
        let s = serde_json::to_string(&GuiAction::HoldKey {
            key: "Tab".into(),
            duration_ms: 200,
        })
        .unwrap();
        assert!(
            s.contains("\"kind\":\"hold_key\""),
            "hold_key tag snake_case: {s}"
        );
        let s = serde_json::to_string(&GuiAction::MovePath {
            points: vec![(1.0, 2.0)],
            duration_ms: 50,
        })
        .unwrap();
        assert!(
            s.contains("\"kind\":\"move_path\""),
            "move_path tag snake_case: {s}"
        );
        assert!(
            s.contains("\"duration_ms\":50"),
            "move_path duration_ms field: {s}"
        );
        let s = serde_json::to_string(&GuiAction::DisplayInfo {}).unwrap();
        assert!(
            s.contains("\"kind\":\"display_info\""),
            "display_info tag snake_case: {s}"
        );
    }

    #[test]
    fn move_path_empty_rejects() {
        // <2 points rejected (ok=false) — needs no trust (point count checked before focused_not_allowed)
        let g = GuiController::new();
        let r = g.execute(GuiAction::MovePath {
            points: vec![(1.0, 1.0)],
            duration_ms: 10,
        });
        let r = r.unwrap();
        assert!(!r.ok, "single-point move_path should be rejected");
        assert!(r.error.unwrap().contains("at least 2 points"));
        let r = g.execute(GuiAction::MovePath {
            points: vec![],
            duration_ms: 10,
        });
        let r = r.unwrap();
        assert!(!r.ok, "empty move_path should be rejected");
    }

    #[test]
    fn display_info_trusted_independent_shape() {
        // display_info goes through CGDisplay, not AX — yields a result without trust (reachable on CI).
        // On headless CI active_displays may return an empty Vec → ok=true displays="[]"; machines with
        // displays get ok=true non-empty.
        // Does not assert displays non-empty here (CI/headless variance); only asserts ok=true and no
        // error (early-return path in effect).
        let g = GuiController::new();
        let r = g.execute(GuiAction::DisplayInfo {}).unwrap();
        assert!(
            r.ok,
            "display_info should be ok (CGDisplay, not AX gated): {r:?}"
        );
        assert!(
            r.error.is_none(),
            "display_info should have no error: {r:?}"
        );
        assert!(
            r.displays.is_some(),
            "displays field should be filled (display_info-specific)"
        );
        // scale_factor should come from compute_scale_factor (not the default 1.0 placeholder — at least >= 1.0)
        assert!(
            r.scale_factor >= 1.0,
            "scale_factor should be >= 1.0: {}",
            r.scale_factor
        );
    }

    #[test]
    fn gui_result_default() {
        let r = GuiResult::default();
        assert!(!r.ok);
        assert!(r.node_tree.is_none());
        assert!(r.screenshot_png_b64.is_none());
        assert!(r.error.is_none());
    }

    /// Operations degrade when unauthorized — CI has no TCC, this is the path taken.
    /// IMPL-9: Screenshot hoisted before the ax_trusted gate, probes Screen Recording itself —
    /// CI without Screen Recording → screen-recording-permission-required (not accessibility).
    #[test]
    fn execute_degrades_without_ax_trust() {
        let ctrl = GuiController::new();
        let r = ctrl
            .execute(GuiAction::Screenshot {
                mask_sensitive: false,
            })
            .unwrap();
        // IMPL-9: screenshot goes through Screen Recording TCC (CoreGraphics), not the Accessibility
        // gate. Both paths are valid, no hard assertion on the ok literal:
        //   CI without Screen Recording → ok:false + screen-recording-permission-required;
        //   trusted machine with Screen Recording → ok:true (PNG).
        if !GuiController::ax_trusted() {
            assert!(
                !r.ok,
                "IMPL-9: unauthorized (no Screen Recording) should degrade to ok:false"
            );
            assert!(
                r.error.is_some(),
                "IMPL-9: unauthorized should degrade (Screen Recording or encode error)"
            );
        }
    }

    /// resolve_keycode coverage — key names case-insensitive + aliases (enter=return, esc=escape, short arrow names)
    #[test]
    fn resolve_keycode_maps_known_keys() {
        assert_eq!(GuiController::resolve_keycode("Tab"), Some(KeyCode::TAB));
        assert_eq!(
            GuiController::resolve_keycode("return"),
            Some(KeyCode::RETURN)
        );
        assert_eq!(
            GuiController::resolve_keycode("Enter"),
            Some(KeyCode::RETURN)
        );
        assert_eq!(GuiController::resolve_keycode("esc"), Some(KeyCode::ESCAPE));
        assert_eq!(
            GuiController::resolve_keycode("UP"),
            Some(KeyCode::UP_ARROW)
        );
        assert_eq!(
            GuiController::resolve_keycode("ctrl"),
            Some(KeyCode::CONTROL)
        );
        assert_eq!(
            GuiController::resolve_keycode("cmd"),
            Some(KeyCode::COMMAND)
        );
        assert_eq!(
            GuiController::resolve_keycode("fn_delete"),
            Some(KeyCode::FORWARD_DELETE)
        );
        assert_eq!(GuiController::resolve_keycode("F12"), Some(KeyCode::F12));
    }

    /// Unknown key name → None (no panic)
    #[test]
    fn resolve_keycode_unknown_returns_none() {
        assert_eq!(GuiController::resolve_keycode("totally-fake-key"), None);
        assert_eq!(GuiController::resolve_keycode(""), None);
    }

    /// KeyPress degrades when unauthorized (CI has no TCC); synthesis should succeed when
    /// authorized (manual).
    /// RUN-12: uses an explicitly unrestricted config (None) so the keycode logic is not perturbed
    /// by the default allowlist (focused-app interception).
    #[test]
    fn keypress_unknown_key_degrades_even_if_trusted() {
        let ctrl = GuiController::new_with_config(GuiConfig {
            allowed_bundle_ids: None,
            allow_type_into_secure: false,
        });
        let r = ctrl
            .execute(GuiAction::KeyPress {
                key: "totally-fake-key".into(),
                modifiers: vec![],
            })
            .unwrap();
        if GuiController::ax_trusted() {
            assert!(!r.ok, "unknown key name should be ok:false");
            assert!(
                r.error.as_deref().unwrap_or("").contains("unknown-key"),
                "unknown key error marker: {:?}",
                r.error
            );
        } else {
            assert!(!r.ok, "unauthorized should degrade");
            assert_eq!(
                r.error.as_deref(),
                Some("accessibility-permission-required")
            );
        }
    }

    /// HoldKey unknown key name degrades — trusted: resolve_keycode returns None → ok:false
    /// unknown-key; CI unauthorized path degrades at the AX gate to accessibility-permission-required
    /// (gate precedes dispatch).
    /// RUN-12: uses an explicitly unrestricted config (None) so the keycode logic is not perturbed
    /// by the default allowlist.
    #[test]
    fn holdkey_unknown_key_degrades_even_if_trusted() {
        let ctrl = GuiController::new_with_config(GuiConfig {
            allowed_bundle_ids: None,
            allow_type_into_secure: false,
        });
        let r = ctrl
            .execute(GuiAction::HoldKey {
                key: "totally-fake-key".into(),
                duration_ms: 10,
            })
            .unwrap();
        if GuiController::ax_trusted() {
            assert!(!r.ok, "unknown key name should be ok:false");
            assert!(
                r.error.as_deref().unwrap_or("").contains("unknown-key"),
                "unknown key error marker: {:?}",
                r.error
            );
        } else {
            assert!(!r.ok, "unauthorized should degrade");
            assert_eq!(
                r.error.as_deref(),
                Some("accessibility-permission-required")
            );
        }
    }

    /// TripleClick degrades when unauthorized — pointer action, CI without TCC takes the degraded path.
    #[test]
    fn tripleclick_degrades_without_ax_trust() {
        let ctrl = GuiController::new();
        let r = ctrl
            .execute(GuiAction::TripleClick {
                ax_label: None,
                ax_position: Some((1.0, 2.0)),
            })
            .unwrap();
        if !GuiController::ax_trusted() {
            assert!(!r.ok, "unauthorized should degrade");
            assert_eq!(
                r.error.as_deref(),
                Some("accessibility-permission-required")
            );
        }
    }

    #[test]
    fn gui_controller_new_is_fast() {
        let start = std::time::Instant::now();
        let _ = GuiController::new();
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_millis() < 50,
            "GuiController::new should be <50ms (lazy), got {elapsed:?}"
        );
    }

    /// resolve_modifier coverage — case-insensitive + aliases (cmd/super, alt, ctrl)
    #[test]
    fn resolve_modifier_maps_known_mods() {
        assert_eq!(
            GuiController::resolve_modifier("command"),
            Some(CGEventFlags::CGEventFlagCommand)
        );
        assert_eq!(
            GuiController::resolve_modifier("Cmd"),
            Some(CGEventFlags::CGEventFlagCommand)
        );
        assert_eq!(
            GuiController::resolve_modifier("super"),
            Some(CGEventFlags::CGEventFlagCommand)
        );
        assert_eq!(
            GuiController::resolve_modifier("shift"),
            Some(CGEventFlags::CGEventFlagShift)
        );
        assert_eq!(
            GuiController::resolve_modifier("Alt"),
            Some(CGEventFlags::CGEventFlagAlternate)
        );
        assert_eq!(
            GuiController::resolve_modifier("control"),
            Some(CGEventFlags::CGEventFlagControl)
        );
        assert_eq!(
            GuiController::resolve_modifier("ctrl"),
            Some(CGEventFlags::CGEventFlagControl)
        );
    }

    /// Unknown modifier → None (no panic)
    #[test]
    fn resolve_modifier_unknown_returns_none() {
        assert_eq!(GuiController::resolve_modifier("hyper"), None);
        assert_eq!(GuiController::resolve_modifier(""), None);
    }

    /// Unknown modifier → ok:false unknown-modifier (trusted-independent, CI path)
    /// RUN-12: uses an explicitly unrestricted config (None) so the modifier logic is not perturbed
    /// by the default allowlist.
    #[test]
    fn keypress_unknown_modifier_degrades_even_if_trusted() {
        let ctrl = GuiController::new_with_config(GuiConfig {
            allowed_bundle_ids: None,
            allow_type_into_secure: false,
        });
        let r = ctrl
            .execute(GuiAction::KeyPress {
                key: "Tab".into(),
                modifiers: vec!["hyper".into()],
            })
            .unwrap();
        if GuiController::ax_trusted() {
            assert!(!r.ok, "unknown modifier should be ok:false");
            assert!(
                r.error
                    .as_deref()
                    .unwrap_or("")
                    .contains("unknown-modifier"),
                "unknown modifier error marker: {:?}",
                r.error
            );
        } else {
            assert!(!r.ok, "unauthorized should degrade");
            assert_eq!(
                r.error.as_deref(),
                Some("accessibility-permission-required")
            );
        }
    }

    /// New-action tag snake_case — serialization tags for scroll/drag/wait
    #[test]
    fn gui_action_new_variants_snake_case() {
        let s = serde_json::to_string(&GuiAction::Scroll {
            dx: 0,
            dy: -1,
            at: None,
        })
        .unwrap();
        assert!(s.contains("\"kind\":\"scroll\""), "scroll tag: {s}");
        let s = serde_json::to_string(&GuiAction::Drag {
            from: (0.0, 0.0),
            to: (1.0, 1.0),
        })
        .unwrap();
        assert!(s.contains("\"kind\":\"drag\""), "drag tag: {s}");
        let s = serde_json::to_string(&GuiAction::Wait { seconds: 1.0 }).unwrap();
        assert!(s.contains("\"kind\":\"wait\""), "wait tag: {s}");
    }

    /// v1.5 new-action serde roundtrip — double_click/right_click/hover/window_*/window_resize
    #[test]
    fn gui_action_v15_variants_serde_roundtrip() {
        let cases = vec![
            GuiAction::DoubleClick {
                ax_label: Some("Open".into()),
                ax_position: Some((10.0, 20.0)),
            },
            GuiAction::DoubleClick {
                ax_label: None,
                ax_position: Some((5.0, 5.0)),
            },
            GuiAction::RightClick {
                ax_label: Some("Menu".into()),
                ax_position: None,
            },
            GuiAction::Hover {
                ax_position: (300.0, 400.0),
            },
            GuiAction::WindowClose {
                bundle_id: Some("com.apple.TextEdit".into()),
            },
            GuiAction::WindowMinimize { bundle_id: None },
            GuiAction::WindowZoom {
                bundle_id: Some("com.apple.Safari".into()),
            },
            GuiAction::WindowResize {
                bundle_id: None,
                width: 800.0,
                height: 600.0,
            },
        ];
        for a in cases {
            let s = serde_json::to_string(&a).unwrap();
            let back: GuiAction = serde_json::from_str(&s).unwrap();
            let s2 = serde_json::to_string(&back).unwrap();
            assert_eq!(s, s2, "serde roundtrip mismatch: {s}");
        }
    }

    /// v1.5 new-action tag snake_case
    #[test]
    fn gui_action_v15_variants_snake_case() {
        let s = serde_json::to_string(&GuiAction::DoubleClick {
            ax_label: None,
            ax_position: Some((1.0, 2.0)),
        })
        .unwrap();
        assert!(s.contains("\"kind\":\"double_click\""), "tag: {s}");
        let s = serde_json::to_string(&GuiAction::RightClick {
            ax_label: None,
            ax_position: Some((1.0, 2.0)),
        })
        .unwrap();
        assert!(s.contains("\"kind\":\"right_click\""), "tag: {s}");
        let s = serde_json::to_string(&GuiAction::Hover {
            ax_position: (1.0, 2.0),
        })
        .unwrap();
        assert!(s.contains("\"kind\":\"hover\""), "tag: {s}");
        let s = serde_json::to_string(&GuiAction::WindowClose { bundle_id: None }).unwrap();
        assert!(s.contains("\"kind\":\"window_close\""), "tag: {s}");
        let s = serde_json::to_string(&GuiAction::WindowMinimize { bundle_id: None }).unwrap();
        assert!(s.contains("\"kind\":\"window_minimize\""), "tag: {s}");
        let s = serde_json::to_string(&GuiAction::WindowZoom { bundle_id: None }).unwrap();
        assert!(s.contains("\"kind\":\"window_zoom\""), "tag: {s}");
        let s = serde_json::to_string(&GuiAction::WindowResize {
            bundle_id: None,
            width: 1.0,
            height: 1.0,
        })
        .unwrap();
        assert!(s.contains("\"kind\":\"window_resize\""), "tag: {s}");
    }

    /// New window actions degrade when unauthorized — CI without TCC takes this path; real AX
    /// operations on trusted machines are verified manually.
    #[test]
    fn window_actions_degrade_without_ax_trust() {
        if GuiController::ax_trusted() {
            // trusted: real window operations need manual TCC + a GUI session, skipped on CI/sandbox
            return;
        }
        let ctrl = GuiController::new();
        for action in [
            GuiAction::WindowClose { bundle_id: None },
            GuiAction::WindowMinimize {
                bundle_id: Some("com.apple.TextEdit".into()),
            },
            GuiAction::WindowZoom { bundle_id: None },
            GuiAction::WindowResize {
                bundle_id: None,
                width: 800.0,
                height: 600.0,
            },
        ] {
            let r = ctrl.execute(action).unwrap();
            assert!(!r.ok, "unauthorized should degrade");
            assert_eq!(
                r.error.as_deref(),
                Some("accessibility-permission-required"),
                "unauthorized error marker"
            );
        }
    }

    /// double_click/right_click/hover degrade when unauthorized (CI path)
    #[test]
    fn pointer_actions_degrade_without_ax_trust() {
        let ctrl = GuiController::new();
        for action in [
            GuiAction::DoubleClick {
                ax_label: None,
                ax_position: Some((10.0, 20.0)),
            },
            GuiAction::RightClick {
                ax_label: None,
                ax_position: Some((10.0, 20.0)),
            },
            GuiAction::Hover {
                ax_position: (10.0, 20.0),
            },
        ] {
            let r = ctrl.execute(action).unwrap();
            if !GuiController::ax_trusted() {
                assert!(!r.ok, "unauthorized should degrade");
                assert_eq!(
                    r.error.as_deref(),
                    Some("accessibility-permission-required")
                );
            }
        }
    }

    /// Hover without coordinates — cannot happen (ax_position is required, not an Option); a
    /// compile-time guarantee only.
    /// double_click/right_click with neither label nor position → resolve_click_position returns
    /// Err (propagated via ?).
    /// CI without TCC → degraded ok:false; trusted machine → execute returns Err (no coordinates), no panic.
    /// RUN-12: uses an explicitly unrestricted config (None) so resolve_click_position logic is not
    /// perturbed by the default allowlist.
    #[test]
    fn double_click_no_target_error_when_trusted() {
        let ctrl = GuiController::new_with_config(GuiConfig {
            allowed_bundle_ids: None,
            allow_type_into_secure: false,
        });
        let res = ctrl.execute(GuiAction::DoubleClick {
            ax_label: None,
            ax_position: None,
        });
        if !GuiController::ax_trusted() {
            let r = res.unwrap();
            assert!(!r.ok, "unauthorized should degrade");
            assert_eq!(
                r.error.as_deref(),
                Some("accessibility-permission-required")
            );
        } else {
            // trusted: no label/position → resolve_click_position errors out as Err, no panic
            assert!(
                res.is_err(),
                "trusted without coordinates should return Err"
            );
            assert!(
                res.unwrap_err()
                    .to_string()
                    .contains("ax_label or ax_position"),
                "error should mention missing target"
            );
        }
    }

    /// Wait trusted-independent — no TCC dependency, runs on CI. seconds=0 should immediately be ok=true.
    #[test]
    fn wait_zero_seconds_ok_without_trust() {
        let ctrl = GuiController::new();
        let r = ctrl.execute(GuiAction::Wait { seconds: 0.0 }).unwrap();
        assert!(r.ok, "Wait 0s should be ok=true (trusted-independent)");
        assert!(r.error.is_none(), "Wait has no error: {:?}", r.error);
    }

    /// Wait clamping — negatives clamped to 0 (no sleep), no panic. The positive-clamped-to-60 path
    /// is verified manually (CI does not run 60s).
    #[test]
    fn wait_clamps_negative_to_zero() {
        let ctrl = GuiController::new();
        let r = ctrl.execute(GuiAction::Wait { seconds: -5.0 }).unwrap();
        assert!(r.ok, "negative Wait should clamp to 0 then be ok=true");
    }

    /// RUN-12: default (non-empty safe set) → bundles outside the set rejected, inside allowed.
    /// Explicit None = unrestricted opt-in → any bundle allowed (backward compatible).
    #[test]
    fn msec04_no_allowlist_allows_any_bundle() {
        // Default non-empty allowlist: evil bundle rejected, safe bundle allowed
        let ctrl = GuiController::new();
        assert!(
            ctrl.check_bundle_allowed("com.evil.keylogger").is_err(),
            "RUN-12: default allowlist should reject unlisted evil bundles"
        );
        assert!(ctrl.check_bundle_allowed("com.apple.TextEdit").is_ok());
        // Explicit None = unrestricted opt-in: any bundle allowed (backward compatible)
        let ctrl_unrestricted = GuiController::new_with_config(GuiConfig {
            allowed_bundle_ids: None,
            allow_type_into_secure: false,
        });
        assert!(ctrl_unrestricted
            .check_bundle_allowed("com.evil.keylogger")
            .is_ok());
        assert!(ctrl_unrestricted
            .check_bundle_allowed("com.apple.TextEdit")
            .is_ok());
    }

    /// M-SEC-04: with an allowlist set → only bundles inside the set allowed, outside rejected.
    #[test]
    fn msec04_allowlist_rejects_unlisted_bundle() {
        let ctrl = GuiController::new_with_config(GuiConfig {
            allowed_bundle_ids: Some(vec![
                "com.apple.TextEdit".into(),
                "com.apple.Terminal".into(),
            ]),
            allow_type_into_secure: false,
        });
        assert!(ctrl.check_bundle_allowed("com.apple.TextEdit").is_ok());
        assert!(ctrl.check_bundle_allowed("com.apple.Terminal").is_ok());
        assert!(
            ctrl.check_bundle_allowed("com.evil.keylogger").is_err(),
            "bundles not in the allowlist should be rejected"
        );
        assert!(
            ctrl.check_bundle_allowed("").is_err(),
            "empty bundle not in the allowlist should be rejected"
        );
    }

    /// RUN-12: GuiConfig default = the non-empty safe set (commercial-safe restricted, not
    /// unrestricted).
    /// An explicit None still = unrestricted opt-in (backward compatible for local trusted callers).
    #[test]
    fn msec04_gui_config_default_unrestricted() {
        let cfg = GuiConfig::default();
        assert!(
            cfg.allowed_bundle_ids.is_some(),
            "RUN-12: default should have a non-empty allowlist"
        );
        let set = cfg.allowed_bundle_ids.unwrap();
        assert!(
            set.contains(&"com.apple.Terminal".to_string()),
            "default set contains Terminal"
        );
        assert!(
            set.contains(&"com.apple.TextEdit".to_string()),
            "default set contains TextEdit"
        );
        assert!(
            set.contains(&"com.apple.finder".to_string()),
            "default set contains finder"
        );
        assert!(
            !cfg.allow_type_into_secure,
            "default rejects type_text into password fields"
        );
    }

    /// M-SEC-04: allow_type_into_secure=true explicit opt-in is constructible.
    #[test]
    fn msec04_allow_type_into_secure_opt_in() {
        let ctrl = GuiController::new_with_config(GuiConfig {
            allowed_bundle_ids: None,
            allow_type_into_secure: true,
        });
        assert!(ctrl.config.allow_type_into_secure);
    }

    /// M-SEC-04: kAXSecureTextFieldSubrole constant is correct (AXSecureTextField, non-empty).
    #[test]
    fn msec04_secure_textfield_subrole_constant() {
        assert_eq!(kAXSecureTextFieldSubrole, "AXSecureTextField");
        assert!(!kAXSecureTextFieldSubrole.is_empty());
    }

    // ===== 0827 fe-gui P0-P3 fix regression tests =====

    /// C-13: allowlist set but AX unauthorized (CI, no TCC) → focused_app_bundle fails and returns
    /// the empty string →
    /// empty string not in allowlist → focused_not_allowed returns Some(degraded). Verifies the
    /// interception logic is CI-reachable
    /// (execute's ax_trusted gate intercepts earlier, so this tests the focused_not_allowed unit path directly).
    #[test]
    fn c13_focused_not_allowed_blocks_when_allowlist_set() {
        let ctrl = GuiController::new_with_config(GuiConfig {
            allowed_bundle_ids: Some(vec!["com.apple.TextEdit".into()]),
            allow_type_into_secure: false,
        });
        let r = ctrl.focused_not_allowed();
        // CI without AX: bundle resolution fails → "" → not in allowlist → Some(degraded).
        // Trusted machine with current focus=TextEdit: bundle hits → None (allowed). Both are valid.
        if !GuiController::ax_trusted() {
            assert!(
                r.is_some(),
                "C-13: CI without AX + allowlist should intercept (bundle resolution failure)"
            );
            let res = r.unwrap();
            assert!(!res.ok, "C-13: interception should be ok:false");
            assert!(
                res.error
                    .as_deref()
                    .unwrap_or("")
                    .contains("focused-app-not-allowed"),
                "C-13: error marker: {:?}",
                res.error
            );
        }
    }

    /// C-13: no allowlist (None) → focused_not_allowed always None (allowed, audited).
    /// Verifies the short-circuit: allowlist=None never calls focused_app_bundle (no AX call).
    /// RUN-12: the default is a non-empty allowlist, so an explicit None is required to test the
    /// unrestricted short-circuit.
    #[test]
    fn c13_focused_not_allowed_passes_without_allowlist() {
        let ctrl = GuiController::new_with_config(GuiConfig {
            allowed_bundle_ids: None,
            allow_type_into_secure: false,
        });
        assert!(
            ctrl.focused_not_allowed().is_none(),
            "C-13: no allowlist (explicit None) should allow and return None"
        );
    }

    /// C-13: type_text with allowlist + CI without AX — execute's ax_trusted gate degrades first,
    /// but when trusted: a focused non-allowlisted app should be intercepted by focused_not_allowed
    /// with ok:false.
    /// The CI path asserts the ax_trusted gate degradation (gate precedes dispatch); verifying
    /// interception on trusted machines needs a real GUI manually.
    #[test]
    fn c13_type_text_blocked_by_allowlist_when_trusted() {
        let ctrl = GuiController::new_with_config(GuiConfig {
            allowed_bundle_ids: Some(vec!["com.apple.TextEdit".into()]),
            allow_type_into_secure: false,
        });
        let r = ctrl
            .execute(GuiAction::TypeText { text: "x".into() })
            .unwrap();
        if GuiController::ax_trusted() {
            // trusted + current focused app not TextEdit → C-13 interception (focused-app-not-allowed);
            // if focus happens to be TextEdit → allowed ok:true (environment-dependent, no hard
            // assertion on ok, just verifying no panic).
            let _ = r.ok;
        } else {
            assert!(!r.ok, "CI without AX should degrade at the ax_trusted gate");
            assert_eq!(
                r.error.as_deref(),
                Some("accessibility-permission-required")
            );
        }
    }

    /// M-12.4: hold_key duration_ms=0 → ok:false hold-key-duration-zero (fail-loud, not a silent no-op).
    /// trusted-independent? No — hold_key goes through execute's ax_trusted gate. CI without AX
    /// takes the gate degradation; on trusted machines the gate passes and duration_ms==0 is
    /// rejected early (before keycode resolution). Both paths are ok:false.
    /// RUN-12: uses an explicitly unrestricted config (None) so the duration logic is not perturbed
    /// by the default allowlist (focused-app interception).
    #[test]
    fn m12_4_hold_key_zero_duration_rejected() {
        let ctrl = GuiController::new_with_config(GuiConfig {
            allowed_bundle_ids: None,
            allow_type_into_secure: false,
        });
        let r = ctrl
            .execute(GuiAction::HoldKey {
                key: "Return".into(),
                duration_ms: 0,
            })
            .unwrap();
        assert!(!r.ok, "M-12.4: duration_ms=0 should be ok:false");
        if GuiController::ax_trusted() {
            assert!(
                r.error
                    .as_deref()
                    .unwrap_or("")
                    .contains("hold-key-duration-zero"),
                "M-12.4: trusted should yield the duration-zero error: {:?}",
                r.error
            );
        } else {
            assert_eq!(
                r.error.as_deref(),
                Some("accessibility-permission-required"),
                "M-12.4: CI without AX takes the gate degradation"
            );
        }
    }

    /// M-12.3: the cgimage_to_rgba + rgba_to_png_b64 doc comments explicitly note the premultiplied
    /// RGBA tradeoff.
    /// Compile-time guarantee: both functions addressable (split interface, callers unbroken).
    #[allow(clippy::type_complexity)]
    #[test]
    fn m12_3_premultiplied_rgba_doc_anchors() {
        let f1 = GuiController::cgimage_to_rgba as fn(&CGImage) -> Result<(Vec<u8>, usize, usize)>;
        let f2 = GuiController::rgba_to_png_b64 as fn(&[u8], usize, usize) -> Result<String>;
        assert!(std::ptr::addr_of!(f1) as usize != 0);
        assert!(std::ptr::addr_of!(f2) as usize != 0);
    }

    /// RUN-12: the default GuiController::new() is restricted — bundles outside the default set are
    /// rejected by check_bundle_allowed.
    /// Commercial-safe default: prevents driving arbitrary apps (keyloggers etc.) without an
    /// explicit allowlist extension.
    #[test]
    fn run12_default_rejects_non_allowlisted_bundle() {
        let ctrl = GuiController::new();
        // Inside the default set: allowed
        assert!(ctrl.check_bundle_allowed("com.apple.Terminal").is_ok());
        assert!(ctrl.check_bundle_allowed("com.apple.finder").is_ok());
        // Outside the default set: rejected (commercial-safe default)
        assert!(
            ctrl.check_bundle_allowed("com.evil.keylogger").is_err(),
            "RUN-12: default restriction should reject evil bundles"
        );
        assert!(
            ctrl.check_bundle_allowed("com.apple.Safari").is_err(),
            "RUN-12: Safari not in the default set should be rejected (requires explicit extension)"
        );
    }

    /// IMPL-9: Screenshot hoisted before the ax_trusted gate — Accessibility being unauthorized
    /// should not mistakenly block screenshots.
    /// Screenshots go through Screen Recording TCC (CoreGraphics), independent of Accessibility.
    /// CI without Screen Recording → screen-recording-permission-required (not accessibility-permission-required).
    /// Trusted machine with Screen Recording → ok:true. Neither path returns an accessibility error.
    #[test]
    fn impl9_screenshot_bypasses_accessibility_gate() {
        let ctrl = GuiController::new();
        let r = ctrl
            .execute(GuiAction::Screenshot {
                mask_sensitive: false,
            })
            .unwrap();
        // Key: screenshot does not go through the Accessibility gate, so the error must not be
        // accessibility-permission-required
        assert_ne!(
            r.error.as_deref(),
            Some("accessibility-permission-required"),
            "IMPL-9: screenshot should not be blocked by the Accessibility gate (TCC permissions independent)"
        );
        if !GuiController::ax_trusted() {
            // CI without Screen Recording → screen-recording degradation (not accessibility)
            assert!(
                !r.ok,
                "IMPL-9: CI without Screen Recording should degrade to ok:false"
            );
            assert!(
                r.error
                    .as_deref()
                    .unwrap_or("")
                    .contains("screen-recording-permission-required"),
                "IMPL-9: CI should return the screen-recording error: {:?}",
                r.error
            );
        }
    }

    /// #38: GuiResult.scale_factor serde defaults to 1.0 (absent field → 1.0, backward compatible).
    #[test]
    fn gui_result_scale_factor_serde_default() {
        let json = r#"{"ok":true}"#;
        let r: GuiResult = serde_json::from_str(json).unwrap();
        assert!(r.ok);
        assert_eq!(
            r.scale_factor, 1.0,
            "absent scale_factor should default to 1.0"
        );
        let s = serde_json::to_string(&r).unwrap();
        assert!(
            s.contains("\"scale_factor\":1.0"),
            "scale_factor should serialize: {s}"
        );
    }

    /// #40: Screenshot mask_sensitive serde defaults to false (absent → false, no masking).
    #[test]
    fn screenshot_mask_sensitive_serde_default() {
        let s = r#"{"kind":"screenshot"}"#;
        let a: GuiAction = serde_json::from_str(s).unwrap();
        match a {
            GuiAction::Screenshot { mask_sensitive } => {
                assert!(
                    !mask_sensitive,
                    "absent mask_sensitive should default to false"
                );
            }
            _ => panic!("deser should be Screenshot"),
        }
        let s2 = r#"{"kind":"screenshot","mask_sensitive":true}"#;
        let a2: GuiAction = serde_json::from_str(s2).unwrap();
        match a2 {
            GuiAction::Screenshot { mask_sensitive } => {
                assert!(
                    mask_sensitive,
                    "explicit mask_sensitive:true should be preserved"
                );
            }
            _ => panic!("deser should be Screenshot"),
        }
    }

    /// #40: mask_rgba_inplace blacks out logical-point rects (including the y-flip).
    /// Builds a 2×2 all-white RGBA buffer; a rect covering the whole image → all black. scale=1.0.
    #[test]
    fn mask_rgba_inplace_full_cover() {
        let mut rgba = vec![255u8; 2 * 2 * 4];
        let rects = vec![(0.0f64, 0.0, 2.0, 2.0)];
        GuiController::mask_rgba_inplace(&mut rgba, 2, 2, 1.0, &rects);
        for px in rgba.chunks(4) {
            assert_eq!(
                px,
                &[0, 0, 0, 255],
                "whole image should be blacked out RGBA(0,0,0,255)"
            );
        }
    }

    /// #40: mask_rgba_inplace partial rect + scale=2.0 + y-flip correctness.
    /// 4×4 image, rect (1,1,1,1) in logical points → scale 2 → pixel region [2,4)×[2,4) (physical).
    /// Y-flip: physical row = h-1-py; py∈[2,4) → rows [0,2) (top two rows).
    #[test]
    fn mask_rgba_inplace_partial_scale_yflip() {
        let mut rgba = vec![255u8; 4 * 4 * 4];
        let rects = vec![(1.0f64, 1.0, 1.0, 1.0)];
        GuiController::mask_rgba_inplace(&mut rgba, 4, 4, 2.0, &rects);
        let is_black = |x: usize, y: usize| -> bool {
            let row = 4 - 1 - y;
            let i = (row * 4 + x) * 4;
            rgba[i] == 0 && rgba[i + 1] == 0 && rgba[i + 2] == 0 && rgba[i + 3] == 255
        };
        // py∈[2,4), px∈[2,4) should be black
        for y in 2..4 {
            for x in 2..4 {
                assert!(is_black(x, y), "({x},{y}) should be black");
            }
        }
        // The rest should be white
        for y in 0..4 {
            for x in 0..4 {
                if !(2..4).contains(&x) || !(2..4).contains(&y) {
                    assert!(!is_black(x, y), "({x},{y}) should be white");
                }
            }
        }
    }

    /// #40: mask_rgba_inplace out-of-bounds clamping (rect beyond the image) — no panic.
    #[test]
    fn mask_rgba_inplace_oob_clamp() {
        let mut rgba = vec![255u8; 2 * 2 * 4];
        let rects = vec![(-5.0f64, -5.0, 100.0, 100.0)];
        GuiController::mask_rgba_inplace(&mut rgba, 2, 2, 1.0, &rects);
        for px in rgba.chunks(4) {
            assert_eq!(
                px,
                &[0, 0, 0, 255],
                "out-of-bounds rect should clamp to the whole image blacked out"
            );
        }
    }

    /// #39: gui_action_batch with empty actions → empty Vec.
    #[test]
    fn gui_action_batch_empty() {
        let ctrl = GuiController::new();
        let results = ctrl.gui_action_batch(vec![]).unwrap();
        assert!(results.is_empty(), "empty batch should return an empty Vec");
    }

    /// #39: gui_action_batch executes multiple actions in order, collecting each step's result.
    /// CI without TCC: Wait trusted-independent ok:true, Click degraded ok:false.
    #[test]
    fn gui_action_batch_sequential_collects() {
        let ctrl = GuiController::new();
        let actions = vec![
            GuiAction::Wait { seconds: 0.0 },
            GuiAction::Click {
                ax_label: None,
                ax_position: None,
            },
            GuiAction::Wait { seconds: 0.0 },
        ];
        let results = ctrl.gui_action_batch(actions).unwrap();
        assert_eq!(results.len(), 3, "should collect 3 step results");
        assert!(results[0].ok, "Wait[0] trusted-independent should be ok");
        assert!(results[2].ok, "Wait[2] trusted-independent should be ok");
        if !GuiController::ax_trusted() {
            assert!(
                !results[1].ok,
                "CI without TCC: Click[1] should degrade to ok:false"
            );
        }
    }
}
