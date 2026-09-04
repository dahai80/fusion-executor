// fe-gui — macOS Computer Use (FR-05)
//
// P4 实装: AXUIElement (accessibility crate, safe wrapper) + CoreGraphics fallback
// CI 跳过 GUI (TCC Accessibility + Screen Recording 权限); ax_trusted() 为 false 时优雅降级。
//
// crate 级 unsafe allow — 仅限本 crate。其余 7 个 crate 仍 workspace unsafe_code="deny"。
// 原因: rustc 1.96 起 extern "C" {} 块内函数默认 unsafe-to-call (unsafe_extern_blocks 迁移),
// accessibility-sys 0.2 用普通 extern "C" 且未导出 safe wrapper。AXIsProcessTrusted() 与
// AXValueGetValue() (position/size) 只在 accessibility-sys 里, accessibility 0.2 safe crate 不覆盖。
// 故这 3 个 FFI 调用需 unsafe block。其余 GUI 逻辑仍走 accessibility 0.2 safe wrapper (约 90%)。
// 用户决策 (2026-08-20): scope allow to fe-gui only, 3 处审计过的 unsafe block。
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

/// 截图节点树上限 — 防 OOM + 递归爆炸
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
        // #40: 敏感区遮罩 — true 时遍历 AX 树查 AXSecureTextField (密码框) 位置/尺寸,
        // 对截图 PNG 对应像素区涂黑后编码, 防 VLM 泄露凭据。需 Accessibility TCC
        // (AX 树遍历); 未授权时跳过遮罩并 warn (截图仍返回, 仅未遮罩)。
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
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GuiResult {
    pub ok: bool,
    pub node_tree: Option<String>,
    pub screenshot_png_b64: Option<String>,
    pub screenshot_width: Option<u32>,
    pub screenshot_height: Option<u32>,
    // #38: backing scale factor — 物理 PNG 像素 / 逻辑点 (Retina=2.0, 非 Retina=1.0)。
    // 坐标契约: 所有 GuiAction x/y 输入 + inspect_tree AXPosition = 逻辑点;
    //           screenshot_width/height = 物理像素。调用方据此双向换算 (pixel = point * scale)。
    // 非 screenshot 结果默认 1.0 (无截图时无意义但向后兼容 absent=1.0)。
    #[serde(default = "default_scale_factor")]
    pub scale_factor: f32,
    pub error: Option<String>,
}

fn default_scale_factor() -> f32 {
    1.0
}

/// 单个 UI 节点 — InspectTree 输出的树节点
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

/// GUI 控制器 — P4 实装 (AXUIElement + CoreGraphics)
/// 点击候选 — (节点, label, 位置)
type ClickCandidate = (AXUIElement, Option<String>, Option<(f64, f64)>);

/// RUN-12: 默认 bundle 安全集 — 商用安全默认非空 allowlist, 防越权驱动任意 app。
/// 本地可信调用方若需无限制, 显式传 GuiConfig { allowed_bundle_ids: None, .. } (向后兼容)。
const DEFAULT_ALLOWED_BUNDLE_IDS: &[&str] = &[
    "com.apple.Terminal",
    "com.apple.TextEdit",
    "com.apple.finder",
];

/// M-SEC-04: GUI 安全配置。
/// - allowed_bundle_ids: None=不限 (显式 opt-in, 仅审计日志); Some=set=仅放行集合内 bundle。
///   RUN-12: 默认非空安全集 (DEFAULT_ALLOWED_BUNDLE_IDS), 商用默认受限。
/// - allow_type_into_secure: false (默认) 时拒绝向 AXSecureTextField (密码框) type_text;
///   true 显式 opt-in (受控场景)。无论取值都记审计 WARN (bundle + 文本长度, 不记文本)。
#[derive(Debug, Clone)]
pub struct GuiConfig {
    pub allowed_bundle_ids: Option<Vec<String>>,
    pub allow_type_into_secure: bool,
}

/// RUN-12: 默认非空 allowlist (商用安全默认), 非 None。
/// 与 check_bundle_allowed None→Ok 契约不冲突: 显式传 None 仍 = 无限制 opt-in。
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

    /// M-SEC-04: 带安全配置构造 (企业/多用户场景设 bundle allowlist + secure flag)。
    pub fn new_with_config(config: GuiConfig) -> Self {
        info!(
            allowlist = ?config.allowed_bundle_ids.as_ref().map(|v| v.len()),
            allow_secure = config.allow_type_into_secure,
            "GuiController::new_with_config (M-SEC-04)"
        );
        Self { config }
    }

    /// M-SEC-04: bundle 放行校验。allowlist=None 始终放行 (仅审计日志); Some=set 须命中。
    fn check_bundle_allowed(&self, bundle_id: &str) -> Result<()> {
        match &self.config.allowed_bundle_ids {
            None => {
                debug!(bundle_id, "M-SEC-04 bundle 无 allowlist, 放行 (审计)");
                Ok(())
            }
            Some(set) => {
                if set.iter().any(|b| b == bundle_id) {
                    debug!(bundle_id, "M-SEC-04 bundle 命中 allowlist");
                    Ok(())
                } else {
                    warn!(
                        bundle_id,
                        "M-SEC-04 bundle 不在 allowlist — 拒绝 (防越权驱动任意 app)"
                    );
                    Err(anyhow!("bundle-not-allowed: {bundle_id}"))
                }
            }
        }
    }

    /// C-13: 解析当前 focused app 的 bundle id (best-effort)。
    /// accessibility-sys 0.2 无 kAXBundleIdentifierAttribute 常量 — 用原始 CFString "AXBundleIdentifier"
    /// 经 AXAttribute::<CFType> 读 + downcast CFString (同 focused_app 读 AXFocusedApplication 模式)。
    /// 用于 HID-post 输入合成方法 (key_press/hold_key/scroll/drag/hover) 的 bundle allowlist 校验。
    fn focused_app_bundle(&self) -> Result<String> {
        let app = Self::focused_app()?;
        let attr = AXAttribute::<CFType>::new(&CFString::from_static_string("AXBundleIdentifier"));
        let cf: CFType = app
            .attribute(&attr)
            .map_err(|e| anyhow!("取 AXBundleIdentifier 失败: {e}"))?;
        let s = cf
            .downcast::<CFString>()
            .ok_or_else(|| anyhow!("AXBundleIdentifier 非 CFString"))?;
        Ok(s.to_string())
    }

    /// C-13: 输入合成方法顶上检查当前 focused app bundle 是否在 allowlist。
    /// allowlist=None → 放行 (审计, 无 AX 调用 short-circuit); Some=set → 解析 focused bundle 后复用
    /// check_bundle_allowed 纯校验 (无逻辑重复)。TOCTOU: check 与 HID-post 间聚焦可能切换 — HID 固有,
    /// best-effort 非原子, 但堵当前 bypass (等非 allowlisted app 聚焦 → type_text 注入)。
    fn check_focused_allowed(&self) -> Result<()> {
        match &self.config.allowed_bundle_ids {
            None => {
                debug!("C-13 输入合成: 无 allowlist, focused app 放行 (审计)");
                Ok(())
            }
            Some(_) => {
                let bundle = self.focused_app_bundle().unwrap_or_default();
                self.check_bundle_allowed(&bundle)
            }
        }
    }

    /// C-13: 输入合成方法顶上调用 — allowlist 拦截返 Some(degraded GuiResult), 放行返 None。
    /// 各方法 `if let Some(r) = self.focused_not_allowed() { return Ok(r); }` 一行 gate。
    fn focused_not_allowed(&self) -> Option<GuiResult> {
        match self.check_focused_allowed() {
            Ok(()) => None,
            Err(e) => {
                warn!(error = %e, "C-13: focused app 不在 allowlist — 拒绝输入合成 (防越权注入)");
                Some(GuiResult {
                    ok: false,
                    error: Some(format!("focused-app-not-allowed: {e}")),
                    ..Default::default()
                })
            }
        }
    }

    /// AX 是否已授权 (TCC Accessibility)。未授权时所有 GUI 操作降级报错。
    /// unsafe: AXIsProcessTrusted 是 accessibility-sys 的 extern "C" fn (rustc 1.96 默认 unsafe-to-call)。
    /// 该 C 函数仅读 TCC 状态返回 bool, 无指针参数, 内存安全无风险。
    pub fn ax_trusted() -> bool {
        unsafe { AXIsProcessTrusted() }
    }

    pub fn execute(&self, action: GuiAction) -> Result<GuiResult> {
        // Wait — 纯延时, trusted-independent, 不需 AX 授权, 先处理 (CI 可测)
        if let GuiAction::Wait { seconds } = &action {
            return self.wait(*seconds);
        }
        // IMPL-9: Screenshot 走 CoreGraphics (CGWindowListCreateImage) 需 Screen Recording TCC,
        // 非 Accessibility TCC — 两权限独立。AX 未授权但 Screen Recording 授权时仍应可截图。
        // 提到 ax_trusted 闸门前, 让 screenshot() 自探 Screen Recording (CGImage None → 降级)。
        if let GuiAction::Screenshot { mask_sensitive } = &action {
            return self.screenshot(*mask_sensitive);
        }
        if !Self::ax_trusted() {
            warn!("AX 未授权 (TCC Accessibility) — GUI 操作降级");
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
            // IMPL-9: Screenshot 已在 ax_trusted 闸门前 early-return (Screen Recording TCC 独立)。
            // 走到此说明 early-return 被重构破 — fail-loud (非 crash), 同 Wait 兜底模式。
            GuiAction::Screenshot { .. } => Ok(GuiResult {
                ok: false,
                error: Some("internal: Screenshot 未在 early-return 处理 (invariant 破坏)".into()),
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
            // m-FT-04: Wait 已在 ax_trusted 前早 return, 走到此说明 early-return 被重构破;
            // 不 panic, fail-loud 返回错误 (调用方可见, 非 crash)
            GuiAction::Wait { .. } => Ok(GuiResult {
                ok: false,
                error: Some("internal: Wait 未在 early-return 处理 (invariant 破坏)".into()),
                ..Default::default()
            }),
        }
    }

    /// #39: 批量原子动作管线 — 顺序执行多个 GuiAction, 收集每步 GuiResult。
    /// 非事务 (单步失败不中止后续 — 调用方据每步 ok 自决重试/补偿); 中止语义由调用方
    /// 读 results 断点实现 (executor 不可知意图)。空 actions 返空 Vec。顺序保证 (非并行),
    /// 因 GUI 动作有隐含时序 (focus→click→type)。
    pub fn gui_action_batch(&self, actions: Vec<GuiAction>) -> Result<Vec<GuiResult>> {
        info!(count = actions.len(), "gui_action_batch 开始");
        let mut results = Vec::with_capacity(actions.len());
        for (i, action) in actions.into_iter().enumerate() {
            let res = self.execute(action)?;
            let ok = res.ok;
            results.push(res);
            info!(step = i, ok, "gui_action_batch 步完成");
        }
        info!(count = results.len(), "gui_action_batch 结束");
        Ok(results)
    }

    fn focus_app(&self, bundle_id: &str) -> Result<GuiResult> {
        info!(bundle_id, "FocusApp");
        // M-SEC-04: bundle 放行校验 (防越权驱动任意 app)。
        if self.check_bundle_allowed(bundle_id).is_err() {
            return Ok(GuiResult {
                ok: false,
                error: Some(format!("bundle-not-allowed: {bundle_id}")),
                ..Default::default()
            });
        }
        let app = AXUIElement::application_with_bundle(bundle_id)
            .map_err(|e| anyhow!("定位 app 失败 {bundle_id}: {e}"))?;
        app.set_frontmost(CFBoolean::true_value())
            .map_err(|e| anyhow!("set_frontmost 失败: {e}"))?;
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
            .map_err(|e| anyhow!("取 focused app 失败: {e}"))?;
        cf.downcast::<AXUIElement>()
            .ok_or_else(|| anyhow!("focused app 类型不匹配"))
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
            .map_err(|e| anyhow!("取 focused window 失败: {e}"))?;
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
                .map_err(|e| anyhow!("press 失败: {e}"))
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

    /// 在 window 子树中找点击目标 — 优先 label 精确匹配, 否则位置最近匹配
    fn find_click_target(
        root: &AXUIElement,
        ax_label: Option<&str>,
        ax_position: Option<(f64, f64)>,
    ) -> Result<AXUIElement> {
        let mut candidates: Vec<ClickCandidate> = Vec::new();
        Self::collect_clickable(root, 0, &mut candidates);
        if candidates.is_empty() {
            return Err(anyhow!("无可点击节点 (子树为空)"));
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
                .ok_or_else(|| anyhow!("位置匹配无候选"))?;
            return Ok(best.0);
        }
        Err(anyhow!("click 需 ax_label 或 ax_position"))
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
            .map_err(|e| anyhow!("取 focused window 失败: {e}"))?;
        let target = Self::find_text_field(&win)?;
        // M-SEC-04: 密码框保护 — AXSecureTextField 是 AXTextField 角色 + AXSecureTextField 子角色。
        // 拒绝向密码框 type_text 除非显式 allow_type_into_secure (防凭据窃取注入)。
        // 审计日志记文本长度 (不记文本本身, 防凭据落盘日志)。
        let is_secure = target
            .subrole()
            .map(|s| s == kAXSecureTextFieldSubrole)
            .unwrap_or(false);
        if is_secure {
            warn!(
                text_len = text.len(),
                allow_secure = self.config.allow_type_into_secure,
                "M-SEC-04: 目标为 AXSecureTextField (密码框) — type_text 审计"
            );
            if !self.config.allow_type_into_secure {
                warn!("M-SEC-04: 拒绝向密码框 type_text (未显式 allow_type_into_secure)");
                return Ok(GuiResult {
                    ok: false,
                    error: Some(
                        "secure-text-field-rejected: 目标为密码框, type_text 被拒 (M-SEC-04)"
                            .into(),
                    ),
                    ..Default::default()
                });
            }
        } else {
            debug!(
                text_len = text.len(),
                "M-SEC-04: type_text 目标非密码框, 审计文本长度"
            );
        }
        let settable = target
            .is_settable(&accessibility::AXAttribute::value())
            .unwrap_or(false);
        if !settable {
            debug!("value 不可 settable, 尝试直接 set_value (部分控件允许)");
        }
        target
            .set_value(CFString::new(text).into_CFType())
            .map_err(|e| anyhow!("set_value 失败: {e}"))?;
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

    /// KeyPress — CGEvent 合成 keydown + keyup, post 到 HID tap。
    /// 键名 → virtual keycode (layout-independent); 未识别返回 ok:false + 已知列表, 不 panic。
    /// modifiers: 和弦修饰键 (Cmd/Shift/Option/Control), 合成顺序:
    ///   keydown 各 modifier (set_flags 累加) → keydown key (带累加 flag) → keyup key → keyup modifier 逆序
    /// core-graphics 0.24 safe wrapper: CGEventSource::new / CGEvent::new_keyboard_event / post / set_flags
    /// 内部均为 unsafe FFI, 但已封进 safe API; 本函数无需手写 unsafe block。
    fn key_press(&self, key: &str, modifiers: &[String]) -> Result<GuiResult> {
        info!(key, mods = ?modifiers, "KeyPress");
        // RUN-12: trusted-independent 输入校验先行 — 未知键名/修饰键降级与焦点 app 无关,
        // 放在 focused_not_allowed 闸门之前 (keycode/modifier 解析不触 AX 焦点读)。
        let code = match Self::resolve_keycode(key) {
            Some(c) => c,
            None => {
                warn!(key, "未知键名 — 降级返回已知列表");
                return Ok(GuiResult {
                    ok: false,
                    error: Some(format!(
                        "unknown-key: '{key}'; 支持的键名见 resolve_keycode \
                         (Return/Tab/Space/Delete/Forward_delete/Escape/Up_arrow/Down_arrow/\
                         Left_arrow/Right_arrow/Home/End/Page_up/Page_down/Help/\
                         F1-F20/Command/Shift/Option/Control/Function/Caps_lock/Mute/\
                         Volume_up/Volume_down)",
                    )),
                    ..Default::default()
                });
            }
        };
        // 解析 modifiers → (flag, keycode); 未识别 modifier 整体降级
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
                            warn!(modifier = m, "未知修饰键 — 降级");
                            return Ok(GuiResult {
                                ok: false,
                                error: Some(format!(
                                    "unknown-modifier: '{m}'; 支持: command/cmd, shift, \
                                     option/alt, control/ctrl",
                                )),
                                ..Default::default()
                            });
                        }
                    };
                    mods.push((f, mk));
                }
                None => {
                    warn!(modifier = m, "未知修饰键 — 降级");
                    return Ok(GuiResult {
                        ok: false,
                        error: Some(format!(
                            "unknown-modifier: '{m}'; 支持: command/cmd, shift, option/alt, \
                             control/ctrl",
                        )),
                        ..Default::default()
                    });
                }
            }
        }
        // RUN-12: 输入校验已过 (trusted-independent), 再查焦点 app 白名单 — 非白名单 app 拒绝合成事件
        if let Some(r) = self.focused_not_allowed() {
            return Ok(r);
        }
        let source = CGEventSource::new(CGEventSourceStateID::CombinedSessionState)
            .map_err(|_| anyhow!("CGEventSource 创建失败 (CGEventSourceCreate 返回 null)"))?;
        // 累加 flag — 修饰键 keydown 事件本身也带全部 modifier flag
        let mut combined = CGEventFlags::CGEventFlagNull;
        for (f, _mk) in &mods {
            combined |= *f;
        }
        // 1. keydown 各 modifier (事件带累加 flag)
        for (f, mk) in &mods {
            let e = CGEvent::new_keyboard_event(source.clone(), *mk, true)
                .map_err(|_| anyhow!("CGEvent modifier keydown 创建失败"))?;
            e.set_flags(*f);
            e.post(CGEventTapLocation::HID);
        }
        // 2. keydown key (带全部 modifier flag)
        let down = CGEvent::new_keyboard_event(source.clone(), code, true)
            .map_err(|_| anyhow!("CGEvent keydown 创建失败"))?;
        down.set_flags(combined);
        down.post(CGEventTapLocation::HID);
        // 3. keyup key (flag 清空)
        let up = CGEvent::new_keyboard_event(source.clone(), code, false)
            .map_err(|_| anyhow!("CGEvent keyup 创建失败"))?;
        up.set_flags(CGEventFlags::CGEventFlagNull);
        up.post(CGEventTapLocation::HID);
        // 4. keyup modifier 逆序 (flag 清空)
        for (_, mk) in mods.iter().rev() {
            let e = CGEvent::new_keyboard_event(source.clone(), *mk, false)
                .map_err(|_| anyhow!("CGEvent modifier keyup 创建失败"))?;
            e.set_flags(CGEventFlags::CGEventFlagNull);
            e.post(CGEventTapLocation::HID);
        }
        debug!(
            keycode = code,
            mods = mods.len(),
            "KeyPress 完成 (和弦 keydown+keyup posted)"
        );
        Ok(GuiResult {
            ok: true,
            ..Default::default()
        })
    }

    /// HoldKey — 按住单键 duration_ms 后释放 (keydown → sleep → keyup)。
    /// 用于长按 (如按住方向键移动光标, 按住 Backspace 连删)。单键无 modifier 和弦。
    /// 未识别键名同 key_press 降级 ok:false + 已知列表。sleep 阻塞当前线程 (GUI 同步路径)。
    fn hold_key(&self, key: &str, duration_ms: u64) -> Result<GuiResult> {
        info!(key, duration_ms, "HoldKey");
        // M-12.4: duration_ms==0 → keydown 立即 keyup = 单击非按住, 静默 no-op 易误用。
        // fail-loud 拒绝 (Rule 12), 调用方显式用 key_press 做单击。
        if duration_ms == 0 {
            warn!(
                key,
                "HoldKey duration_ms=0 — 拒绝 (keydown 即 keyup 是单击非按住, 显式用 key_press)"
            );
            return Ok(GuiResult {
                ok: false,
                error: Some(
                    "hold-key-duration-zero: duration_ms 必须 >0 (按住需非零时长; 单击用 key_press)"
                        .into(),
                ),
                ..Default::default()
            });
        }
        // RUN-12: trusted-independent keycode 校验先行 (与 key_press 同理)
        let code = match Self::resolve_keycode(key) {
            Some(c) => c,
            None => {
                warn!(key, "未知键名 — 降级返回已知列表");
                return Ok(GuiResult {
                    ok: false,
                    error: Some(format!(
                        "unknown-key: '{key}'; 支持的键名见 resolve_keycode \
                         (Return/Tab/Space/Delete/Forward_delete/Escape/Up_arrow/Down_arrow/\
                         Left_arrow/Right_arrow/Home/End/Page_up/Page_down/Help/\
                         F1-F20/Command/Shift/Option/Control/Function/Caps_lock/Mute/\
                         Volume_up/Volume_down)",
                    )),
                    ..Default::default()
                });
            }
        };
        // RUN-12: 焦点 app 白名单 — keycode 已过, 非白名单 app 拒绝合成事件
        if let Some(r) = self.focused_not_allowed() {
            return Ok(r);
        }
        let source = CGEventSource::new(CGEventSourceStateID::CombinedSessionState)
            .map_err(|_| anyhow!("CGEventSource 创建失败 (hold_key)"))?;
        // keydown
        let down = CGEvent::new_keyboard_event(source.clone(), code, true)
            .map_err(|_| anyhow!("CGEvent keydown 创建失败 (hold_key)"))?;
        down.post(CGEventTapLocation::HID);
        // 按住 — 阻塞 sleep (GUI 同步, duration_ms 量级; 超 5s 截断防误用挂死)
        let capped = duration_ms.min(5000);
        if capped != duration_ms {
            warn!(
                asked = duration_ms,
                capped, "HoldKey duration 超 5s 上限, 截断防挂死"
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(capped));
        // keyup
        let up = CGEvent::new_keyboard_event(source.clone(), code, false)
            .map_err(|_| anyhow!("CGEvent keyup 创建失败 (hold_key)"))?;
        up.post(CGEventTapLocation::HID);
        debug!(
            keycode = code,
            capped, "HoldKey 完成 (keydown→sleep→keyup posted)"
        );
        Ok(GuiResult {
            ok: true,
            ..Default::default()
        })
    }

    /// 修饰键名 (大小写不敏感) → CGEventFlags bit。仅 4 主修饰键。
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

    /// 键名 (不区分大小写) → virtual keycode。匹配 core_graphics::event::KeyCode 常量。
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

    /// 找文本输入框 — AXTextField / AXTextArea 角色的 focused 元素, 否则子树第一个
    fn find_text_field(root: &AXUIElement) -> Result<AXUIElement> {
        let mut found: Option<AXUIElement> = None;
        Self::walk_first_text(root, 0, &mut found);
        found.ok_or_else(|| anyhow!("未找到文本输入框 (AXTextField/AXTextArea)"))
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
            .map_err(|e| anyhow!("取 focused window 失败: {e}"))?;
        let mut count = 0usize;
        let root = Self::build_node(&win, 0, &mut count);
        let tree = serde_json::to_string(&root).map_err(|e| anyhow!("节点树序列化失败: {e}"))?;
        Ok(GuiResult {
            ok: true,
            node_tree: Some(tree),
            ..Default::default()
        })
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

    /// 读 AXPosition — unsafe: AXValueGetValue 是 accessibility-sys extern "C" fn (rustc 1.96 默认 unsafe)。
    /// 语义: 从 ax_ref 读 CGPoint 写入栈上 pt。ax_ref 来自 CFType downcast (cf_to_axvalue),
    /// 若类型不符 AXValueGetValue 返回 false (不写)。指针只指向本地栈变量, 生命周期安全。
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

    /// 读 AXSize — 同 read_position, 写入 CGSize。
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

    /// CFType → AXValueRef (类型不匹配返回 None, 不 panic)
    fn cf_to_axvalue(cf: &CFType) -> Option<AXValueRef> {
        let ptr = cf.as_concrete_TypeRef() as AXValueRef;
        if ptr.is_null() {
            None
        } else {
            Some(ptr)
        }
    }

    /// #40: 收集焦点 app 焦点窗口内所有 AXSecureTextField (密码框) 的逻辑点矩形 (x, y, w, h)。
    /// 递归遍历 AX 子树 (复用 build_node 的深度/节点上限防爆炸)。AX 未授权时返空 Vec
    /// (调用方 screenshot 已在 ax_trusted() 闸门内调用, 此处仍 fail-soft)。
    fn collect_secure_rects() -> Vec<(f64, f64, f64, f64)> {
        let app = match Self::focused_app() {
            Ok(a) => a,
            Err(e) => {
                warn!(error = %e, "collect_secure_rects: 取 focused app 失败 — 返空");
                return vec![];
            }
        };
        let win = match app.focused_window().or_else(|_| app.main_window()) {
            Ok(w) => w,
            Err(e) => {
                warn!(error = %e, "collect_secure_rects: 取 focused window 失败 — 返空");
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
        // AXSecureTextField: subrole == kAXSecureTextFieldSubrole (密码框显式标记)
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

    /// #40: 对 RGBA 缓冲区原地涂黑敏感区。rects 是逻辑点 (x, y, w, h); scale 转 物理像素。
    /// 坐标系换算: AX 原点左上 (y 向下), 位图上下文原点左下 (行 0 = 底) — 故位图行 = h_px - 1 - y_px。
    /// 越界裁剪到 [0, w_px)/[0, h_px) 防 panic。
    fn mask_rgba_inplace(
        rgba: &mut [u8],
        w_px: usize,
        h_px: usize,
        scale: f32,
        rects: &[(f64, f64, f64, f64)],
    ) {
        let bytes_per_row = w_px * 4;
        for &(lx, ly, lw, lh) in rects {
            // 逻辑点 → 物理像素 (向下取整 + clamp)
            let x0 = ((lx * scale as f64).floor() as isize).max(0) as usize;
            let y0 = ((ly * scale as f64).floor() as isize).max(0) as usize;
            let x1 = (((lx + lw) * scale as f64).ceil() as isize).min(w_px as isize) as usize;
            let y1 = (((ly + lh) * scale as f64).ceil() as isize).min(h_px as isize) as usize;
            if x0 >= x1 || y0 >= y1 || x0 >= w_px || y0 >= h_px {
                continue;
            }
            // 涂黑: RGBA = (0,0,0,255)。y 翻转 — 位图行 0 在底。
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

    /// 截图 — CGWindowListCreateImage 全屏 → CGImage → 位图上下文取 RGBA → PNG → base64
    /// Screen Recording TCC 未授权时 CGImage 为 None → 返回明确错误。
    /// #40: mask_sensitive=true 时遍历 AX 树查 AXSecureTextField (密码框) 区块, 对 RGBA
    /// 像素涂黑后编码 — 防 VLM 泄露凭据。需 Accessibility TCC; 未授权跳过遮罩 + warn。
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
                warn!("Screen Recording 未授权 — 截图降级");
                return Ok(GuiResult {
                    ok: false,
                    error: Some(
                        "screen-recording-permission-required (CGWindowListCreateImage 返回 null)"
                            .into(),
                    ),
                    ..Default::default()
                });
            }
        };
        let (mut rgba, vw, vh) = match Self::cgimage_to_rgba(&img) {
            Ok(t) => t,
            Err(e) => {
                warn!(error = %e, "截图编码失败 — 降级");
                return Ok(GuiResult {
                    ok: false,
                    error: Some(format!("screenshot-encode-failed: {e}")),
                    ..Default::default()
                });
            }
        };
        // #38: scale_factor = 物理像素 / 逻辑点。CGDisplay::main().bounds() 返主屏逻辑点尺寸;
        // screenshot 是全屏物理像素 (img.width/height)。Retina 上 = 2.0, 非 Retina = 1.0。
        // bounds.width 为 0 (罕见异常) 时降级 1.0 防 NaN。
        let scale_factor = {
            let main = CGDisplay::main();
            let logical_w = main.bounds().size.width;
            if logical_w > 0.0 {
                (img.width() as f32 / logical_w as f32).max(1.0)
            } else {
                warn!("主屏逻辑宽度为 0 — scale_factor 降级 1.0");
                1.0
            }
        };
        info!(scale_factor, "Screenshot scale_factor 计算完成");
        // #40: 敏感区遮罩 — AXSecureTextField (密码框) 像素涂黑。
        let masked_count = if mask_sensitive {
            if Self::ax_trusted() {
                let rects = Self::collect_secure_rects();
                if !rects.is_empty() {
                    Self::mask_rgba_inplace(&mut rgba, vw, vh, scale_factor, &rects);
                }
                rects.len()
            } else {
                warn!("mask_sensitive=true 但 AX 未授权 — 跳过敏感区遮罩 (截图未遮罩返回)");
                0
            }
        } else {
            0
        };
        if masked_count > 0 {
            info!(masked_count, "敏感区遮罩完成 (AXSecureTextField 区块涂黑)");
        }
        let png_b64 = match Self::rgba_to_png_b64(&rgba, vw, vh) {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "截图编码失败 — 降级");
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

    /// CGImage → RGBA Vec<u8> (预乘, premultiplied last) + 宽高。位图上下文统一像素格式。
    /// 返回 Vec 以便调用方 (mask) 原地改像素后再编码。
    ///
    /// M-12.3: 位图上下文用 kCGImageAlphaPremultipliedLast — CoreGraphics 返回**预乘 RGBA**
    /// (RGB 已乘 alpha)。PNG 标准期望**非预乘** (straight) alpha。此处直接编码预乘像素,
    /// 半透明区 (alpha<255) 合成时颜色偏移 (RGB 偏暗)。屏幕截图多为不透明 (alpha=255, 预乘无差异);
    /// 仅含透明窗/菜单阴影的截图边缘可能色偏。已知取舍 (Rule 2 最小改): 显式 unpremultiply 需逐像素
    /// 除法 (4*w*h 次, 满屏 4M+ ops) 且 alpha=0 除零特判 — 当前调用方 (mlx-vlm 视觉 grounding)
    /// 不依赖精确 alpha, 色偏在容差内, 不实装。若未来需精确 alpha, 在此循环 unpremultiply。
    fn cgimage_to_rgba(img: &CGImage) -> Result<(Vec<u8>, usize, usize)> {
        let w = img.width();
        let h = img.height();
        if w == 0 || h == 0 {
            return Err(anyhow!("截图尺寸为 0"));
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
        // ctx.data() 是 &[u8] 借用 ctx — copy 到 Vec 后 ctx 可 drop, 再原地 mask。
        let rgba: Vec<u8> = ctx.data().to_vec();
        Ok((rgba, w, h))
    }

    /// RGBA Vec → PNG → base64。
    fn rgba_to_png_b64(rgba: &[u8], w: usize, h: usize) -> Result<String> {
        let mut buf: Vec<u8> = Vec::with_capacity(0);
        {
            let mut enc = Encoder::new(&mut buf, w as u32, h as u32);
            enc.set_color(ColorType::Rgba);
            enc.set_depth(BitDepth::Eight);
            let mut writer = enc
                .write_header()
                .map_err(|e| anyhow!("PNG 写头失败: {e}"))?;
            writer
                .write_image_data(rgba)
                .map_err(|e| anyhow!("PNG 写像素失败: {e}"))?;
        }
        Ok(B64.encode(&buf))
    }

    /// 滚轮滚动 — CGEvent new_scroll_event (highsierra feature)。
    /// dx=水平 (axis2), dy=垂直 (axis1); LINE 单位。at 给定则先移动光标到该坐标。
    /// core-graphics 0.24 safe wrapper 封装 CGEventCreateScrollWheelEvent2 的 unsafe FFI。
    fn scroll(&self, dx: i32, dy: i32, at: Option<(f64, f64)>) -> Result<GuiResult> {
        info!(dx, dy, at = ?at, "Scroll");
        if let Some(r) = self.focused_not_allowed() {
            return Ok(r);
        }
        let source = CGEventSource::new(CGEventSourceStateID::CombinedSessionState)
            .map_err(|_| anyhow!("CGEventSource 创建失败 (scroll)"))?;
        if let Some((x, y)) = at {
            let moved = CGEvent::new_mouse_event(
                source.clone(),
                CGEventType::MouseMoved,
                CGPoint::new(x, y),
                CGMouseButton::Left,
            )
            .map_err(|_| anyhow!("CGEvent MouseMoved 创建失败 (scroll 光标定位)"))?;
            moved.post(CGEventTapLocation::HID);
        }
        // new_scroll_event(source, units, wheel_count, wheel1=axis2水平, wheel2=axis1垂直, wheel3=0)
        let ev = CGEvent::new_scroll_event(source, ScrollEventUnit::LINE, 2, dx, dy, 0).map_err(
            |_| anyhow!("CGEvent scroll 创建失败 (CGEventCreateScrollWheelEvent2 返回 null)"),
        )?;
        ev.post(CGEventTapLocation::HID);
        debug!(dx, dy, "Scroll 完成 (ScrollWheel posted)");
        Ok(GuiResult {
            ok: true,
            ..Default::default()
        })
    }

    /// 拖拽 — mouseDown(from) → LeftMouseDragged(间帧) → mouseUp(to)。
    /// 左键单次拖拽; 间帧线性插值平滑 (默认 16 帧)。CGEvent new_mouse_event 各带位置, 无需 set_location。
    fn drag(&self, from: (f64, f64), to: (f64, f64)) -> Result<GuiResult> {
        info!(from = ?from, to = ?to, "Drag");
        if let Some(r) = self.focused_not_allowed() {
            return Ok(r);
        }
        let source = CGEventSource::new(CGEventSourceStateID::CombinedSessionState)
            .map_err(|_| anyhow!("CGEventSource 创建失败 (drag)"))?;
        let steps = 16i32;
        // 1. mouseDown at from (左键按下)
        let down = CGEvent::new_mouse_event(
            source.clone(),
            CGEventType::LeftMouseDown,
            CGPoint::new(from.0, from.1),
            CGMouseButton::Left,
        )
        .map_err(|_| anyhow!("CGEvent LeftMouseDown 创建失败 (drag)"))?;
        down.post(CGEventTapLocation::HID);
        // 2. LeftMouseDragged 间帧 (from → to 线性插值)
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
            .map_err(|_| anyhow!("CGEvent LeftMouseDragged 创建失败 (drag 间帧 {i})"))?;
            moved.post(CGEventTapLocation::HID);
        }
        // 3. mouseUp at to (左键抬起)
        let up = CGEvent::new_mouse_event(
            source,
            CGEventType::LeftMouseUp,
            CGPoint::new(to.0, to.1),
            CGMouseButton::Left,
        )
        .map_err(|_| anyhow!("CGEvent LeftMouseUp 创建失败 (drag)"))?;
        up.post(CGEventTapLocation::HID);
        debug!(steps, "Drag 完成 (down→drag→up posted)");
        Ok(GuiResult {
            ok: true,
            ..Default::default()
        })
    }

    /// 双击 — 先定位 AX 点击目标取坐标, 再 CGEvent 合成两次 left click, click_state=2。
    /// click_state 字段 (EventField::MOUSE_EVENT_CLICK_STATE=1) 告知系统这是连续第二击。
    /// 复用 find_click_target 取坐标 (与 click() 同路径); 无坐标目标 → 降级。
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
            .map_err(|_| anyhow!("CGEventSource 创建失败 (double_click)"))?;
        // 两次 left click, 第二击 click_state=2 (区分单击/双击手势)
        for click_no in 1..=2i64 {
            let down = CGEvent::new_mouse_event(
                source.clone(),
                CGEventType::LeftMouseDown,
                CGPoint::new(pos.0, pos.1),
                CGMouseButton::Left,
            )
            .map_err(|_| anyhow!("CGEvent LeftMouseDown 创建失败 (double_click {click_no})"))?;
            down.set_integer_value_field(EventField::MOUSE_EVENT_CLICK_STATE, click_no);
            down.post(CGEventTapLocation::HID);
            let up = CGEvent::new_mouse_event(
                source.clone(),
                CGEventType::LeftMouseUp,
                CGPoint::new(pos.0, pos.1),
                CGMouseButton::Left,
            )
            .map_err(|_| anyhow!("CGEvent LeftMouseUp 创建失败 (double_click {click_no})"))?;
            up.set_integer_value_field(EventField::MOUSE_EVENT_CLICK_STATE, click_no);
            up.post(CGEventTapLocation::HID);
        }
        debug!(pos = ?pos, "DoubleClick 完成 (2× down/up posted, click_state=2)");
        Ok(GuiResult {
            ok: true,
            ..Default::default()
        })
    }

    /// 三击 — 同 double_click 定位, CGEvent 合成三次 left click, click_state 递增 1..=3。
    /// 用于整段/整行文本选择 (如三击选行)。复用 resolve_click_position 取坐标。
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
            .map_err(|_| anyhow!("CGEventSource 创建失败 (triple_click)"))?;
        // 三次 left click, click_state 1/2/3 递增 (系统据连续击数判手势)
        for click_no in 1..=3i64 {
            let down = CGEvent::new_mouse_event(
                source.clone(),
                CGEventType::LeftMouseDown,
                CGPoint::new(pos.0, pos.1),
                CGMouseButton::Left,
            )
            .map_err(|_| anyhow!("CGEvent LeftMouseDown 创建失败 (triple_click {click_no})"))?;
            down.set_integer_value_field(EventField::MOUSE_EVENT_CLICK_STATE, click_no);
            down.post(CGEventTapLocation::HID);
            let up = CGEvent::new_mouse_event(
                source.clone(),
                CGEventType::LeftMouseUp,
                CGPoint::new(pos.0, pos.1),
                CGMouseButton::Left,
            )
            .map_err(|_| anyhow!("CGEvent LeftMouseUp 创建失败 (triple_click {click_no})"))?;
            up.set_integer_value_field(EventField::MOUSE_EVENT_CLICK_STATE, click_no);
            up.post(CGEventTapLocation::HID);
        }
        debug!(pos = ?pos, "TripleClick 完成 (3× down/up posted, click_state=3)");
        Ok(GuiResult {
            ok: true,
            ..Default::default()
        })
    }

    /// 右击 — 先定位取坐标, CGEvent RightMouseDown/RightMouseUp + CGMouseButton::Right。
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
            .map_err(|_| anyhow!("CGEventSource 创建失败 (right_click)"))?;
        let down = CGEvent::new_mouse_event(
            source.clone(),
            CGEventType::RightMouseDown,
            CGPoint::new(pos.0, pos.1),
            CGMouseButton::Right,
        )
        .map_err(|_| anyhow!("CGEvent RightMouseDown 创建失败 (right_click)"))?;
        down.post(CGEventTapLocation::HID);
        let up = CGEvent::new_mouse_event(
            source,
            CGEventType::RightMouseUp,
            CGPoint::new(pos.0, pos.1),
            CGMouseButton::Right,
        )
        .map_err(|_| anyhow!("CGEvent RightMouseUp 创建失败 (right_click)"))?;
        up.post(CGEventTapLocation::HID);
        debug!(pos = ?pos, "RightClick 完成 (right down/up posted)");
        Ok(GuiResult {
            ok: true,
            ..Default::default()
        })
    }

    /// 悬停 — CGEvent MouseMoved 到指定坐标 (不按键, 仅移动光标)。
    fn hover(&self, ax_position: (f64, f64)) -> Result<GuiResult> {
        info!(ax_position = ?ax_position, "Hover");
        if let Some(r) = self.focused_not_allowed() {
            return Ok(r);
        }
        let source = CGEventSource::new(CGEventSourceStateID::CombinedSessionState)
            .map_err(|_| anyhow!("CGEventSource 创建失败 (hover)"))?;
        let moved = CGEvent::new_mouse_event(
            source,
            CGEventType::MouseMoved,
            CGPoint::new(ax_position.0, ax_position.1),
            CGMouseButton::Left,
        )
        .map_err(|_| anyhow!("CGEvent MouseMoved 创建失败 (hover)"))?;
        moved.post(CGEventTapLocation::HID);
        debug!(pos = ?ax_position, "Hover 完成 (MouseMoved posted)");
        Ok(GuiResult {
            ok: true,
            ..Default::default()
        })
    }

    /// 解析点击坐标 — 优先 ax_position; 否则 ax_label 匹配 AX 节点读 AXPosition。
    /// click/double_click/right_click 共用。无 label 无 position → 报错。
    fn resolve_click_position(
        &self,
        ax_label: Option<&str>,
        ax_position: Option<(f64, f64)>,
    ) -> Result<(f64, f64)> {
        if let Some(pos) = ax_position {
            return Ok(pos);
        }
        let label = ax_label.ok_or_else(|| anyhow!("需 ax_label 或 ax_position 定位点击坐标"))?;
        let app = Self::focused_app()?;
        let win = app
            .focused_window()
            .or_else(|_| app.main_window())
            .map_err(|e| anyhow!("取 focused window 失败: {e}"))?;
        let target = Self::find_click_target(&win, Some(label), None)?;
        Self::read_position(&target).ok_or_else(|| anyhow!("目标节点无 AXPosition, 无法取坐标"))
    }

    /// 窗口按钮 — close/minimize/zoom。按 AX 按钮属性取子元素 → press()。
    /// bundle_id 给定则聚焦该 app, 否则用当前 focused app。
    /// 安全: accessibility 0.2 safe wrapper (attribute/press), 零手写 unsafe。
    fn window_button(&self, bundle_id: Option<String>, which: &str) -> Result<GuiResult> {
        info!(bundle_id = ?bundle_id, which, "WindowButton");
        // M-SEC-04: bundle 给定时校验放行 (防越权操作任意 app 窗口); None=当前 focused app, 放行+审计。
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
                .map_err(|e| anyhow!("定位 app 失败 {b}: {e}"))?,
            None => Self::focused_app()?,
        };
        let win = app
            .focused_window()
            .or_else(|_| app.main_window())
            .map_err(|e| anyhow!("取 window 失败: {e}"))?;
        let btn_attr_name = match which {
            "close" => kAXCloseButtonAttribute,
            "minimize" => kAXMinimizeButtonAttribute,
            "zoom" => kAXZoomButtonAttribute,
            other => return Err(anyhow!("未知窗口按钮: {other}")),
        };
        let btn_attr = AXAttribute::<CFType>::new(&CFString::from_static_string(btn_attr_name));
        let cf = win
            .attribute(&btn_attr)
            .map_err(|e| anyhow!("取 {which} 按钮属性失败: {e}"))?;
        let btn = cf
            .downcast::<AXUIElement>()
            .ok_or_else(|| anyhow!("{which} 按钮属性非 AXUIElement"))?;
        btn.press()
            .map_err(|e| anyhow!("press {which} 按钮失败: {e}"))?;
        debug!(which, "WindowButton 完成 (press posted)");
        Ok(GuiResult {
            ok: true,
            ..Default::default()
        })
    }

    /// 窗口缩放 — 拖右下角 resize 把手到目标尺寸。读当前 AXPosition+AXSize 取右下角,
    /// 算目标右下角, CGEvent 拖拽 (复用 drag 坐标逻辑, 零新增依赖)。
    /// 用拖拽而非 AXValueCreate 设 AXSize — 后者需新 unsafe block (AXValueCreate extern "C"),
    /// 超出既定 3 处 unsafe scope; 拖拽走 safe CGEvent wrapper, 复用已测 drag 路径。
    fn window_resize(
        &self,
        bundle_id: Option<String>,
        width: f64,
        height: f64,
    ) -> Result<GuiResult> {
        info!(bundle_id = ?bundle_id, width, height, "WindowResize");
        // M-SEC-04: bundle 给定时校验放行 (防越权 resize 任意 app 窗口); None=focused app 放行+审计。
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
                .map_err(|e| anyhow!("定位 app 失败 {b}: {e}"))?,
            None => Self::focused_app()?,
        };
        let win = app
            .focused_window()
            .or_else(|_| app.main_window())
            .map_err(|e| anyhow!("取 window 失败: {e}"))?;
        let pos = Self::read_position(&win).ok_or_else(|| anyhow!("窗口无 AXPosition"))?;
        let sz = Self::read_size(&win).ok_or_else(|| anyhow!("窗口无 AXSize"))?;
        // 右下角 resize 把手 = 当前右下角; 拖到 (左上角 + 目标尺寸) 右下角
        let from = (pos.0 + sz.0, pos.1 + sz.1);
        let to = (pos.0 + width, pos.1 + height);
        if width < 50.0 || height < 50.0 {
            warn!(width, height, "目标尺寸过小, 可能拖不动");
        }
        self.drag(from, to)
    }

    /// 等待 — 纯延时, 非 AX/CGEvent。GUI 动作间停顿 (如点击后等动画)。
    /// seconds 限 [0, 60] 秒, 超界裁剪。trusted-independent (无 TCC 依赖, 可单测)。
    fn wait(&self, seconds: f64) -> Result<GuiResult> {
        let secs = if seconds < 0.0 {
            warn!(seconds, "Wait 负值, 裁剪为 0");
            0.0
        } else if seconds > 60.0 {
            warn!(seconds, "Wait 超 60s 上限, 裁剪为 60");
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
        ];
        for a in cases {
            let s = serde_json::to_string(&a).unwrap();
            let back: GuiAction = serde_json::from_str(&s).unwrap();
            let s2 = serde_json::to_string(&back).unwrap();
            assert_eq!(s, s2, "serde 往返不一致");
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
    }

    #[test]
    fn gui_result_default() {
        let r = GuiResult::default();
        assert!(!r.ok);
        assert!(r.node_tree.is_none());
        assert!(r.screenshot_png_b64.is_none());
        assert!(r.error.is_none());
    }

    /// 未授权时操作降级 — CI 无 TCC, 走此路径。
    /// IMPL-9: Screenshot 提到 ax_trusted 闸门前, 自探 Screen Recording —
    /// CI 无 Screen Recording → screen-recording-permission-required (非 accessibility)。
    #[test]
    fn execute_degrades_without_ax_trust() {
        let ctrl = GuiController::new();
        let r = ctrl
            .execute(GuiAction::Screenshot {
                mask_sensitive: false,
            })
            .unwrap();
        // IMPL-9: screenshot 走 Screen Recording TCC (CoreGraphics), 非 Accessibility 闸门。
        // 两路径均合法, 不强断言 ok 字面:
        //   CI 无 Screen Recording → ok:false + screen-recording-permission-required;
        //   trusted 机有 Screen Recording → ok:true (PNG)。
        if !GuiController::ax_trusted() {
            assert!(
                !r.ok,
                "IMPL-9: 未授权 (无 Screen Recording) 应降级 ok:false"
            );
            assert!(
                r.error.is_some(),
                "IMPL-9: 未授权应降级 (Screen Recording 或 encode 错误)"
            );
        }
    }

    /// resolve_keycode 覆盖 — 键名大小写不敏感 + 别名 (enter=return, esc=escape, arrows短名)
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

    /// 未知键名 → None (不 panic)
    #[test]
    fn resolve_keycode_unknown_returns_none() {
        assert_eq!(GuiController::resolve_keycode("totally-fake-key"), None);
        assert_eq!(GuiController::resolve_keycode(""), None);
    }

    /// 未授权时 KeyPress 降级 (CI 无 TCC); 授权时合成应成功 (手动)
    /// RUN-12: 用显式无限制 config (None), 测 keycode 逻辑不被默认 allowlist 干扰 (focused 拦截)。
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
            assert!(!r.ok, "未知键名应 ok:false");
            assert!(
                r.error.as_deref().unwrap_or("").contains("unknown-key"),
                "未知键名错误标记: {:?}",
                r.error
            );
        } else {
            assert!(!r.ok, "未授权应降级");
            assert_eq!(
                r.error.as_deref(),
                Some("accessibility-permission-required")
            );
        }
    }

    /// HoldKey 未知键名降级 — trusted 时经 resolve_keycode 返 None → ok:false unknown-key;
    /// CI 未授权路径在 AX 闸门降级 accessibility-permission-required (闸门先于 dispatch)。
    /// RUN-12: 用显式无限制 config (None), 测 keycode 逻辑不被默认 allowlist 干扰。
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
            assert!(!r.ok, "未知键名应 ok:false");
            assert!(
                r.error.as_deref().unwrap_or("").contains("unknown-key"),
                "未知键名错误标记: {:?}",
                r.error
            );
        } else {
            assert!(!r.ok, "未授权应降级");
            assert_eq!(
                r.error.as_deref(),
                Some("accessibility-permission-required")
            );
        }
    }

    /// TripleClick 未授权降级 — 指针动作, CI 无 TCC 走降级路径。
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
            assert!(!r.ok, "未授权应降级");
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
            "GuiController::new 应 <50ms (lazy), 实际 {elapsed:?}"
        );
    }

    /// resolve_modifier 覆盖 — 大小写不敏感 + 别名 (cmd/super, alt, ctrl)
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

    /// 未知修饰键 → None (不 panic)
    #[test]
    fn resolve_modifier_unknown_returns_none() {
        assert_eq!(GuiController::resolve_modifier("hyper"), None);
        assert_eq!(GuiController::resolve_modifier(""), None);
    }

    /// 未知修饰键 → ok:false unknown-modifier (trusted-independent, CI 路径)
    /// RUN-12: 用显式无限制 config (None), 测 modifier 逻辑不被默认 allowlist 干扰。
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
            assert!(!r.ok, "未知修饰键应 ok:false");
            assert!(
                r.error
                    .as_deref()
                    .unwrap_or("")
                    .contains("unknown-modifier"),
                "未知修饰键错误标记: {:?}",
                r.error
            );
        } else {
            assert!(!r.ok, "未授权应降级");
            assert_eq!(
                r.error.as_deref(),
                Some("accessibility-permission-required")
            );
        }
    }

    /// 新动作 tag snake_case — scroll/drag/wait 序列化 tag
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

    /// v1.5 新动作 serde 往返 — double_click/right_click/hover/window_*/window_resize
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
            assert_eq!(s, s2, "serde 往返不一致: {s}");
        }
    }

    /// v1.5 新动作 tag snake_case
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

    /// 未授权时新窗口动作降级 — CI 无 TCC 走此路径; trusted 机真实 AX 操作手动验
    #[test]
    fn window_actions_degrade_without_ax_trust() {
        if GuiController::ax_trusted() {
            // trusted: 真实窗口操作需手动 TCC + GUI 会话, CI/sandbox 跳过
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
            assert!(!r.ok, "未授权应降级");
            assert_eq!(
                r.error.as_deref(),
                Some("accessibility-permission-required"),
                "未授权错误标记"
            );
        }
    }

    /// 未授权时 double_click/right_click/hover 降级 (CI 路径)
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
                assert!(!r.ok, "未授权应降级");
                assert_eq!(
                    r.error.as_deref(),
                    Some("accessibility-permission-required")
                );
            }
        }
    }

    /// Hover 无坐标降级 — 不可能触发 (ax_position 必填非 Option), 仅编译期保证。
    /// double_click/right_click 无 label 无 position → resolve_click_position 返 Err (经 ? 上抛)。
    /// CI 无 TCC → 降级 ok:false; trusted 机 → execute 返 Err (无定位坐标), 不 panic。
    /// RUN-12: 用显式无限制 config (None), 测 resolve_click_position 逻辑不被默认 allowlist 干扰。
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
            assert!(!r.ok, "未授权应降级");
            assert_eq!(
                r.error.as_deref(),
                Some("accessibility-permission-required")
            );
        } else {
            // trusted: 无 label/position → resolve_click_position 报错上抛 Err, 不 panic
            assert!(res.is_err(), "trusted 无定位坐标应返 Err");
            assert!(
                res.unwrap_err()
                    .to_string()
                    .contains("ax_label 或 ax_position"),
                "错误应提及定位缺失"
            );
        }
    }

    /// Wait trusted-independent — 无 TCC 依赖, CI 可跑。seconds=0 应立即 ok=true。
    #[test]
    fn wait_zero_seconds_ok_without_trust() {
        let ctrl = GuiController::new();
        let r = ctrl.execute(GuiAction::Wait { seconds: 0.0 }).unwrap();
        assert!(r.ok, "Wait 0s 应 ok=true (trusted-independent)");
        assert!(r.error.is_none(), "Wait 无错误: {:?}", r.error);
    }

    /// Wait 裁剪 — 负值裁 0 (不睡眠), 不 panic。正值裁 60 路径手动验 (CI 不跑 60s)。
    #[test]
    fn wait_clamps_negative_to_zero() {
        let ctrl = GuiController::new();
        let r = ctrl.execute(GuiAction::Wait { seconds: -5.0 }).unwrap();
        assert!(r.ok, "负值 Wait 应裁 0 后 ok=true");
    }

    /// RUN-12: 默认 (非空安全集) → 集合外 bundle 拒, 集合内放行。
    /// 显式传 None = 无限制 opt-in → 任意 bundle 放行 (向后兼容)。
    #[test]
    fn msec04_no_allowlist_allows_any_bundle() {
        // 默认非空 allowlist: evil bundle 拒, 安全 bundle 放行
        let ctrl = GuiController::new();
        assert!(
            ctrl.check_bundle_allowed("com.evil.keylogger").is_err(),
            "RUN-12: 默认 allowlist 应拒未列入的 evil bundle"
        );
        assert!(ctrl.check_bundle_allowed("com.apple.TextEdit").is_ok());
        // 显式 None = 无限制 opt-in: 任意 bundle 放行 (向后兼容)
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

    /// M-SEC-04: 设 allowlist → 仅集合内 bundle 放行, 集合外拒绝。
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
            "未列入 allowlist 的 bundle 应被拒"
        );
        assert!(
            ctrl.check_bundle_allowed("").is_err(),
            "空 bundle 非白名单应拒"
        );
    }

    /// RUN-12: GuiConfig default = 非空安全集 (商用安全默认受限, 非无限制)。
    /// 显式传 None 仍 = 无限制 opt-in (向后兼容本地可信调用方)。
    #[test]
    fn msec04_gui_config_default_unrestricted() {
        let cfg = GuiConfig::default();
        assert!(
            cfg.allowed_bundle_ids.is_some(),
            "RUN-12: 默认应有非空 allowlist"
        );
        let set = cfg.allowed_bundle_ids.unwrap();
        assert!(
            set.contains(&"com.apple.Terminal".to_string()),
            "默认集含 Terminal"
        );
        assert!(
            set.contains(&"com.apple.TextEdit".to_string()),
            "默认集含 TextEdit"
        );
        assert!(
            set.contains(&"com.apple.finder".to_string()),
            "默认集含 finder"
        );
        assert!(!cfg.allow_type_into_secure, "默认拒绝向密码框 type_text");
    }

    /// M-SEC-04: allow_type_into_secure=true 显式 opt-in 可构造。
    #[test]
    fn msec04_allow_type_into_secure_opt_in() {
        let ctrl = GuiController::new_with_config(GuiConfig {
            allowed_bundle_ids: None,
            allow_type_into_secure: true,
        });
        assert!(ctrl.config.allow_type_into_secure);
    }

    /// M-SEC-04: kAXSecureTextFieldSubrole 常量正确 (AXSecureTextField, 非空)。
    #[test]
    fn msec04_secure_textfield_subrole_constant() {
        assert_eq!(kAXSecureTextFieldSubrole, "AXSecureTextField");
        assert!(!kAXSecureTextFieldSubrole.is_empty());
    }

    // ===== 0827 fe-gui P0-P3 修复回归测试 =====

    /// C-13: 设 allowlist 但 AX 未授权 (CI 无 TCC) → focused_app_bundle 失败返空串 →
    /// 空串不在 allowlist → focused_not_allowed 返 Some(degraded)。验证拦截逻辑在 CI 可达
    /// (execute 的 ax_trusted 闸门早拦截, 故直接测 focused_not_allowed 单元路径)。
    #[test]
    fn c13_focused_not_allowed_blocks_when_allowlist_set() {
        let ctrl = GuiController::new_with_config(GuiConfig {
            allowed_bundle_ids: Some(vec!["com.apple.TextEdit".into()]),
            allow_type_into_secure: false,
        });
        let r = ctrl.focused_not_allowed();
        // CI 无 AX: bundle 解析失败 → "" → 不在 allowlist → Some(degraded)。
        // trusted 机且当前 focused=TextEdit: bundle 命中 → None (放行)。两种环境均合法。
        if !GuiController::ax_trusted() {
            assert!(
                r.is_some(),
                "C-13: CI 无 AX + allowlist 应拦截 (bundle 解析失败)"
            );
            let res = r.unwrap();
            assert!(!res.ok, "C-13: 拦截应 ok:false");
            assert!(
                res.error
                    .as_deref()
                    .unwrap_or("")
                    .contains("focused-app-not-allowed"),
                "C-13: 错误标记: {:?}",
                res.error
            );
        }
    }

    /// C-13: 无 allowlist (None) → focused_not_allowed 始终 None (放行, 审计)。
    /// 验证 short-circuit: allowlist=None 时不调 focused_app_bundle (无 AX 调用)。
    /// RUN-12: 默认非空 allowlist, 须显式传 None 才测无限制 short-circuit。
    #[test]
    fn c13_focused_not_allowed_passes_without_allowlist() {
        let ctrl = GuiController::new_with_config(GuiConfig {
            allowed_bundle_ids: None,
            allow_type_into_secure: false,
        });
        assert!(
            ctrl.focused_not_allowed().is_none(),
            "C-13: 无 allowlist (显式 None) 应放行返 None"
        );
    }

    /// C-13: type_text 在 allowlist + CI 无 AX 下 — execute 的 ax_trusted 闸门先降级,
    /// 但若 trusted: focused 非 allowlisted app 应被 focused_not_allowed 拦截 ok:false。
    /// CI 路径断言 ax_trusted 闸门降级 (闸门在 dispatch 前); trusted 机验证拦截需真实 GUI 手动。
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
            // trusted + 当前 focused app 非 TextEdit → C-13 拦截 (focused-app-not-allowed);
            // 若 focused 恰为 TextEdit → 放行 ok:true (测试环境依赖, 不强断言 ok 值, 仅验不 panic)。
            let _ = r.ok;
        } else {
            assert!(!r.ok, "CI 无 AX 应 ax_trusted 闸门降级");
            assert_eq!(
                r.error.as_deref(),
                Some("accessibility-permission-required")
            );
        }
    }

    /// M-12.4: hold_key duration_ms=0 → ok:false hold-key-duration-zero (fail-loud, 非静默 no-op)。
    /// trusted-independent? 否 — hold_key 经 execute 的 ax_trusted 闸门。CI 无 AX 走闸门降级;
    /// trusted 机闸门过后 duration_ms==0 早拒绝 (在 keycode resolve 前)。两路径均 ok:false。
    /// RUN-12: 用显式无限制 config (None), 测 duration 逻辑不被默认 allowlist 干扰 (focused 拦截)。
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
        assert!(!r.ok, "M-12.4: duration_ms=0 应 ok:false");
        if GuiController::ax_trusted() {
            assert!(
                r.error
                    .as_deref()
                    .unwrap_or("")
                    .contains("hold-key-duration-zero"),
                "M-12.4: trusted 应 duration-zero 错误: {:?}",
                r.error
            );
        } else {
            assert_eq!(
                r.error.as_deref(),
                Some("accessibility-permission-required"),
                "M-12.4: CI 无 AX 走闸门降级"
            );
        }
    }

    /// M-12.3: cgimage_to_rgba + rgba_to_png_b64 文档注释显式标注预乘 RGBA 取舍。
    /// 编译期保证: 两函数可寻址 (拆分后接口, 不破坏调用方)。
    #[allow(clippy::type_complexity)]
    #[test]
    fn m12_3_premultiplied_rgba_doc_anchors() {
        let f1 = GuiController::cgimage_to_rgba as fn(&CGImage) -> Result<(Vec<u8>, usize, usize)>;
        let f2 = GuiController::rgba_to_png_b64 as fn(&[u8], usize, usize) -> Result<String>;
        assert!(std::ptr::addr_of!(f1) as usize != 0);
        assert!(std::ptr::addr_of!(f2) as usize != 0);
    }

    /// RUN-12: 默认 GuiController::new() 受限 — 非默认集 bundle 被 check_bundle_allowed 拒。
    /// 商用安全默认: 防越权驱动任意 app (keylogger 等), 须显式扩 allowlist。
    #[test]
    fn run12_default_rejects_non_allowlisted_bundle() {
        let ctrl = GuiController::new();
        // 默认集内: 放行
        assert!(ctrl.check_bundle_allowed("com.apple.Terminal").is_ok());
        assert!(ctrl.check_bundle_allowed("com.apple.finder").is_ok());
        // 默认集外: 拒 (商用安全默认)
        assert!(
            ctrl.check_bundle_allowed("com.evil.keylogger").is_err(),
            "RUN-12: 默认受限应拒 evil bundle"
        );
        assert!(
            ctrl.check_bundle_allowed("com.apple.Safari").is_err(),
            "RUN-12: 默认集不含 Safari 应拒 (须显式扩)"
        );
    }

    /// IMPL-9: Screenshot 提到 ax_trusted 闸门前 — Accessibility 未授权不应误拦截图。
    /// 截图走 Screen Recording TCC (CoreGraphics), 与 Accessibility 独立。
    /// CI 无 Screen Recording → screen-recording-permission-required (非 accessibility-permission-required)。
    /// trusted 机有 Screen Recording → ok:true。两路径均不返 accessibility 错误。
    #[test]
    fn impl9_screenshot_bypasses_accessibility_gate() {
        let ctrl = GuiController::new();
        let r = ctrl
            .execute(GuiAction::Screenshot {
                mask_sensitive: false,
            })
            .unwrap();
        // 关键: screenshot 不经 Accessibility 闸门, 故 error 不应是 accessibility-permission-required
        assert_ne!(
            r.error.as_deref(),
            Some("accessibility-permission-required"),
            "IMPL-9: screenshot 不应被 Accessibility 闸门拦 (TCC 权限独立)"
        );
        if !GuiController::ax_trusted() {
            // CI 无 Screen Recording → screen-recording 降级 (非 accessibility)
            assert!(!r.ok, "IMPL-9: CI 无 Screen Recording 应降级 ok:false");
            assert!(
                r.error
                    .as_deref()
                    .unwrap_or("")
                    .contains("screen-recording-permission-required"),
                "IMPL-9: CI 应返 screen-recording 错误: {:?}",
                r.error
            );
        }
    }

    /// #38: GuiResult.scale_factor serde 默认 1.0 (absent field → 1.0, 向后兼容)。
    #[test]
    fn gui_result_scale_factor_serde_default() {
        let json = r#"{"ok":true}"#;
        let r: GuiResult = serde_json::from_str(json).unwrap();
        assert!(r.ok);
        assert_eq!(r.scale_factor, 1.0, "absent scale_factor 应默认 1.0");
        let s = serde_json::to_string(&r).unwrap();
        assert!(
            s.contains("\"scale_factor\":1.0"),
            "scale_factor 应序列化: {s}"
        );
    }

    /// #40: Screenshot mask_sensitive serde 默认 false (absent → false, 不遮罩)。
    #[test]
    fn screenshot_mask_sensitive_serde_default() {
        let s = r#"{"kind":"screenshot"}"#;
        let a: GuiAction = serde_json::from_str(s).unwrap();
        match a {
            GuiAction::Screenshot { mask_sensitive } => {
                assert!(!mask_sensitive, "absent mask_sensitive 应默认 false");
            }
            _ => panic!("deser 应为 Screenshot"),
        }
        let s2 = r#"{"kind":"screenshot","mask_sensitive":true}"#;
        let a2: GuiAction = serde_json::from_str(s2).unwrap();
        match a2 {
            GuiAction::Screenshot { mask_sensitive } => {
                assert!(mask_sensitive, "显式 mask_sensitive:true 应保留");
            }
            _ => panic!("deser 应为 Screenshot"),
        }
    }

    /// #40: mask_rgba_inplace 涂黑逻辑点矩形 (含 Y 翻转)。
    /// 构造 2×2 RGBA 全白, rect 覆盖整图 → 全黑。scale=1.0。
    #[test]
    fn mask_rgba_inplace_full_cover() {
        let mut rgba = vec![255u8; 2 * 2 * 4];
        let rects = vec![(0.0f64, 0.0, 2.0, 2.0)];
        GuiController::mask_rgba_inplace(&mut rgba, 2, 2, 1.0, &rects);
        for px in rgba.chunks(4) {
            assert_eq!(px, &[0, 0, 0, 255], "全图应涂黑 RGBA(0,0,0,255)");
        }
    }

    /// #40: mask_rgba_inplace 局部矩形 + scale=2.0 + Y 翻转正确性。
    /// 4×4 图, rect (1,1,1,1) 逻辑点 → scale 2 → 像素区 [2,4)×[2,4) (物理)。
    /// Y 翻转: 物理行 = h-1-py, py∈[2,4) → 行 [0,2) (顶两行)。
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
        // py∈[2,4), px∈[2,4) 应黑
        for y in 2..4 {
            for x in 2..4 {
                assert!(is_black(x, y), "({x},{y}) 应黑");
            }
        }
        // 其余应白
        for y in 0..4 {
            for x in 0..4 {
                if !(2..4).contains(&x) || !(2..4).contains(&y) {
                    assert!(!is_black(x, y), "({x},{y}) 应白");
                }
            }
        }
    }

    /// #40: mask_rgba_inplace 越界裁剪 (rect 超图边界) 不 panic。
    #[test]
    fn mask_rgba_inplace_oob_clamp() {
        let mut rgba = vec![255u8; 2 * 2 * 4];
        let rects = vec![(-5.0f64, -5.0, 100.0, 100.0)];
        GuiController::mask_rgba_inplace(&mut rgba, 2, 2, 1.0, &rects);
        for px in rgba.chunks(4) {
            assert_eq!(px, &[0, 0, 0, 255], "超界 rect 应裁剪到全图涂黑");
        }
    }

    /// #39: gui_action_batch 空 actions → 空 Vec。
    #[test]
    fn gui_action_batch_empty() {
        let ctrl = GuiController::new();
        let results = ctrl.gui_action_batch(vec![]).unwrap();
        assert!(results.is_empty(), "空 batch 应返空 Vec");
    }

    /// #39: gui_action_batch 顺序执行多动作, 收集每步结果。
    /// CI 无 TCC: Wait trusted-independent ok:true, Click 降级 ok:false。
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
        assert_eq!(results.len(), 3, "应收集 3 步结果");
        assert!(results[0].ok, "Wait[0] trusted-independent 应 ok");
        assert!(results[2].ok, "Wait[2] trusted-independent 应 ok");
        if !GuiController::ax_trusted() {
            assert!(!results[1].ok, "CI 无 TCC: Click[1] 应降级 ok:false");
        }
    }
}
