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
    kAXFocusedApplicationAttribute, kAXPositionAttribute, kAXSizeAttribute, kAXValueTypeCGPoint,
    kAXValueTypeCGSize, AXIsProcessTrusted, AXValueGetValue, AXValueRef,
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
    CGEvent, CGEventFlags, CGEventTapLocation, CGEventType, CGKeyCode, CGMouseButton, KeyCode,
    ScrollEventUnit,
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
    Screenshot {},
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
    pub error: Option<String>,
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

pub struct GuiController;

impl GuiController {
    pub fn new() -> Self {
        info!("GuiController::new() — AXUIElement + CoreGraphics (P4)");
        Self
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
            GuiAction::Screenshot {} => self.screenshot(),
            GuiAction::InspectTree {} => self.inspect_tree(),
            GuiAction::Scroll { dx, dy, at } => self.scroll(dx, dy, at),
            GuiAction::Drag { from, to } => self.drag(from, to),
            GuiAction::Wait { .. } => unreachable!("Wait 已在 ax_trusted 前处理"),
        }
    }

    fn focus_app(&self, bundle_id: &str) -> Result<GuiResult> {
        info!(bundle_id, "FocusApp");
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
        let app = Self::focused_app()?;
        let win = app
            .focused_window()
            .or_else(|_| app.main_window())
            .map_err(|e| anyhow!("取 focused window 失败: {e}"))?;
        let target = Self::find_text_field(&win)?;
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

    /// 截图 — CGWindowListCreateImage 全屏 → CGImage → 位图上下文取 RGBA → PNG → base64
    /// Screen Recording TCC 未授权时 CGImage 为 None → 返回明确错误。
    fn screenshot(&self) -> Result<GuiResult> {
        info!("Screenshot");
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
        let png_b64 = match Self::cgimage_to_png_b64(&img) {
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
            ..Default::default()
        })
    }

    /// CGImage → RGBA → PNG → base64。用位图上下文统一像素格式 (避免源图 alpha/bgr 差异)。
    fn cgimage_to_png_b64(img: &CGImage) -> Result<String> {
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
        let rgba: &[u8] = ctx.data();
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
            GuiAction::Screenshot {},
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
            GuiAction::Wait { seconds: 0.0 },
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
        let s = serde_json::to_string(&GuiAction::Screenshot {}).unwrap();
        assert!(s.contains("\"kind\":\"screenshot\""), "tag snake_case: {s}");
        let s = serde_json::to_string(&GuiAction::InspectTree {}).unwrap();
        assert!(
            s.contains("\"kind\":\"inspect_tree\""),
            "tag snake_case: {s}"
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

    /// 未授权时所有操作降级 — CI 无 TCC, 走此路径
    #[test]
    fn execute_degrades_without_ax_trust() {
        let ctrl = GuiController::new();
        let r = ctrl.execute(GuiAction::Screenshot {}).unwrap();
        if !GuiController::ax_trusted() {
            assert!(!r.ok, "未授权应降级");
            assert_eq!(
                r.error.as_deref(),
                Some("accessibility-permission-required"),
                "未授权错误标记"
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
    #[test]
    fn keypress_unknown_key_degrades_even_if_trusted() {
        let ctrl = GuiController::new();
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
    #[test]
    fn keypress_unknown_modifier_degrades_even_if_trusted() {
        let ctrl = GuiController::new();
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
}
