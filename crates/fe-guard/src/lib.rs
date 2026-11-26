// fe-guard: fusion-guard Phase 3 consumer-side sync UDS client + local wire mirror + rule cache.
// Cross-project constraint: fusion-guard is READ-ONLY — this crate only mirrors the guard wire
// contract (no path dep into fusion-guard), keeping fusion-executor builds independent.
// crate unsafe_code="deny" inherited from the workspace.
//
// wire contract (verified from fusion-guard read-only source):
//   framing = newline-delimited JSON (FRAMING_BYTE=0x0A, MAX_LINE_BYTES=1MB), REQ_TIMEOUT_SECS=2.
//   guard.ping        -> {pong:bool, version:String, rules_epoch:u64}
//   guard.evaluate    params positional: [content(0), caller_epoch(1,u64), tenant_id(2),
//                        requester(3), action(4), content_type(5,def"shell"), category_hint(6,opt)]
//                      -> GuardVerdict
//   guard.rules.dump  -> {rules:Vec<GuardRule>, epoch:u64}  (regex-stage rules only)
//   error codes: -32001 Unauthorized/Forbidden, -32002 RateLimited, -32003 StaleEpoch,
//                -32010 Engine/timeout/internal/connection-limit

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, warn};

// ---------- wire mirror types ----------

// Risk level (lowercase serialization l1/l2/l3/l4, repr u8, L4=highest=absolute Block).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub enum RiskLevel {
    L1 = 0,
    L2 = 1,
    L3 = 2,
    L4 = 3,
}

impl RiskLevel {
    pub fn rank(self) -> u8 {
        self as u8
    }
}

impl PartialOrd for RiskLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RiskLevel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

// Security action (lowercase: allow|preview|redact|block; severity order Block>Redact>Preview>Allow).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GuardAction {
    Allow,
    Preview,
    Redact,
    Block,
}

impl GuardAction {
    pub fn severity(self) -> u8 {
        match self {
            GuardAction::Allow => 0,
            GuardAction::Preview => 1,
            GuardAction::Redact => 2,
            GuardAction::Block => 3,
        }
    }

    pub fn is_block(self) -> bool {
        matches!(self, GuardAction::Block)
    }
}

// Scan stage (lowercase: regex|ast|semantic).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStage {
    Regex,
    Ast,
    Semantic,
}

// Rule scope (lowercase; mirrors fields of guard.rules.dump items, plays no decision role
// in this crate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleScope {
    Command,
    Content,
    Network,
    Filesystem,
}

// guard.evaluate verdict (mirrors fg-core GuardVerdict).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardVerdict {
    pub action: GuardAction,
    pub risk_level: RiskLevel,
    pub reason: String,
    pub stage: CheckStage,
    #[serde(default)]
    pub requires_approval: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redacted_content: Option<String>,
    #[serde(default)]
    pub seatbelt_required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_id: Option<uuid::Uuid>,
    #[serde(default)]
    pub verdict_epoch: u64,
    #[serde(default)]
    pub verdict_ttl_secs: u32,
    #[serde(default)]
    pub inferred_category: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category_hint: Option<String>,
}

impl GuardVerdict {
    // high_risk judgment (consistent with guard itself): L3||L4 OR action==Block.
    pub fn high_risk(&self) -> bool {
        matches!(self.risk_level, RiskLevel::L3 | RiskLevel::L4) || self.action.is_block()
    }
}

// regex-stage rule item returned by guard.rules.dump (mirrors fg-rules GuardRule).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardRule {
    pub name: String,
    pub pattern: String,
    pub stage: CheckStage,
    pub action: GuardAction,
    pub risk_level: RiskLevel,
    pub reason: String,
    pub scope: RuleScope,
}

// guard.rules.dump envelope {rules, epoch}.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSet {
    pub rules: Vec<GuardRule>,
    pub epoch: u64,
}

// guard.ping response.
#[derive(Debug, Clone, Deserialize)]
pub struct GuardPing {
    pub pong: bool,
    pub version: String,
    pub rules_epoch: u64,
}

// ---------- errors ----------

// Client error. `code` maps to the guard JSON-RPC error code; any IO/timeout/connection
// failure → Unavailable (fail-closed).
#[derive(Debug, Error)]
pub enum GuardError {
    #[error("guard unreachable: {0}")]
    Unavailable(String),
    #[error("guard request timeout")]
    Timeout,
    #[error("guard unauthorized: {0}")]
    Unauthorized(String),
    #[error("guard rate limited")]
    RateLimited,
    #[error("guard stale epoch: caller={caller} guard={guard}")]
    StaleEpoch { caller: u64, guard: u64 },
    #[error("guard internal error: {0}")]
    Engine(String),
    #[error("guard bad response: {0}")]
    BadResponse(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
}

// ---------- sync UDS client ----------

const REQ_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_LINE_BYTES: usize = 1024 * 1024;

// JSON-RPC request envelope (params as a positional array, aligned with the guard evaluate
// positional contract).
#[derive(Debug, Serialize)]
struct RpcRequest {
    jsonrpc: &'static str,
    id: u64,
    method: &'static str,
    params: serde_json::Value,
}

// JSON-RPC response envelope (result or error, one of the two).
#[derive(Debug, Deserialize)]
struct RpcResponse {
    #[allow(dead_code)]
    jsonrpc: Option<String>,
    id: Option<u64>,
    result: Option<serde_json::Value>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i32,
    message: String,
}

// Sync client without tokio (fe-security is a sync crate). A fresh connection per call
// (evaluate is not a hot path, once per command; pooling needs a framing state machine +
// id demux with no benefit, ~0.5ms connect is acceptable).
#[derive(Debug, Clone)]
pub struct GuardClient {
    sock: PathBuf,
    tenant: String,
    id_counter: Arc<AtomicU64>,
}

impl GuardClient {
    pub fn new<P: Into<PathBuf>>(sock: P, tenant: String) -> Self {
        Self {
            sock: sock.into(),
            tenant,
            id_counter: Arc::new(AtomicU64::new(1)),
        }
    }

    pub fn sock(&self) -> &Path {
        &self.sock
    }

    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    fn next_id(&self) -> u64 {
        self.id_counter.fetch_add(1, Ordering::Relaxed)
    }

    // Send one JSON-RPC request and read a single-line response (per-call connection).
    // Error codes map to GuardError; IO/timeout/connection failure → Unavailable (the caller
    // branches its fail-closed fallback on this).
    fn call(
        &self,
        method: &'static str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, GuardError> {
        let id = self.next_id();
        let req = RpcRequest {
            jsonrpc: "2.0",
            id,
            method,
            params,
        };
        let mut payload = serde_json::to_vec(&req)?;
        payload.push(b'\n');

        // Connect failure = guard down → Unavailable (not the Io variant, clearer semantics
        // for the fallback path to branch on).
        let mut stream = match UnixStream::connect(&self.sock) {
            Ok(s) => s,
            Err(e) => {
                debug!(error = %e, sock = ?self.sock, "guard connect failed");
                return Err(GuardError::Unavailable(format!("connect: {e}")));
            }
        };
        stream.set_read_timeout(Some(REQ_TIMEOUT))?;
        stream.set_write_timeout(Some(REQ_TIMEOUT))?;

        stream.write_all(&payload)?;

        // read_until + cumulative byte cap (aligned with guard C17 OOM guard; take(MAX_LINE_BYTES+1)).
        let mut reader = BufReader::new(&stream);
        let mut line: Vec<u8> = Vec::new();
        reader
            .by_ref()
            .take((MAX_LINE_BYTES + 1) as u64)
            .read_until(b'\n', &mut line)?;
        if line.len() > MAX_LINE_BYTES {
            return Err(GuardError::BadResponse(format!(
                "response exceeded {MAX_LINE_BYTES} bytes"
            )));
        }
        // Trim trailing newline.
        while line.last() == Some(&b'\n') {
            line.pop();
        }
        if line.is_empty() {
            return Err(GuardError::BadResponse("empty response".into()));
        }

        let resp: RpcResponse = serde_json::from_slice(&line)?;
        // Defensive id matching: drop lines whose id does not match (guard never replies with
        // a mismatched id on the same connection, but this is defensive).
        if let Some(rid) = resp.id {
            if rid != id {
                return Err(GuardError::BadResponse(format!(
                    "id mismatch: sent {id}, got {rid}"
                )));
            }
        }
        if let Some(err) = resp.error {
            return Err(Self::map_error(err));
        }
        resp.result
            .ok_or_else(|| GuardError::BadResponse("missing result".into()))
    }

    // JSON-RPC error code → GuardError. -32001 auth failure → Unauthorized (caller fails
    // closed, does not degrade).
    fn map_error(e: RpcError) -> GuardError {
        match e.code {
            -32001 => GuardError::Unauthorized(e.message),
            -32002 => GuardError::RateLimited,
            -32003 => {
                // guard StaleEpoch message contains caller/guard epochs; the client does not
                // parse it, preserving the original semantics.
                GuardError::StaleEpoch {
                    caller: 0,
                    guard: 0,
                }
            }
            -32010 => GuardError::Engine(e.message),
            _ => GuardError::BadResponse(format!("code {}: {}", e.code, e.message)),
        }
    }

    // guard.ping -> {pong, version, rules_epoch}.
    pub fn ping(&self) -> Result<GuardPing, GuardError> {
        let v = self.call("guard.ping", serde_json::Value::Array(vec![]))?;
        let ping: GuardPing = serde_json::from_value(v)?;
        if !ping.pong {
            return Err(GuardError::BadResponse("ping pong=false".into()));
        }
        Ok(ping)
    }

    // guard.rules.dump -> {rules, epoch}. caller_epoch is currently not validated by the
    // guard handler (only mutation paths validate it), but the positional slot is kept to
    // align with the contract.
    pub fn rules_dump(&self, caller_epoch: u64) -> Result<RuleSet, GuardError> {
        let params = serde_json::json!([caller_epoch]);
        let v = self.call("guard.rules.dump", params)?;
        let rs: RuleSet = serde_json::from_value(v)?;
        Ok(rs)
    }

    // guard.evaluate (positional params). Returns GuardVerdict.
    pub fn evaluate(
        &self,
        content: &str,
        caller_epoch: u64,
        requester: &str,
        action: &str,
        content_type: &str,
        category_hint: Option<&str>,
    ) -> Result<GuardVerdict, GuardError> {
        let mut params = vec![
            serde_json::Value::String(content.to_string()),
            serde_json::Value::Number(serde_json::Number::from(caller_epoch)),
            serde_json::Value::String(self.tenant.clone()),
            serde_json::Value::String(requester.to_string()),
            serde_json::Value::String(action.to_string()),
            serde_json::Value::String(content_type.to_string()),
        ];
        if let Some(h) = category_hint {
            params.push(serde_json::Value::String(h.to_string()));
        }
        let v = self.call("guard.evaluate", serde_json::Value::Array(params))?;
        let verdict: GuardVerdict = serde_json::from_value(v)?;
        Ok(verdict)
    }
}

// ---------- rule cache ----------

// Disk + in-memory rule cache. While guard is alive, rules_dump writes to disk + updates
// memory; guard down → load from disk into memory. Degraded mode has regex-stage rules only
// (the dump itself returns regex-stage only) and does not reproduce the guard's full verdict
// (limitation honestly labeled).
//
// Cache path: ~/.fusion-executor/guard-rules.json (HOME-private 0o600).
pub struct RulesCache {
    path: PathBuf,
    inner: Mutex<CacheInner>,
}

#[derive(Debug, Clone, Default)]
struct CacheInner {
    epoch: u64,
    // Pre-compiled regexes so the degraded path does not recompile each time (rules whose
    // parse fails are skipped + warned, never a total failure).
    compiled: Vec<Option<CompiledRule>>,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    re: regex::Regex,
    action: GuardAction,
    risk_level: RiskLevel,
    reason: String,
}

impl RulesCache {
    pub fn new(path: PathBuf) -> Self {
        let inner = Self::load_disk(&path).unwrap_or_else(|e| {
            warn!(error = %e, path = ?path, "guard rules cache load failed — cold start");
            CacheInner::default()
        });
        Self {
            path,
            inner: Mutex::new(inner),
        }
    }

    fn load_disk(path: &Path) -> Result<CacheInner, GuardError> {
        let bytes = std::fs::read(path)?;
        let rs: RuleSet = serde_json::from_slice(&bytes)?;
        Ok(Self::compile(rs))
    }

    fn compile(rs: RuleSet) -> CacheInner {
        let mut compiled = Vec::with_capacity(rs.rules.len());
        for r in &rs.rules {
            // Only regex-stage rules can be locally compiled and reproduced (the dump returns
            // regex-stage only, but filter defensively).
            if r.stage != CheckStage::Regex {
                compiled.push(None);
                continue;
            }
            match regex::Regex::new(&r.pattern) {
                Ok(re) => compiled.push(Some(CompiledRule {
                    re,
                    action: r.action,
                    risk_level: r.risk_level,
                    reason: r.reason.clone(),
                })),
                Err(e) => {
                    warn!(rule = %r.name, error = %e, "guard cached rule compile failed — skip");
                    compiled.push(None);
                }
            }
        }
        CacheInner {
            epoch: rs.epoch,
            compiled,
        }
    }

    // Refresh while guard is alive: memory + disk. A persist failure only warns (memory is
    // still fresh, not blocking).
    pub fn refresh(&self, rs: RuleSet) {
        let next = Self::compile(rs.clone());
        *self.inner.lock().expect("rules cache lock poisoned") = next;
        if let Err(e) = self.persist(&rs) {
            warn!(error = %e, path = ?self.path, "guard rules cache persist failed (in-memory still fresh)");
        }
    }

    fn persist(&self, rs: &RuleSet) -> Result<(), GuardError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(rs)?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    pub fn epoch(&self) -> u64 {
        self.inner.lock().expect("rules cache lock poisoned").epoch
    }

    // Degraded path: match content against in-memory regex rules one by one; a hit returns a
    // block verdict (action Block OR risk L3/L4). Regex-stage only, coarser than the live
    // guard (tokenizer/AST/semantic are not in the dump) — gap #2 is exactly this consequence.
    pub fn run_cached_rules(&self, content: &str) -> Option<GuardVerdict> {
        let inner = self.inner.lock().expect("rules cache lock poisoned");
        for c in inner.compiled.iter().flatten() {
            if c.re.is_match(content) {
                // A degraded hit blocks outright (guard down, fail-closed, stricter than the
                // live guard).
                if c.action.is_block() || matches!(c.risk_level, RiskLevel::L3 | RiskLevel::L4) {
                    return Some(GuardVerdict {
                        action: GuardAction::Block,
                        risk_level: c.risk_level,
                        reason: format!("guard unreachable, cached rule hit: {}", c.reason),
                        stage: CheckStage::Regex,
                        requires_approval: matches!(c.risk_level, RiskLevel::L3),
                        redacted_content: None,
                        seatbelt_required: true,
                        action_id: None,
                        verdict_epoch: inner.epoch,
                        verdict_ttl_secs: 0,
                        inferred_category: String::new(),
                        category_hint: None,
                    });
                }
            }
        }
        None
    }

    pub fn is_empty(&self) -> bool {
        self.inner
            .lock()
            .expect("rules cache lock poisoned")
            .compiled
            .iter()
            .flatten()
            .count()
            == 0
    }
}

// ---------- unit tests ----------

#[cfg(test)]
mod tests {
    use super::*;

    fn rs_cache_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("fe-guard-test-{name}-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn sample_ruleset(epoch: u64) -> RuleSet {
        RuleSet {
            epoch,
            rules: vec![GuardRule {
                name: "rm-rf".into(),
                pattern: r"rm\s+-rf?\s+(/|~|\*)".into(),
                stage: CheckStage::Regex,
                action: GuardAction::Block,
                risk_level: RiskLevel::L4,
                reason: "destructive rm -rf".into(),
                scope: RuleScope::Command,
            }],
        }
    }

    #[test]
    fn verdict_serde_roundtrip_lowercase() {
        let v = GuardVerdict {
            action: GuardAction::Block,
            risk_level: RiskLevel::L4,
            reason: "x".into(),
            stage: CheckStage::Regex,
            requires_approval: false,
            redacted_content: None,
            seatbelt_required: true,
            action_id: None,
            verdict_epoch: 7,
            verdict_ttl_secs: 30,
            inferred_category: "destructive".into(),
            category_hint: None,
        };
        let s = serde_json::to_string(&v).unwrap();
        assert!(s.contains("\"action\":\"block\""), "action lowercase: {s}");
        assert!(s.contains("\"risk_level\":\"l4\""), "risk lowercase: {s}");
        assert!(s.contains("\"stage\":\"regex\""), "stage lowercase: {s}");
        // category_hint None → omitted (skip_serializing_if).
        assert!(!s.contains("category_hint"), "hint omitted: {s}");
        let back: GuardVerdict = serde_json::from_str(&s).unwrap();
        assert_eq!(back.action, GuardAction::Block);
        assert_eq!(back.risk_level, RiskLevel::L4);
    }

    #[test]
    fn verdict_serde_old_json_category_hint_default() {
        // Old verdict JSON missing category_hint/redacted_content → #[serde(default)] parses it.
        let s = r#"{"action":"allow","risk_level":"l1","reason":"","stage":"regex","requires_approval":false,"seatbelt_required":false,"verdict_epoch":0,"verdict_ttl_secs":0,"inferred_category":""}"#;
        let v: GuardVerdict = serde_json::from_str(s).unwrap();
        assert_eq!(v.action, GuardAction::Allow);
        assert!(v.category_hint.is_none());
        assert!(v.redacted_content.is_none());
    }

    #[test]
    fn high_risk_judgment() {
        let mk = |action: GuardAction, rl: RiskLevel| GuardVerdict {
            action,
            risk_level: rl,
            reason: String::new(),
            stage: CheckStage::Regex,
            requires_approval: false,
            redacted_content: None,
            seatbelt_required: false,
            action_id: None,
            verdict_epoch: 0,
            verdict_ttl_secs: 0,
            inferred_category: String::new(),
            category_hint: None,
        };
        assert!(mk(GuardAction::Allow, RiskLevel::L4).high_risk());
        assert!(mk(GuardAction::Block, RiskLevel::L1).high_risk());
        assert!(mk(GuardAction::Preview, RiskLevel::L3).high_risk());
        assert!(!mk(GuardAction::Allow, RiskLevel::L1).high_risk());
        assert!(!mk(GuardAction::Preview, RiskLevel::L2).high_risk());
    }

    #[test]
    fn rules_cache_refresh_and_epoch() {
        let path = rs_cache_path("refresh");
        let cache = RulesCache::new(path.clone());
        assert_eq!(cache.epoch(), 0, "cold start epoch 0");
        assert!(cache.is_empty());
        cache.refresh(sample_ruleset(42));
        assert_eq!(cache.epoch(), 42);
        assert!(!cache.is_empty());
        // Disk persistence can be reloaded.
        let cache2 = RulesCache::new(path.clone());
        assert_eq!(cache2.epoch(), 42, "disk reload epoch");
        assert!(!cache2.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn run_cached_rules_hit_block() {
        let path = rs_cache_path("hit");
        let cache = RulesCache::new(path.clone());
        cache.refresh(sample_ruleset(1));
        let v = cache
            .run_cached_rules("rm -rf /")
            .expect("destructive match");
        assert_eq!(v.action, GuardAction::Block);
        assert_eq!(v.risk_level, RiskLevel::L4);
        assert!(v.seatbelt_required);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn run_cached_rules_miss() {
        let path = rs_cache_path("miss");
        let cache = RulesCache::new(path.clone());
        cache.refresh(sample_ruleset(1));
        assert!(cache.run_cached_rules("echo hello").is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn run_cached_rules_empty_no_panic() {
        let path = rs_cache_path("empty");
        let cache = RulesCache::new(path.clone());
        assert!(cache.is_empty());
        assert!(
            cache.run_cached_rules("rm -rf /").is_none(),
            "empty cache no false block"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn guard_client_connect_fail_unavailable() {
        // Point at a non-existent socket → Unavailable (fail-closed, no panic).
        let mut sock = std::env::temp_dir();
        sock.push(format!("fe-guard-nope-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock);
        let client = GuardClient::new(sock, "tenant".into());
        let err = client.ping().unwrap_err();
        assert!(
            matches!(err, GuardError::Unavailable(_)),
            "connect fail → Unavailable, got {err:?}"
        );
    }

    #[test]
    fn map_error_codes() {
        // Directly verify the code→variant mapping (so the fallback path branches correctly).
        let cases: [(i32, &str); 4] = [
            (-32001, "unauthorized"),
            (-32002, "rate"),
            (-32003, "stale"),
            (-32010, "engine"),
        ];
        for (code, label) in cases {
            let err = GuardClient::map_error(RpcError {
                code,
                message: label.into(),
            });
            let ok = matches!(
                (code, &err),
                (-32001, GuardError::Unauthorized(_))
                    | (-32002, GuardError::RateLimited)
                    | (-32003, GuardError::StaleEpoch { .. })
                    | (-32010, GuardError::Engine(_))
            );
            assert!(ok, "code {code} → wrong variant {err:?}");
        }
    }
}
