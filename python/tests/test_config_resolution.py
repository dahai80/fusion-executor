"""Issue #60 (config Phase 2.2): fusion_core.config single-point resolution wiring.

Acceptance (issue #60):
- dev 缺 key: client_key() == "" + warning (无默认值字面量 "fg-admin-key")
- FUSION_PROFILE=prod 缺 key: RuntimeError (fail-fast)
- LayaToolSelector HTTP backend 经 client_key()/default_mlx_base_url() 单点解析

不依赖 laya 模型缓存 (CI 全环境可跑) — 只测 key/URL 解析接线, 不发真实请求。
"""

from __future__ import annotations

import logging

import pytest

from fusion_executor import LayaToolSelector

_KEY_ENVS = ("FUSION_CLIENT_KEY", "FUSION_MLX_API_KEY", "MLX_API_KEY")


def _clear_key_env(monkeypatch):
    for env in _KEY_ENVS:
        monkeypatch.delenv(env, raising=False)


def test_client_key_dev_missing_empty_with_warning(monkeypatch, caplog):
    """dev 缺 key = "" + warning (config-conventions §3 — 无默认值字面量)。"""
    from fusion_core import config as fc_config

    _clear_key_env(monkeypatch)
    monkeypatch.delenv("FUSION_PROFILE", raising=False)
    monkeypatch.setattr(fc_config, "_ANON_WARNED", set())
    with caplog.at_level(logging.WARNING, logger="fusion_core.config"):
        assert fc_config.client_key() == ""
    assert any("anonymous dev mode" in r.message.lower() for r in caplog.records)


def test_client_key_prod_missing_raises(monkeypatch):
    """FUSION_PROFILE=prod 缺 key = RuntimeError (fail-fast, 认证旁路防线)。"""
    from fusion_core import config as fc_config

    _clear_key_env(monkeypatch)
    monkeypatch.setenv("FUSION_PROFILE", "prod")
    with pytest.raises(RuntimeError, match="FUSION_CLIENT_KEY not set"):
        fc_config.client_key()


def test_client_key_explicit_env(monkeypatch):
    """FUSION_CLIENT_KEY 设置 → 原样返回 (无 deprecated warning)。"""
    from fusion_core import config as fc_config

    _clear_key_env(monkeypatch)
    monkeypatch.delenv("FUSION_PROFILE", raising=False)
    monkeypatch.setattr(fc_config, "_ANON_WARNED", set())
    monkeypatch.setenv("FUSION_CLIENT_KEY", "test-client-key-123")
    assert fc_config.client_key() == "test-client-key-123"


def test_http_backend_uses_client_key(monkeypatch):
    """HTTP backend: 无显式 api_key → Bearer 头携带 client_key() 解析值。"""
    _clear_key_env(monkeypatch)
    monkeypatch.delenv("FUSION_PROFILE", raising=False)
    monkeypatch.setenv("FUSION_CLIENT_KEY", "wired-key-abc")
    sel = LayaToolSelector(min_confidence=0.0, backend="http")
    auth = sel._http_client.headers.get("Authorization")
    assert auth == "Bearer wired-key-abc"


def test_http_backend_explicit_api_key_wins(monkeypatch):
    """显式 api_key kwarg 优先于环境解析 (调用方注入覆盖单点默认)。"""
    _clear_key_env(monkeypatch)
    monkeypatch.delenv("FUSION_PROFILE", raising=False)
    monkeypatch.setenv("FUSION_CLIENT_KEY", "env-key")
    sel = LayaToolSelector(min_confidence=0.0, backend="http", api_key="explicit-key")
    assert sel._http_client.headers.get("Authorization") == "Bearer explicit-key"


def test_http_backend_prod_missing_key_raises(monkeypatch):
    """HTTP backend 构造在 prod 缺 key → RuntimeError (不静默降级)。"""
    _clear_key_env(monkeypatch)
    monkeypatch.setenv("FUSION_PROFILE", "prod")
    with pytest.raises(RuntimeError, match="FUSION_CLIENT_KEY not set"):
        LayaToolSelector(min_confidence=0.0, backend="http")


def test_http_backend_url_resolution(monkeypatch):
    """URL: 显式 mlx_url > FUSION_MLX_URL env > 默认 http://localhost:11434/v1。"""
    _clear_key_env(monkeypatch)
    monkeypatch.delenv("FUSION_PROFILE", raising=False)
    monkeypatch.setenv("FUSION_MLX_URL", "http://10.0.0.5:11434/v1/")
    sel = LayaToolSelector(min_confidence=0.0, backend="http")
    assert sel._decide_url == "http://10.0.0.5:11434/v1/laya/decide"

    sel2 = LayaToolSelector(min_confidence=0.0, backend="http", mlx_url="http://explicit:1/v1")
    assert sel2._decide_url == "http://explicit:1/v1/laya/decide"


def test_no_secret_default_literal_left():
    """config-conventions §3: secret 默认值字面量一律非法 — 源码不留 "fg-admin-key"。"""
    import inspect

    import fusion_executor.laya_tool_selector as lts

    src = inspect.getsource(lts)
    assert "fg-admin-key" not in src
