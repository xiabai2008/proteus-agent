"""内置工具的工具体内 URL 边界校验测试（file:// 与云元数据地址拒绝）。

背景：urllib.urlopen 原生支持 file://，且不经过 PolicyGate 闸门的直接
fn 调用路径仍可达工具体——_allow_http_url 必须自带同一条边界：
仅 http(s) 协议；链路本地（云元数据 169.254.0.0/16）/组播/保留段拒绝；
环回/私网是授权靶机的合法目标，不阻断。
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from penagent.builtin_tools import http_probe, robots_fetch


def test_http_probe_rejects_file_scheme(tmp_path):
    """file:// 指向真实本地文件 -> 返回 error，文件内容不出现在输出里。"""
    secret = tmp_path / "secret.txt"
    secret.write_text("TOPSECRET", encoding="utf-8")
    result = http_probe(secret.as_uri())          # file:///.../secret.txt
    assert "error" in result
    assert "TOPSECRET" not in str(result)


def test_http_probe_rejects_other_schemes():
    for bad in ("ftp://example.com/x", "gopher://x", "javascript:x"):
        result = http_probe(bad)
        assert "error" in result and "协议不被允许" in result["error"]


def test_http_probe_rejects_metadata_address():
    """解析到链路本地（云元数据）-> 拒绝。"""
    result = http_probe("http://169.254.169.254/latest/meta-data/")
    assert "error" in result and "禁止的地址" in result["error"]


def test_http_probe_allows_authorized_loopback():
    """环回是授权靶机默认白名单 -> 不被工具内边界拒绝（网络错误可接受）。"""
    result = http_probe("http://127.0.0.1:1/")    # 端口 1 大概率无服务
    assert "协议不被允许" not in str(result) and "禁止的地址" not in str(result)


def test_robots_fetch_rejects_file_scheme(tmp_path):
    secret = tmp_path / "robots.txt"
    secret.write_text("Disallow: /TOPSECRET", encoding="utf-8")
    result = robots_fetch(str(tmp_path))
    assert "error" in result
    assert "TOPSECRET" not in str(result)
