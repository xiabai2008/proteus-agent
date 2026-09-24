"""带会话态的 HTTP：cookie jar + 请求日志 + 原样重放（P1-1，2026-09-24）。

补的是"登录后渗透"这条真实工作流。此前内核只有 `http_raw`——每次调用手传
`cookie`/`headers`，没有会话复用，也没有"把证据里那条请求原样重发"的能力：
登录一次、带着会话扫一遍、再把关键请求重放成 PoC，这三件事在核心里都做不了。

设计：

- **会话切片**：`<data_dir>/http-sessions/<session>.json` 存 cookie 与请求日志。
  多目标/多身份用不同 `session` 名隔离（如 `admin` / `guest`）。
- **请求日志**：每次调用记一条 `request_id`（`<session>-<seq>`），重放按它取原文。
  日志只留最近 N 条（缺省 50），避免文件无限增长。
- **凭据不回显**：返回里只给 cookie 的**名字与数量**，值不落输出；请求头记录
  沿用 `_mask_headers` 脱敏。凭据在 jar 文件里是明文——它在 `data/` 下
  （已 gitignore），且内核从不把它写进证据链。
- **重放比对**：`replay_request` 重发后比对状态码与正文哈希，给出
  `same_status` / `same_body`——"可复现"从文档要求变成可执行动作。
- 边界与 `http_raw` 同源：仅 http/https、不跟随重定向、4xx/5xx 按响应返回、
  CR/LF 头拒绝、目标白名单由 PolicyGate 在执行前裁决。

`data_dir` 由 `configure()` 注入（MCP server 构造时调用）；未注入时用
`data/`（相对于进程 cwd——preset 把 cwd 设为仓库根）。
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Optional, Union

DATA_DIR = "data"
MAX_LOG = 50
COOKIE_CAP = 60

_session_state: dict[str, dict] = {}


def configure(data_dir: Union[str, Path, None]) -> None:
    """注入数据目录（MCP server / 测试用）。"""
    global DATA_DIR
    if data_dir:
        DATA_DIR = str(data_dir)


def sessions_dir() -> Path:
    return Path(DATA_DIR) / "http-sessions"


def _jar_path(session: str) -> Path:
    name = "".join(c for c in str(session or "default")
                   if c.isalnum() or c in "-_")[:40] or "default"
    return sessions_dir() / f"{name}.json"


def load_session(session: str = "default") -> dict:
    """读会话切片（缺失/损坏 → 空切片，不抛异常）。"""
    path = _jar_path(session)
    key = str(path)
    if key in _session_state:
        return _session_state[key]
    data: dict = {"cookies": {}, "log": [], "next_seq": 1}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            data["cookies"] = dict(raw.get("cookies") or {})
            data["log"] = list(raw.get("log") or [])[-MAX_LOG:]
            data["next_seq"] = int(raw.get("next_seq") or
                                   (len(data["log"]) + 1))
    except (OSError, ValueError, TypeError):
        pass
    _session_state[key] = data
    return data


def save_session(session: str, data: dict) -> None:
    path = _jar_path(session)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        data = dict(data)
        data["log"] = list(data.get("log") or [])[-MAX_LOG:]
        path.write_text(json.dumps(data, ensure_ascii=False, indent=1),
                        encoding="utf-8")
    except OSError:
        pass                    # 落盘失败不阻断请求本身（fail-open，与审计桥同源）
    _session_state[str(path)] = data


def _set_cookies_from(resp_headers) -> dict:
    """从响应头收 Set-Cookie（只取 name=value，忽略属性）。"""
    jar: dict[str, str] = {}
    try:
        items = resp_headers.get_all("Set-Cookie") or []
    except Exception:                     # noqa: BLE001
        items = []
    for item in items:
        head = str(item).split(";", 1)[0].strip()
        if "=" in head:
            name, _, value = head.partition("=")
            name = name.strip()
            if name:
                jar[name] = value.strip()
    return jar


def _cookie_header(cookies: dict) -> str:
    return "; ".join(f"{k}={v}" for k, v in list(cookies.items())[:COOKIE_CAP])


def _body_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]


def _do_request(url: str, method: str, body: str, headers: dict,
                cookie: str, timeout: float, max_body: int,
                grep: str) -> dict:
    """发一次请求并返回原始结果（http_raw 语义，供会话/重放共用）。"""
    from penagent.builtin_tools import (_NoRedirect, GREP_SCAN_CAP,
                                        _allow_http_url, _clean_headers,
                                        _grep_body, _mask_headers,
                                        mask_response_headers)
    import urllib.error
    import urllib.request

    method = (method or "GET").strip().upper()
    if method not in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"):
        return {"url": url, "method": method,
                "error": f"不支持的方法: {method}"}
    try:
        cap = max(256, min(int(max_body or 1200), 20000))
    except (TypeError, ValueError):
        cap = 1200
    send_headers, header_problems = _clean_headers(headers, cookie)
    data = body.encode("utf-8") if body and method != "HEAD" else None
    if data is not None and not any(k.lower() == "content-type"
                                    for k in send_headers):
        send_headers["Content-Type"] = "application/x-www-form-urlencoded"

    try:
        req = urllib.request.Request(
            _allow_http_url(url), data=data, method=method,
            headers={"User-Agent": "XPentest/0.1 (authorized test)",
                     **send_headers})
        opener = urllib.request.build_opener(_NoRedirect)
        started = time.perf_counter()
        try:
            resp = opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as exc:
            resp = exc
        try:
            scan = max(cap, GREP_SCAN_CAP)
            raw = b"" if method == "HEAD" else resp.read(scan + 1)
            elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
            truncated = len(raw) > cap
            text_body = raw[:cap].decode("utf-8", errors="replace")
            scan_text = raw[:scan].decode("utf-8", errors="replace")
            result = {
                "url": getattr(resp, "url", url),
                "method": method,
                "status": getattr(resp, "status", None)
                          or getattr(resp, "code", None),
                "reason": str(getattr(resp, "reason", "") or ""),
                "headers": mask_response_headers(
                    list(resp.headers.items())),
                "location": resp.headers.get("Location", ""),
                "body": text_body,
                "truncated": truncated,
                "elapsed_ms": elapsed_ms,
                "request_headers": _mask_headers(send_headers),
                "_body_digest": _body_digest(text_body),
                "_set_cookies": _set_cookies_from(resp.headers),
            }
            if truncated:
                result["note"] = ("正文已截断——改用 grep 参数做定向提取，"
                                  "不要加大 max_body（回灌按 2500 字符截断）")
            if grep:
                result["grep"] = _grep_body(scan_text, grep)
                result["grep"]["scanned_chars"] = len(scan_text)
            if header_problems:
                result["header_problems"] = header_problems
        finally:
            try:
                resp.close()
            except Exception:             # noqa: BLE001
                pass
        return result
    except Exception as exc:              # noqa: BLE001
        return {"url": url, "method": method, "error": str(exc)[:300],
                "request_headers": _mask_headers(send_headers),
                **({"header_problems": header_problems}
                   if header_problems else {})}


def session_http(url: str, method: str = "GET", body: str = "",
                 headers=None, cookie: str = "", session: str = "default",
                 grep: str = "", timeout: float = 10.0, max_body: int = 1200,
                 update_cookies: bool = True) -> dict:
    """带会话态的 HTTP 请求：自动带 cookie、吸收 Set-Cookie、返回可重放的 id。

    用法（登录后渗透的标准动作）：

    1. `session_http(login_url, "POST", "user=admin&pass=...", session="admin")`
       —— 响应里的 Set-Cookie 自动进 jar，返回 `cookies_set: ["PHPSESSID"]`；
    2. 之后的请求只写 `session="admin"`，cookie 自动带上（不必手抄）；
    3. 关键请求返回的 `request_id` 交给 `replay_request` 做可复现验证。

    `update_cookies=false` 时只读不写 jar（用于对照实验）。
    """
    jar = load_session(session)
    eff_cookie = str(cookie or "").strip() or _cookie_header(jar["cookies"])
    result = _do_request(url, method, body, headers or {}, eff_cookie,
                         timeout, max_body, grep)

    seq = int(jar.get("next_seq") or 1)
    request_id = f"{Path(_jar_path(session)).stem}-{seq:04d}"
    jar["next_seq"] = seq + 1
    new_cookies = result.pop("_set_cookies", {}) if update_cookies else {}
    if update_cookies and new_cookies:
        jar["cookies"].update(new_cookies)
    jar["log"].append({
        "request_id": request_id,
        "url": url, "method": (method or "GET").upper(), "body": body,
        "headers": result.get("request_headers") or [],
        "cookie_names": sorted(jar["cookies"]),
        "status": result.get("status"),
        "oracle": result.get("_body_digest", ""),
        "elapsed_ms": result.get("elapsed_ms"),
        "at": time.strftime("%Y-%m-%d %H:%M:%S"),
    })
    if update_cookies:
        save_session(session, jar)

    result["request_id"] = request_id
    result["session"] = Path(_jar_path(session)).stem
    result["cookie_names"] = sorted(jar["cookies"])
    if new_cookies:
        result["cookies_set"] = sorted(new_cookies)
    return result


def replay_request(request_id: str, session: str = "default",
                   compare_body: bool = True,
                   timeout: float = 10.0) -> dict:
    """把日志里那条请求**原样重发**，并比对结果——可复现 PoC 的执行动作。

    比什么：状态码与正文哈希（正文按当时的抓取上限）。`same_status` 为真
    而 `same_body` 为假，通常说明页面有动态内容（时间戳/随机 token），不是
    漏洞消失；两个都假说明结论不可复现，应当如实降级结论。
    """
    jar = load_session(session)
    entry = None
    for item in reversed(jar["log"]):
        if str(item.get("request_id")) == str(request_id):
            entry = item
            break
    if entry is None:
        known = [i.get("request_id") for i in jar["log"][-10:]]
        return {"request_id": request_id, "ok": False,
                "error": f"日志里没有这个 request_id（会话 {session} 最近的有："
                         f"{known or '（空）'}）"}

    cookie = _cookie_header(jar["cookies"])
    result = _do_request(entry["url"], entry["method"], entry.get("body", ""),
                         {}, cookie, timeout, 1200, "")
    fresh = {"status": result.get("status"), "elapsed_ms": result.get("elapsed_ms"),
             "body_digest": result.pop("_body_digest", "")}
    result.pop("_set_cookies", None)
    original = {"status": entry.get("status"), "elapsed_ms": entry.get("elapsed_ms"),
                "body_digest": entry.get("oracle", "")}
    verdict = {
        "same_status": fresh["status"] == original["status"],
        "same_body": (fresh["body_digest"] == original["body_digest"]
                      if compare_body else None),
    }
    if verdict["same_status"] and verdict["same_body"] is not False:
        verdict["hint"] = "可复现：状态码与正文哈希一致，结论可以此为准"
    elif verdict["same_status"]:
        verdict["hint"] = ("状态码一致但正文哈希不同——常见于动态内容"
                           "（时间戳/随机 token/csrf），不是漏洞消失")
    else:
        verdict["hint"] = ("状态码不同：结论**不可复现**，应如实降级"
                           "（不要把它写成已验证的发现）")
    result.update({"request_id": entry["request_id"], "ok": True,
                   "original": original, "replay": fresh, "verdict": verdict})
    return result
