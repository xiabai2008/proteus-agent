"""LLM 客户端：OpenAI 兼容 chat/completions，多模型路由。

配置：PENTEST_LLM_BASE_URL / PENTEST_LLM_API_KEY / PENTEST_LLM_MODEL
（.env 或环境变量）。决策用主模型；摘要/压缩可用低成本模型（路由预留）。
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = PROJECT_ROOT / ".env"


@dataclass
class LLMConfig:
    base_url: str = "https://opencode.ai/zen/v1"
    api_key: str = ""
    model: str = "deepseek-v4-flash-free"
    timeout: int = 180
    temperature: float = 0.3

    @classmethod
    def from_env(cls, env_path: Path = ENV_FILE) -> "LLMConfig":
        env: dict[str, str] = {}
        if env_path.exists():
            for line in env_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    env[k.strip()] = v.strip()
        return cls(
            base_url=os.environ.get("PENTEST_LLM_BASE_URL")
                     or env.get("PENTEST_LLM_BASE_URL", cls.base_url),
            api_key=os.environ.get("PENTEST_LLM_API_KEY")
                    or env.get("PENTEST_LLM_API_KEY", ""),
            model=os.environ.get("PENTEST_LLM_MODEL")
                  or env.get("PENTEST_LLM_MODEL", cls.model),
        )

    def ready(self) -> bool:
        return bool(self.api_key)


class LLMError(Exception):
    pass


def chat(config: LLMConfig, messages: list[dict],
         temperature: Optional[float] = None,
         max_tokens: int = 4096,
         retries: int = 3) -> str:
    """调用 chat/completions，返回 assistant 文本（503/429 退避重试）。"""
    if not config.ready():
        raise LLMError("未配置 PENTEST_LLM_API_KEY（.env 或环境变量）")
    import time as _time

    last_err: Optional[LLMError] = None
    for attempt in range(retries + 1):
        if attempt:
            _time.sleep(3 * attempt)
        body = json.dumps({
            "model": config.model,
            "messages": messages,
            "temperature": config.temperature if temperature is None
            else temperature,
            "max_tokens": max_tokens,
        }).encode("utf-8")
        req = urllib.request.Request(
            config.base_url.rstrip("/") + "/chat/completions",
            data=body,
            headers={
                "Authorization": f"Bearer {config.api_key}",
                "Content-Type": "application/json",
                "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                               "AppleWebKit/537.36 (KHTML, like Gecko) "
                               "Chrome/126.0 Safari/537.36"),
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=config.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            try:
                content = data["choices"][0]["message"]["content"]
                if not content or not content.strip():
                    last_err = LLMError("LLM 返回空内容，重试")
                    continue
                return content
            except (KeyError, IndexError, TypeError) as exc:
                raise LLMError(
                    f"LLM 响应格式异常: {str(data)[:300]}") from exc
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            last_err = LLMError(f"LLM API HTTP {exc.code}: {detail}")
            if exc.code not in (429, 500, 502, 503):
                raise last_err
        except urllib.error.URLError as exc:
            last_err = LLMError(f"LLM API 不可达: {exc.reason}")
            if attempt == retries:
                break
    raise last_err or LLMError("LLM 调用失败")


def _extract_json_block(text: str) -> str:
    """从文本中提取第一个平衡的 JSON 对象块（容忍前后说明文字）。"""
    import re

    # 1) 代码块包裹
    m = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
    if m:
        return m.group(1)
    # 2) 找第一个 '{' 做括号平衡提取
    start = text.find("{")
    if start == -1:
        return text
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        ch = text[i]
        if esc:
            esc = False
            continue
        if ch == "\\":
            esc = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return text[start:]


def chat_json(config: LLMConfig, messages: list[dict],
              temperature: Optional[float] = None,
              max_tokens: int = 4096) -> dict:
    """要求模型输出 JSON 并解析（容忍包裹/前后说明/嵌套）。"""
    raw = chat(config, messages, temperature, max_tokens)
    text = _extract_json_block(raw.strip())
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise LLMError(f"LLM 输出不是合法 JSON: {exc}\n---\n{raw[:800]}") from exc
    if not isinstance(data, dict):
        raise LLMError("LLM 输出不是 JSON 对象")
    return data
