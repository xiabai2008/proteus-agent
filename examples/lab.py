"""真实渗透靶场基线：对运行中的本地靶场做被动侦察并断言预期发现。

与 `examples/target.py` 的区别：那是**三个端点的演示靶**（自造，用于闭环自测）；
本模块接的是**业界标准的真实漏洞应用**——攻击面更广、框架特征更真实。

本机运行中的三个靶（容器由使用者自己管理，本模块**只读探测**）：

| id | 靶 | 默认地址 | 镜像 |
|---|---|---|---|
| dvwa | DVWA（Damn Vulnerable Web Application） | http://127.0.0.1:8080 | vulnerables/web-dvwa |
| juice-shop | OWASP Juice Shop | http://127.0.0.1:3000 | bkimminich/juice-shop |
| sw-secure-lab | SW-Secure Lab | http://127.0.0.1:8081 | lab-environment-lab |

**只做被动侦察**：HTTP 探测 + 已知路径可达性，不发送任何攻击载荷。
这符合"基线"的定位——先定义"哪些东西是应该被发现的"，为后续 agent 能力
评测提供 ground truth，而不是自己去打。

探测经**内核工具链**（`ToolRegistry.execute`）而非直接调函数——这样走的是
与 agent 完全相同的闸门与沙箱裁决路径，顺带验证工具链对真实靶场可用。

容器生命周期不归本模块管：靶是你自己的，本模块绝不 stop / rm 别人的容器。
靶不可达时给出启动提示，由使用方决定是否启动。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# 默认地址与端口（按本机运行中的靶；如需改动，传参覆盖）
DEFAULT_URLS = {
    "dvwa": "http://127.0.0.1:8080",
    "juice-shop": "http://127.0.0.1:3000",
    "sw-secure-lab": "http://127.0.0.1:8081",
}


@dataclass(frozen=True)
class Finding:
    """一条预期发现：某路径应返回某状态、且（可选）响应中包含某文本。"""

    name: str
    path: str
    expect_status: int = 200
    expect_contains: str = ""
    note: str = ""


@dataclass(frozen=True)
class LabTarget:
    """一个真实靶场及其预期发现清单。"""

    id: str
    label: str
    image: str
    findings: tuple[Finding, ...] = field(default_factory=tuple)
    hint: str = ""


# ----------------------------------------------------------------------
# 靶场定义（预期发现来自对各靶的实际探测，不是猜的）
# ----------------------------------------------------------------------
LABS: tuple[LabTarget, ...] = (
    LabTarget(
        id="dvwa",
        label="DVWA（Damn Vulnerable Web Application）",
        image="vulnerables/web-dvwa",
        hint="docker run -d --rm --name lab-dvwa -p 8080:80 "
             "vulnerables/web-dvwa",
        findings=(
            Finding("home", "/", 200, "Damn Vulnerable Web Application",
                    note="登录页可达，标题暴露应用身份"),
            Finding("login-page", "/login.php", 200, "",
                    note="登录入口存在"),
            Finding("robots", "/robots.txt", 200, "",
                    note="robots.txt 可读（被动信息收集面）"),
            Finding("dir-listing", "/docs", 200, "Index of",
                    note="目录列表未关闭，暴露文件结构（真实信息泄漏发现）"),
        ),
    ),
    LabTarget(
        id="juice-shop",
        label="OWASP Juice Shop",
        image="bkimminich/juice-shop",
        hint="docker run -d --rm --name lab-juice -p 3000:3000 "
             "bkimminich/juice-shop",
        findings=(
            Finding("home", "/", 200, "OWASP Juice Shop",
                    note="SPA 首页可达"),
            Finding("rest-search", "/rest/products/search?q=", 200, "",
                    note="REST 商品搜索接口未鉴权可达（注入面）"),
            Finding("api-products", "/api/Products", 200, "",
                    note="REST API 可达"),
            Finding("version-leak", "/rest/admin/application-version", 200, "",
                    note="版本信息接口未鉴权可达（信息泄漏）"),
            Finding("challenges-api", "/api/Challenges", 200, "",
                    note="挑战清单接口可达（靶场自描述，暴露可攻击面）"),
        ),
    ),
    LabTarget(
        id="sw-secure-lab",
        label="SW-Secure Lab",
        image="lab-environment-lab",
        hint="该靶由你本机自有环境提供（镜像 lab-environment-lab）",
        findings=(
            Finding("home", "/", 200, "SW-Secure Lab",
                    note="首页可达并识别身份"),
        ),
    ),
)


def get_lab(lab_id: str) -> Optional[LabTarget]:
    """按 id 取靶定义（未知 id 返回 None）。"""
    return next((lab for lab in LABS if lab.id == lab_id), None)


# ----------------------------------------------------------------------
# 探测（经内核工具链）
# ----------------------------------------------------------------------
def _kernel_registry():
    """构建走闸门与沙箱的注册表（与 agent 同一条执行路径）。"""
    from penagent.agent import Policy
    from penagent.policy_gate import PolicyGate
    from penagent.registry import build_center

    registry = build_center().build_registry()
    registry.gate = PolicyGate(Policy(allowed_targets=["127.0.0.1",
                                                       "localhost"]))
    return registry


def probe_lab(lab: LabTarget, base_url: str = "",
              registry=None) -> dict:
    """对靶探测预期发现，返回 {finding_name: 是否命中}。

    经内核注册表执行 `http_probe` —— 走与 agent 相同的闸门裁决；靶越界
    （不在白名单）会被闸门拒绝，命中记为 False 而不是抛异常。
    """
    import json

    base = (base_url or DEFAULT_URLS.get(lab.id, "")).rstrip("/")
    reg = registry if registry is not None else _kernel_registry()
    hits: dict[str, bool] = {}
    for f in lab.findings:
        url = base + f.path
        result = reg.execute("http_probe", {"url": url})
        if not result.ok:
            hits[f.name] = False
            continue
        payload = result.output if isinstance(result.output, dict) else {}
        status = payload.get("status")
        blob = json.dumps(payload, ensure_ascii=False)
        ok = (status == f.expect_status
              and (not f.expect_contains or f.expect_contains in blob))
        hits[f.name] = bool(ok)
    return hits


def reachable(base_url: str, timeout: float = 1.5) -> bool:
    """靶是否可达（TCP 层探测，不打 HTTP）。"""
    import socket
    import urllib.parse

    parsed = urllib.parse.urlparse(base_url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((host, port)) == 0
    finally:
        s.close()
