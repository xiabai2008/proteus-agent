"""把 CTF 技能知识源蒸馏进内核技能库（路线 2）。

两个来源：
- yaklang/hack-skills（CURATED，hs-* 前缀）：本地浅克隆 data/knowledge/
  hack-skills/skills/<slug>/SKILL.md，evidence_text 指回本地原文；
- ljagiello/ctf-skills（HCS_CURATED，hcs-* 前缀，2026-09-27 并入）：
  不做本地克隆，evidence_text 指向 GitHub 原文（seckb 已收录全文，
  kb_search/kb_get 可检索深读）。补齐 crypto/pwn/reverse/forensics 等
  hack-skills 没有的类别——首批只蒸馏 ctf-crypto（有对应 mode）+
  ctf-reverse/ctf-forensics（先落库，待建 mode 后即可注入）。

为什么手工蒸馏而不是脚本全文导入（2026-09-27 决策）：
- find_skills 按 target_fingerprint 关键词共现匹配——指纹要对着内核调用
  方式写（中文+英文混合），机器搬运写不出这种粒度；
- pentest_run 的系统提示只注入排序后前 3 条——条目必须小而准，全文塞进
  steps 会把预算烧在上下文里；
- 深度原文仍在知识源（本地克隆或 seckb），evidence_text 指路即可。

落盘规则：<data_dir>/skills/<category>/<skill_id>.json——Memory 按
namespace（=mode.memory_namespace）扫 skills/<namespace>/，category 必须
与目标 mode 的 skills 白名单一致，否则永不上屏。

用法：
    python tools/import_hack_skills.py [--data-dir data]
幂等：同 id 覆盖（重复导入=更新），保留已有成功率/次数统计。
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from penagent.memory import Skill  # noqa: E402

# 知识源相对 data_dir 的路径（hack-skills 的本地克隆位置）
KNOWLEDGE_REL = "knowledge/hack-skills/skills"

# 第一批：CTF Web 高频六个方向（每条步骤都对应内核工具可执行的动作；
# 深层 payload 细节不进 steps——evidence_text 指向原文按需读）
CURATED = [
    {
        "slug": "deserialization-insecure",
        "title": "反序列化 RCE 系统化打法（PHP/Python/Java）",
        "category": "ctf-web",
        "fingerprint": "反序列化 deserialize unserialize pickle yaml php "
                       "java python web flask",
        "steps": [
            "指纹判型：报错/响应头/入口参数形态判断语言与库（PHP unserialize、"
            "Python pickle/base64 gASV 前缀、YAML !!python、Java AC ED 00 05）",
            "PHP：先确认是否有可用 gadget（composer 阅读/vendor 目录枚举），"
            "按 魔术方法入口（__destruct/__wakeup/__toString）链到执行原语；"
            "无链时测 phar:// 流包装",
            "Python pickle：http_raw 确认回显与否——有回显直接 check_output；"
            "零回显走 oob_read 外带或写文件三步（见人格第 8 条）",
            "YAML：pyyaml unsafe_load 用 !!python/object/apply:os.system；"
            "safe_load 出现 !!python 即确认误配",
            "结论用 replay_request 重放确认可复现，report_gen 收口",
        ],
        "tools": ["http_raw", "python_solve", "oob_read", "replay_request",
                  "report_gen"],
    },
    {
        "slug": "ssti-server-side-template-injection",
        "title": "SSTI 引擎判型与利用（Jinja2/Twig/Freemarker 等）",
        "category": "ctf-web",
        "fingerprint": "ssti template injection jinja2 twig 模板注入 "
                       "python web flask",
        "steps": [
            "探针判型：{{7*7}}/${7*7}/<%= 7*7 %> 差异化注入定位引擎家族",
            "Jinja2：{{lipsum.__globals__['os'].popen('id').read()}} 类 "
            "lipsum/配置对象 gadget 拿执行原语；waf 时按字符集做字符串拼接",
            "零回显时绑执行原语到 oob_read 外带或写文件到已知可读路由",
            "replay_request 确认可复现后 report_gen 收口",
        ],
        "tools": ["http_raw", "python_solve", "oob_read", "replay_request",
                  "report_gen"],
    },
    {
        "slug": "sqli-sql-injection",
        "title": "SQL 注入判型与无回显利用（登录态/布尔/时间盲注）",
        "category": "ctf-web",
        "fingerprint": "sql injection sqli mysql sqlite 登录 login "
                       "authentication bypass sql",
        "steps": [
            "判型：报错注入（直接回显错误）→ 联合查询（列数对齐）→ "
            "布尔/时间盲注（响应差异或 SLEEP 延迟）依次排除",
            "登录态绕过：admin'-- 类注释闭合、OR 1=1 恒真；用 session_http "
            "带 cookie 验证登录后路径",
            "盲注用 python_solve 写二分脚本逐字符提取（内核侧跑，别手数）",
            "SQLite/MySQL 特性差异按知识源原文核（attach/写文件路径不同）",
            "replay_request 固化 PoC 请求，report_gen 收口",
        ],
        "tools": ["http_raw", "session_http", "python_solve", "replay_request",
                  "report_gen"],
    },
    {
        "slug": "cmdi-command-injection",
        "title": "命令注入绕过与执行确认",
        "category": "ctf-web",
        "fingerprint": "command injection cmdi rce exec shell 命令注入 "
                       "ping host web",
        "steps": [
            "确认拼接点：原参数后接 ; | ` $( ) 换行等分隔符逐个试",
            "过滤绕过：空格用 ${IFS}/$IFS$9，关键词用 ca\\t / 变量拼接，"
            "编码用 base64 管道解码执行",
            "读 flag：cat /flag* 或 ls / 先定位；输出进不了响应时改 "
            "oob_read 外带或写到 Web 根",
            "replay_request 重放确认，report_gen 收口",
        ],
        "tools": ["http_raw", "oob_read", "replay_request", "report_gen"],
    },
    {
        "slug": "ssrf-server-side-request-forgery",
        "title": "SSRF 利用面与协议升级（gopher/file/云元数据）",
        "category": "ctf-web",
        "fingerprint": "ssrf request forgery 内网 url fetch proxy "
                       "ssrf web curl",
        "steps": [
            "确认回连点：url/file/fetch 类参数，先用 http_probe 打宿主端口 "
            "验证服务器代请求是否成立",
            "协议面：file:/// 读本地、gopher:// 打内网 Redis/HTTP、"
            "http://host.docker.internal 打宿主（容器内视角同 oob_read 提示）",
            "盲 SSRF 直接接 oob_read：让目标回连收集器即证明确认",
            "内网横向时记录端口差异，证据链留痕后 report_gen 收口",
        ],
        "tools": ["http_raw", "http_probe", "oob_read", "report_gen"],
    },
    {
        "slug": "path-traversal-lfi",
        "title": "路径穿越与 LFI-to-RCE（wrapper 矩阵）",
        "category": "ctf-web",
        "fingerprint": "lfi path traversal 文件包含 include readfile "
                       "wrapper php web",
        "steps": [
            "穿越深度 ../ 递增或绝对路径直读；过滤绕过：....//、编码 %2e%2e、"
            "PHP filter 链",
            "PHP wrapper 矩阵：php://filter/convert.base64-encode 读源码，"
            "data:// 与 input:// 直接执行（需 allow_url_include）",
            "LFI-to-RCE：日志投毒（session 上传进度/-access.log）、"
            "php://filter chain 爆破生成执行型 filter（见知识源原文）",
            "读到的源码用 python_solve 解码判读，结论 report_gen 收口",
        ],
        "tools": ["http_raw", "python_solve", "report_gen"],
    },
]

# 第二批：ljagiello/ctf-skills 蒸馏（hcs-* 前缀）。ctf-crypto 两条对应
# ctf-crypto mode（白名单 skills=[ctf-crypto]）可即时注入；ctf-reverse/
# ctf-forensics 先落库（暂无对应 mode，建 mode 后把 category 加进白名单
# 即可上屏），检索层 seckb 已覆盖原文。
HCS_CURATED = [
    {
        "slug": "crypto-rsa",
        "prefix": "hcs-",
        "title": "RSA 攻击矩阵（判型→自动化→结构化弱点→预言机）",
        "category": "ctf-crypto",
        "source_url": "https://github.com/ljagiello/ctf-skills/blob/main/"
                      "ctf-crypto/rsa-attacks.md",
        "fingerprint": "rsa n e c 共模 common modulus wiener coppersmith "
                       "hastad 广播 broadcast lattice 格 预言机 oracle "
                       "dp dq 泄露 fermat pollard 素数 factor",
        "steps": [
            "侦察判型：解析 PEM/题目给的 n、e——先看位数，sympy.factorint 试"
            "小因子；直接跑 RsaCtfTool 自动过一遍 Wiener/Fermat/Pollard p-1/"
            "Hastad 常见弱点",
            "公共参数：同 n 不同 e 两密文扩展 GCD（共模攻击）；多把公钥两两 "
            "gcd(n) 找共享素数（Batch GCD）",
            "指数异常：gcd(e,phi)≠1 时 e'=e/g 开 g 次根后 CRT 枚举；e=3 多份"
            "密文 Hastad 广播 CRT 合并；带线性填充变体走 Coppersmith",
            "结构化素数：p、q 相近 Fermat 分解；q=next_prime(p) 连续素数；"
            "部分素数位已知走 Coppersmith（Howgrave-Graham 建格→fpylll LLL）",
            "预言机类：Bleichenbacher/Manger padding oracle、同态绕过"
            "（c·r^e 查询后除 r）、LSB 预言机二分——python_solve 写循环打",
            "密钥泄露：dp/dq 泄露 O(e) 枚举恢复；CRT 签名故障 "
            "gcd(s^e−m, n) 一次分解 n",
            "格分诊：模线性方程+隐含量小/稀疏/有偏/部分泄露 → HNP/LWE 建格，"
            "LLL→BKZ→Babai 递进；细节 kb_search 'lattice LWE Coppersmith'",
        ],
        "tools": ["python_solve", "report_gen"],
    },
    {
        "slug": "crypto-general",
        "prefix": "hcs-",
        "title": "通用密码学打法（XOR/经典/AES 模式/PRNG/哈希）",
        "category": "ctf-crypto",
        "source_url": "https://github.com/ljagiello/ctf-skills/blob/main/"
                      "ctf-crypto/SKILL.md",
        "fingerprint": "crypto xor 异或 vigenere caesar 替换密码 aes ecb "
                       "cbc gcm padding oracle mt19937 lcg prng 随机数 "
                       "random 哈希 hash length extension md5 sha crc32 "
                       "ecdsa nonce dh",
        "steps": [
            "经典密码：替换密码频率分析；Vigenère Kasiski 或已知明文（flag "
            "前缀锚定）；多字节 XOR 按列频率分析，空格 0x20 做锚点",
            "XOR 密钥恢复：已知文件头 magic bytes（PNG/PDF/ZIP）异或推重复"
            "密钥；级联 XOR 暴力首字节后确定性推导",
            "AES 模式：ECB 块重排/cut-and-paste；CBC 位翻转改明文；Padding "
            "Oracle 每块约 4096 查询（python_solve 自动化）；GCM nonce 重用"
            "恢复认证密钥",
            "哈希：length extension（hashpumpy）打 Merkle-Damgard "
            "（MD5/SHA1/SHA256）；CRC32 线性性伪造签名",
            "PRNG：MT19937 untemper（624 个连续输出恢复状态）；LCG 逆推"
            "（模逆）；V8 XorShift128+ 用 z3 约束求解",
            "ECDLP/DSA：ECDSA nonce 重用直接解私钥；小 k 暴力；p-1 光滑走 "
            "Pohlig-Hellman",
            "工具栈：pycryptodome/sympy/gmpy2/z3-solver 优先，全部 "
            "python_solve 跑；原文 kb_search 'crypto' 按需深读",
        ],
        "tools": ["python_solve", "report_gen"],
    },
    {
        "slug": "reverse-triage",
        "prefix": "hcs-",
        "title": "逆向工程快速三连与让程序自己算",
        "category": "ctf-reverse",
        "source_url": "https://github.com/ljagiello/ctf-skills/blob/main/"
                      "ctf-reverse/SKILL.md",
        "fingerprint": "reverse 逆向 pyc 字节码 bytecode apk wasm 固件 "
                       "firmware gdb ghidra angr frida 反调试 anti-debug "
                       "vm 虚拟机保护 upx 二进制 binary",
        "steps": [
            "快速三连（很多题不用真逆）：strings/rabin2 -z 找明文 flag → "
            "ltrace/strace 看运行时比较 → frida hook strcmp/memcmp 抓期望值",
            "判型：file + 特征识别——Python pyc 用 pycdc 反编译；Go 找 "
            "runtime 特征；Rust demangle；APK 用 apktool+jadx；WASM 用 wabt",
            "方向判断（搞反白干）：transform(flag)==target 则逆变换；"
            "transform(target)==flag 则对 target 正着应用变换",
            "让程序自己算：断在最终比较点（多个假 flag 断最后一个），输入"
            "等长垃圾后 dump 寄存器/内存拿真 flag",
            "自动化：flag-checker 类用 angr 符号执行；异架构/重反调试用 "
            "Qiling 模拟；python_solve 跑脚本",
            "反调试绕过：ptrace 检测/PEB/时序检查——按 seckb 检索 "
            "'anti-analysis' 原文对照",
        ],
        "tools": ["python_solve", "report_gen"],
    },
    {
        "slug": "forensics-triage",
        "prefix": "hcs-",
        "title": "取证分诊四连（隐写/流量/内存/磁盘）",
        "category": "ctf-forensics",
        "source_url": "https://github.com/ljagiello/ctf-skills/blob/main/"
                      "ctf-forensics/SKILL.md",
        "fingerprint": "forensics 取证 流量 pcap 内存 dump memory 磁盘 disk "
                       "隐写 stego steganography binwalk volatility zsteg "
                       "steghide exiftool 图片 音频 file carving",
        "steps": [
            "分诊四连：file → exiftool（元数据常藏 flag）→ binwalk（嵌文件）"
            "→ strings -n 8；按结果分流到隐写/流量/内存/磁盘",
            "隐写：PNG/BMP 用 zsteg；JPG 先 steghide 空密码再字典；位平面/"
            "色道差分用 python_solve 写解码；音频看频谱图"
            "（ffmpeg showspectrumpic）",
            "流量：tshark 过滤 http/dns/icmp；两种包间隔=0/1 的时序编码；"
            "TLS 流量先找 keylog 文件",
            "内存/磁盘：volatility3（pslist/filescan/cmdline/dumpfiles）；"
            "磁盘 fls -r + photorec 恢复删除文件",
            "文件修复：补 magic bytes、PNG IHDR 高度改回使 CRC 匹配、ZIP 头"
            "修复——python_solve 处理",
            "取出的加密 blob 转投密码学打法（hcs-crypto-*）；原文 kb_search "
            "'forensics stego' 深读",
        ],
        "tools": ["python_solve", "report_gen"],
    },
]


def import_skills(data_dir: str, knowledge_rel: str = KNOWLEDGE_REL) -> dict:
    """把 CURATED + HCS_CURATED 蒸馏技能 upsert 进
    <data_dir>/skills/<category>/。"""
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    written, src_missing = [], []
    for entry in [*CURATED, *HCS_CURATED]:
        prefix = entry.get("prefix", "hs-")
        skill_id = (prefix + entry["slug"])[:40]
        category = entry["category"]
        skills_dir = Path(data_dir) / "skills" / category
        skills_dir.mkdir(parents=True, exist_ok=True)
        if "source_url" in entry:
            evidence = (f"延伸阅读: {entry['source_url']}"
                        "（seckb 已收录原文，kb_search/kb_get 可检索深读）")
        else:
            src = Path(data_dir) / knowledge_rel / entry["slug"] / "SKILL.md"
            evidence = (
                f"延伸阅读: {src.as_posix()}"
                + ("" if src.is_file() else "（知识源未克隆，路径供参考）"))
            if not src.is_file():
                src_missing.append(entry["slug"])
        skill = Skill(
            id=skill_id,
            title=entry["title"],
            target_fingerprint=entry["fingerprint"],
            steps=entry["steps"],
            tools=entry["tools"],
            evidence_text=evidence,
            category=category,
            source_mission=("ctf-skills-import" if prefix == "hcs-"
                            else "hack-skills-import"),
            created_at=now,
        )
        # 已存在则保留复用统计（成功率/次数），其余字段以本批蒸馏为准
        existing = skills_dir / f"{skill_id}.json"
        if existing.is_file():
            try:
                old = Skill.from_dict(json.loads(existing.read_text("utf-8")))
                skill.success_rate = old.success_rate
                skill.successes = old.successes
                skill.attempts = old.attempts
            except (OSError, ValueError, TypeError):
                pass
        existing.write_text(json.dumps(skill.to_dict(), ensure_ascii=False,
                                       indent=2), encoding="utf-8")
        written.append(skill_id)
    return {"written": written, "knowledge_source_missing": src_missing}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data-dir", default=str(PROJECT_ROOT / "data"))
    args = ap.parse_args()
    result = import_skills(args.data_dir)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
