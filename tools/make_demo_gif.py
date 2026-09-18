"""生成 README 演示 GIF：把真实作战记录渲染成终端动画。

数据来源（真实任务，非摆拍）：
- 渗透侦察：data/missions/pentest-standard/ec8adcd5.json（8+ 步、/debug 泄漏发现）
- CTF 编码链：data/missions/ctf-crypto/5cb8eeec.json（3 步解出 flag）

运行：python tools/make_demo_gif.py
输出：docs/assets/demo.gif（无限循环，约 12s）
"""
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "assets" / "demo.gif"

W, H = 900, 520
BG = (13, 17, 23)          # GitHub dark
FG = (201, 209, 217)
DIM = (110, 118, 129)
GREEN = (63, 185, 80)
AMBER = (210, 153, 34)
BLUE = (88, 166, 255)
PURPLE = (188, 140, 255)
RED = (248, 113, 113)
CYAN = (86, 180, 196)

FONT = "C:/Windows/Fonts/msyh.ttc"
F = lambda size: ImageFont.truetype(FONT, size)

LH = 26                     # 行高
MX = 28                     # 左边距


def screen(mode_badge, badge_color, lines, cursor_on=True):
    """一帧画面：标题栏 + 模式徽章 + 已输出行 + 光标。"""
    im = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(im)
    # 标题栏
    d.rectangle([0, 0, W, 40], fill=(22, 27, 34))
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([16 + i * 24, 14, 28 + i * 24, 26], fill=c)
    d.text((W // 2 - 190, 8), "Proteus · 千面 — multi-mode pentest agent",
           font=F(16), fill=FG)
    # 模式徽章
    bw = 6 + len(mode_badge) * 9
    d.rounded_rectangle([W - bw - 20, 9, W - 20, 31], radius=10,
                        outline=badge_color, width=1)
    d.text((W - bw - 10, 11), mode_badge, font=F(14), fill=badge_color)
    # 正文
    y = 56
    for text, color in lines:
        d.text((MX, y), text, font=F(15), fill=color)
        y += LH
    # 光标（on/off 闪烁，保证停留帧不合并、节奏稳定）
    if cursor_on:
        d.rectangle([MX + 2, y + 2, MX + 14, y + 20], fill=GREEN)
    # 页脚
    d.text((MX, H - 30), "一个内核，千种面孔 — github.com/xiabai2008/proteus-agent",
           font=F(13), fill=DIM)
    return im


P1 = "$ python -m penagent run --mode pentest-standard \\"
P2 = "      --target http://127.0.0.1:8080 --objective '授权靶标侦察评估'"
P3 = "$ python -m penagent run --mode ctf-crypto \\"
P4 = "      --target data/eval-ctf/encoding_chain.txt --objective '解出 flag'"

SCREEN1 = [
    (P1, FG),
    (P2, DIM),
    ("[闸门] 目标白名单 127.0.0.1 √   证据链已开启   危险工具 → require_confirm", CYAN),
    ("[03] httpx_probe    → Demo Portal - Flask/2.3 · BaseHTTP/0.6 Python/3.12.9", FG),
    ("[04] port_scan      → open: 135, 445, 3306, 3389, 8080", FG),
    ("[05] robots_fetch   → Disallow: /admin, /debug", FG),
    ("[06] http_probe /admin   → 401 √ 已固化证据", FG),
    ("[07] http_probe /debug   → 200 [!] 信息泄漏", AMBER),
    ("[10] gobuster_dir   → … require_confirm（等待人工确认，未执行）", DIM),
    ("[14] nuclei_scan    → … require_confirm（等待人工确认，未执行）", DIM),
    ("[结论] /debug 匿名可访问是当前最值得深入的信息泄漏点", AMBER),
    ("[证据] 引用 seq=[1..10] · 链式哈希 integrity √ · 反幻觉校验通过", GREEN),
]
SCREEN2 = [
    (P3, FG),
    (P4, DIM),
    ("[闸门] verifier = FlagRegexVerifier · 预算 20min · 工具白名单已切换", CYAN),
    ("[01] file_type     → 703B · text/plain", FG),
    ("[02] codec_chain   → hex → base64 → rot13 逐层解开", FG),
    ("[收口] flag{layered_encodings_ok}   ✔ FlagRegexVerifier", GREEN),
]

frames = []


def push(badge, color, lines, n=2):
    for i in range(n):
        frames.append(screen(badge, color, lines, cursor_on=(i % 2 == 0)))


# 屏一：逐行打出
for i in range(len(SCREEN1) + 1):
    push("pentest-standard", BLUE, SCREEN1[:i], 2 if i else 6)
# 屏一停留（光标闪烁）
push("pentest-standard", BLUE, SCREEN1, 36)
# 屏二：逐行打出
for i in range(len(SCREEN2) + 1):
    push("ctf-crypto", PURPLE, SCREEN2[:i], 2 if i else 6)
# 屏二停留（光标闪烁）
push("ctf-crypto", PURPLE, SCREEN2, 36)

OUT.parent.mkdir(parents=True, exist_ok=True)
pal = [f.convert("P", palette=Image.ADAPTIVE, colors=64) for f in frames]
pal[0].save(OUT, save_all=True, append_images=pal[1:], duration=90,
            loop=0, optimize=True)
print(f"written: {OUT} ({OUT.stat().st_size / 1024:.0f} KB, {len(pal)} frames)")
