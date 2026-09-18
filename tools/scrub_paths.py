"""公开前路径清洗：把 docs/根文档 里的本机路径替换为占位符。"""
from pathlib import Path

MAP = [
    ("<REPO>", "<REPO>"),
    ("D:\\<USER>_PROJECTS\\proteus-agent", "<REPO>"),
    ("<WS>", "<WS>"),
    ("D:\\<USER>_PROJECTS", "<WS>"),
    ("<PY312>", "<PY312>"),
    ("D:\\tools\\Python 3.12.9", "<PY312>"),
    ("<USER_HOME>", "<USER_HOME>"),
    ("C:\\Users\\<USER>", "<USER_HOME>"),
    ("<TOOLS_DIR>", "<TOOLS_DIR>"),
    ("C:\\Tools\\reasonix_sentou", "<TOOLS_DIR>"),
]

targets = [Path("AGENTS.md"), Path("README.md"), Path("requirements.txt"),
           Path("penagent/adapters/packetforge.py")]
targets += sorted(Path("docs").glob("**/*.md")) + sorted(Path("docs").glob("**/*.html"))
changed = []
for p in targets:
    s = p.read_text(encoding="utf-8")
    orig = s
    for a, b in MAP:
        s = s.replace(a, b)
    if "<USER>" in s:
        s = s.replace("<USER>", "<USER>")
    if s != orig:
        p.write_text(s, encoding="utf-8")
        changed.append(str(p))
print("scrubbed:", len(changed))
for c in changed:
    print(" -", c)
