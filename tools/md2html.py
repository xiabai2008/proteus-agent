"""Markdown -> 单文件 HTML（浅色主题，中文排版）"""
import re
import sys
from pathlib import Path

import markdown

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "docs" / "渗透测试Agent调研报告-多模式切换.md"
DST = REPO / "docs" / "渗透测试Agent调研报告-多模式切换.html"

md_text = SRC.read_text(encoding="utf-8")

html_body = markdown.markdown(
    md_text,
    extensions=["tables", "fenced_code", "toc", "attr_list", "sane_lists"],
    extension_configs={"toc": {"permalink": False}},
)

TEMPLATE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>多模式渗透测试 Agent 调研报告</title>
<style>
  :root {
    --bg: #f7f8fa;
    --paper: #ffffff;
    --ink: #1c2024;
    --ink-2: #4a5158;
    --ink-3: #7b848c;
    --line: #e3e6ea;
    --accent: #1f5fa9;
    --accent-soft: #eaf2fb;
    --warn: #a8442b;
    --warn-soft: #fdf1ee;
    --ok: #1f7a4d;
    --ok-soft: #ecf7f1;
    --mono: "Cascadia Mono", "JetBrains Mono", Consolas, "Courier New", monospace;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--ink);
    font-family: "Microsoft YaHei", "PingFang SC", "Hiragino Sans GB", system-ui, sans-serif;
    font-size: 15.5px;
    line-height: 1.85;
    -webkit-font-smoothing: antialiased;
  }
  .wrap {
    max-width: 1080px;
    margin: 0 auto;
    padding: 48px 40px 96px;
  }
  .paper {
    background: var(--paper);
    border: 1px solid var(--line);
    border-radius: 10px;
    padding: 56px 60px 72px;
    box-shadow: 0 1px 3px rgba(20, 30, 40, .04), 0 12px 32px rgba(20, 30, 40, .05);
  }
  h1 {
    font-size: 30px;
    line-height: 1.35;
    margin: 0 0 8px;
    letter-spacing: -.2px;
  }
  h1 + blockquote { margin-top: 20px; }
  h2 {
    font-size: 22px;
    margin: 52px 0 16px;
    padding-bottom: 10px;
    border-bottom: 2px solid var(--accent);
    letter-spacing: -.1px;
  }
  h3 {
    font-size: 17.5px;
    margin: 34px 0 12px;
    padding-left: 11px;
    border-left: 4px solid var(--accent);
    color: var(--ink);
  }
  h4 { font-size: 15.5px; margin: 24px 0 8px; color: var(--ink-2); }
  p { margin: 12px 0; }
  strong { color: var(--ink); font-weight: 700; }
  a { color: var(--accent); text-decoration: none; border-bottom: 1px solid #c3d8ef; }
  ul, ol { padding-left: 24px; margin: 12px 0; }
  li { margin: 6px 0; }
  hr { border: 0; border-top: 1px solid var(--line); margin: 44px 0; }
  blockquote {
    margin: 18px 0;
    padding: 14px 20px;
    background: var(--accent-soft);
    border-left: 4px solid var(--accent);
    border-radius: 0 6px 6px 0;
    color: var(--ink-2);
    font-size: 14.5px;
  }
  blockquote p { margin: 5px 0; }
  code {
    font-family: var(--mono);
    font-size: 13px;
    background: #f0f2f5;
    border: 1px solid var(--line);
    border-radius: 4px;
    padding: 1.5px 5px;
    color: #24405c;
    word-break: break-word;
  }
  pre {
    background: #fbfcfd;
    border: 1px solid var(--line);
    border-left: 3px solid var(--accent);
    border-radius: 6px;
    padding: 16px 18px;
    overflow-x: auto;
    margin: 16px 0;
  }
  pre code { background: none; border: 0; padding: 0; font-size: 12.8px; line-height: 1.65; color: #24405c; }
  table {
    width: 100%;
    border-collapse: collapse;
    margin: 18px 0;
    font-size: 13.8px;
    display: block;
    overflow-x: auto;
  }
  th, td {
    border: 1px solid var(--line);
    padding: 9px 12px;
    text-align: left;
    vertical-align: top;
    line-height: 1.65;
  }
  th { background: #f2f5f8; font-weight: 700; color: var(--ink); white-space: nowrap; }
  tr:nth-child(even) td { background: #fafbfc; }
  td code { font-size: 12.3px; }
  .toc {
    background: #fafbfc;
    border: 1px solid var(--line);
    border-radius: 8px;
    padding: 20px 26px;
    margin: 28px 0 8px;
    font-size: 14px;
  }
  .toc-title { font-weight: 700; margin-bottom: 8px; color: var(--ink-2); font-size: 13px; letter-spacing: .5px; }
  .toc ul { list-style: none; padding-left: 0; margin: 0; }
  .toc ul ul { padding-left: 20px; margin-top: 4px; }
  .toc li { margin: 3px 0; }
  .toc a { border: 0; }
  @media (max-width: 820px) {
    .wrap { padding: 20px 14px 60px; }
    .paper { padding: 28px 20px 40px; border-radius: 8px; }
    h1 { font-size: 23px; }
    h2 { font-size: 19px; }
  }
  @media print {
    body { background: #fff; font-size: 12px; }
    .wrap { max-width: none; padding: 0; }
    .paper { border: 0; box-shadow: none; padding: 0; }
    .toc { display: none; }
    h2 { page-break-after: avoid; }
    table, pre, blockquote { page-break-inside: avoid; }
  }
</style>
</head>
<body>
<div class="wrap">
<div class="paper">
__CONTENT__
</div>
</div>
</body>
</html>
"""

# 生成简易目录
toc_items = re.findall(r"^(#{1,2})\s+(.+)$", md_text, flags=re.MULTILINE)
toc_html = ['<div class="toc"><div class="toc-title">目 录</div><ul>']
for hashes, title in toc_items:
    lvl = len(hashes)
    if lvl == 1:
        continue
    toc_html.append(f'<li>{title}</li>')
toc_html.append("</ul></div>")
toc = "\n".join(toc_html)

html = TEMPLATE.replace("__CONTENT__", toc + "\n" + html_body)
DST.write_text(html, encoding="utf-8")
print("written:", DST, len(html), "chars")
