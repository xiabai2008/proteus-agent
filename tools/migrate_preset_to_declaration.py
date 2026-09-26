# -*- coding: utf-8 -*-
"""把 legacy 目录 preset（proteus-ctf-web）迁移成新版 DSH 的 declaration row，
注入官方桌面端 profile patch（~/.dsh/profiles/desktop/cordis.patch.yml）。

依据（安装版 app.asar 内置文档 "Editing Cordis compositions"）：
  - 新版 DSH 不再扫描 $DSH_HOME/.agent-presets（"Nothing reads that directory
    any more"）；preset 改为 @deepseek-ai/dsh-agent-preset 的声明行，随 bundle
    patch / profile patch 分发。
  - 声明行 config 字段：id / plugins(必填) + name / description / order(可选)。
  - plugins 里的 './xxx.mjs' 相对"声明所在文件目录"解析 -> 把四个 mjs 复制到
    profile 目录，相对路径保持 './' 语义不变。
"""
import io
import os
import shutil
import subprocess
import sys

HOME = os.path.expanduser('~')
PROFILE_DIR = os.path.join(HOME, '.dsh', 'profiles', 'desktop')
PATCH = os.path.join(PROFILE_DIR, 'cordis.patch.yml')
BACKUP = PATCH + '.bak-before-declaration'
LEGACY_DIR = os.path.join(HOME, '.dsh', '.agent-presets', 'proteus-ctf-web')
AGENT_YML = os.path.join(LEGACY_DIR, 'agent.cordis.yml')
MJS = ['proteus-persona.mjs', 'proteus-tools-policy.mjs',
       'proteus-supervisor.mjs', 'proteus-commands.mjs']

# ---- 1. backup current patch ----
if not os.path.exists(BACKUP):
    shutil.copy2(PATCH, BACKUP)
    print('backup ->', BACKUP)
else:
    print('backup exists ->', BACKUP)

# ---- 2. read legacy agent.cordis.yml, skip header comments ----
with io.open(AGENT_YML, 'r', encoding='utf-8') as f:
    lines = f.read().splitlines()
start = next(i for i, ln in enumerate(lines) if ln.startswith('- id:'))
body = lines[start:]
# sanity: col-0 lines must be list items; comments/blank allowed; deeper indent fine
for ln in body:
    if not ln.strip() or ln.lstrip().startswith('#'):
        continue
    if not ln.startswith(' '):
        assert ln.startswith('- '), 'unexpected top-level line: ' + ln[:80]
# indent +10 so top-level '- id:' lands at col 10 under 'plugins:' (col 8)
indented = ['          ' + ln if ln.strip() else '' for ln in body]
# strip comment-only lines to keep the patch compact (keep structure lines)
indented = [ln for ln in indented if ln.strip() == '' or not ln.lstrip().startswith('#')]

# ---- 3. copy the four local plugin files next to the profile patch ----
for name in MJS:
    src = os.path.join(LEGACY_DIR, name)
    dst = os.path.join(PROFILE_DIR, name)
    shutil.copy2(src, dst)
    print('copied', dst)

# ---- 4. assemble declaration block ----
declaration = u'''
# ======================================================================
# Proteus preset（declaration row，适配新版 DSH 桌面端）
# 旧机制 ~/.dsh/.agent-presets 目录扫描已被新版移除（"Nothing reads that
# directory any more"）；preset 改为 @deepseek-ai/dsh-agent-preset 声明行。
# plugins 逐字取自 legacy agent.cordis.yml；'./proteus-*.mjs' 相对本文件
# 所在目录解析，四个插件文件已复制到本目录（见上方 MJS 复制步骤）。
# 迁移依据：安装版 app.asar 内置文档 "Editing Cordis compositions"。
# ======================================================================
- insert:
    - id: preset-proteus-ctf-web
      name: '@deepseek-ai/dsh-agent-preset'
      config:
        id: proteus-ctf-web
        name: Proteus CTF-Web
        description: CTF Web 解题（codec 链 / HTTP 原始证据 / 容器化 RE 工具；flag 判定）。仅用于授权范围内的受控安全实验。
        order: 10
        plugins:
''' + '\n'.join(indented).rstrip() + '\n'

# ---- 5. append to profile patch ----
with io.open(PATCH, 'r', encoding='utf-8') as f:
    current = f.read()
marker = u'# Proteus preset（declaration row'
if marker in current:
    print('declaration already present; replacing old block')
    head = current.split(u'# ======================================================================\n# Proteus preset')[0]
    current = head.rstrip() + '\n'
with io.open(PATCH, 'a', encoding='utf-8') as f:
    f.write(declaration)
print('patched ->', PATCH)

# ---- 6. validate with js-yaml from the harness repo ----
script = u"const y=require('js-yaml');const fs=require('fs');" \
         u"let d=fs.readFileSync(%r,'utf8').replace(/!!js /g,'!js ');" \
         u"const t=new y.Type('!js',{kind:'scalar',resolve:()=>true,construct:s=>s});" \
         u"const schema=y.DEFAULT_SCHEMA.extend({implicit:[t]});" \
         u"const doc=y.load(d,{schema});console.log('YAML OK, entries:',doc.length);" \
         u"const ins=doc.filter(e=>e.insert);console.log('insert blocks:',ins.length);" \
         u"const dec=ins[0].insert[0];console.log('decl id:',dec.id,'| preset:',dec.config.id,'| plugin rows:',dec.config.plugins.length);" % PATCH.replace('\\', '/')
r = subprocess.run([r'C:/Users/HZR/.workbuddy/binaries/node/versions/22.22.2-3/node.exe', '-e', script],
                   cwd=r'D:/HZR_PROJECTS/deepseek-harness', capture_output=True, text=True)
print(r.stdout.strip())
if r.returncode != 0:
    print('VALIDATION FAILED:')
    print(r.stderr[-2000:])
    sys.exit(1)
print('OK')
