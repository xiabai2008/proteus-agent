import os
a = os.path.expandvars(r'%LOCALAPPDATA%/Programs/DeepSeek Harness/resources/app.asar')
data = open(a, 'rb').read()
pkgs = ['dsh-agent-instructions','dsh-tool-bash','dsh-tool-pwsh','dsh-tool-fs-search','dsh-tool-fs','dsh-tool-jobs','dsh-skill-filesystem','dsh-tool-skill','dsh-command-goal','dsh-tool-goal','dsh-plan-mode','dsh-compaction-basic','dsh-command-compact','dsh-compaction-tool-result-pruner','dsh-tool-subagent-control','dsh-tool-subagent','dsh-workflow-ptc','dsh-tool-workflow','dsh-tool-ralph','dsh-tool-ask-user','dsh-tool-todo','dsh-tool-web','dsh-tool-present','dsh-plugin-manager','dsh-mcp-client','dsh-persona','dsh-agent-preset','dsh-agent-preset-registry']
for p in pkgs:
    print(f"{p:38s}", data.count(p.encode()))
