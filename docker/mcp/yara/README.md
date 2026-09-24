# YARA MCP Server

A Model Context Protocol server that provides malware detection and pattern matching capabilities using [YARA](https://virustotal.github.io/yara/).

## Tools

| Tool | Description |
|------|-------------|
| `yara_scan` | Scan files/directories with pre-installed YARA rules |
| `yara_scan_with_rules` | Scan with custom inline YARA rules |
| `list_rulesets` | List available YARA rule sets |
| `get_scan_results` | Retrieve results from a previous scan |
| `list_active_scans` | Show currently running scans |

## Features

- **Pre-installed Rulesets**: Includes malware, crypto, and packer detection rules
- **Custom Rules**: Write and use custom YARA rules on the fly
- **Recursive Scanning**: Scan entire directories
- **Pattern Matching**: Detect malware signatures, packers, crypto implementations

## Pre-installed Rule Categories

The image comes with rules from [Yara-Rules/rules](https://github.com/Yara-Rules/rules):

- **malware/**: Malware family signatures
- **crypto/**: Cryptographic implementations
- **packers/**: Executable packers and protectors
- **cve_rules/**: CVE-specific detection rules

## Docker

### Build

```bash
docker build -t yara-mcp .
```

### Run

```bash
docker run --rm -i yara-mcp
```

### With sample files volume

```bash
docker run --rm -i \
  -v /path/to/samples:/app/samples:ro \
  -v /path/to/custom-rules:/app/rules:ro \
  yara-mcp
```

## Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "yara": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "/path/to/samples:/app/samples:ro",
        "yara-mcp"
      ]
    }
  }
}
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `YARA_RULES_DIR` | `/app/rules` | Directory containing YARA rules |
| `YARA_OUTPUT_DIR` | `/app/output` | Directory for scan results |
| `YARA_TIMEOUT` | `300` | Default scan timeout (seconds) |
| `YARA_MAX_CONCURRENT` | `2` | Maximum concurrent scans |
| `YARA_MAX_FILE_SIZE` | `104857600` | Max file size to scan (100MB) |

## Example Usage

### Scan with pre-installed rules

```
Scan /app/samples/suspicious.exe for malware using YARA rules
```

### Scan with specific ruleset

```
Scan /app/samples/ with the packers ruleset to detect packed executables
```

### Scan with custom rules

```
Scan /app/samples/file.bin with this custom YARA rule:
rule detect_backdoor {
    strings:
        $cmd = "cmd.exe" nocase
        $shell = "/bin/sh"
        $connect = "connect" nocase
    condition:
        any of them
}
```

### List available rulesets

```
What YARA rulesets are available?
```

## Writing YARA Rules

Example YARA rule structure:

```yara
rule example_malware {
    meta:
        description = "Detects Example Malware"
        author = "Security Researcher"
        date = "2024-01-01"

    strings:
        $magic = { 4D 5A }  // MZ header
        $str1 = "malicious_function" nocase
        $str2 = /https?:\/\/[a-z0-9.-]+\/[a-z0-9]+\.exe/i

    condition:
        $magic at 0 and any of ($str*)
}
```

## Security Notice

This tool is designed for authorized malware analysis and security research only. Only analyze files you have permission to examine.

## License

MIT
