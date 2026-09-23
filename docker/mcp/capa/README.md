# Capa MCP Server

Binary capability detection using [Mandiant's capa](https://github.com/mandiant/capa).

## Tools

| Tool | Description |
|------|-------------|
| `capa_analyze` | Analyze binary capabilities |
| `get_analysis_results` | Retrieve previous analysis |
| `list_active_scans` | Show running analyses |

## Features

- Detect malware capabilities
- MITRE ATT&CK mapping
- Malware Behavior Catalog (MBC) mapping
- PE, ELF, shellcode analysis
- Supports .NET binaries

## Docker

```bash
docker build -t capa-mcp .
docker run --rm -i -v /path/to/samples:/app/samples:ro capa-mcp
```

## Example Usage

```
Analyze /app/samples/suspicious.exe for malware capabilities
What ATT&CK techniques does this binary use?
```

## License

MIT
