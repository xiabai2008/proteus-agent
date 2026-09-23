# SearchSploit MCP Server

Exploit database search using [SearchSploit](https://www.exploit-db.com/searchsploit).

## Tools

| Tool | Description |
|------|-------------|
| `searchsploit_search` | Search exploits by keyword |
| `searchsploit_examine` | Get exploit code by EDB-ID |
| `list_recent_searches` | Show recent searches |

## Features

- Offline Exploit-DB search
- Search by software, version, platform
- View exploit source code
- Filter by type (local, remote, DoS, etc.)

## Docker

```bash
docker build -t searchsploit-mcp .
docker run --rm -i searchsploit-mcp
```

## Example Usage

```
Search for Apache 2.4 exploits
Find WordPress plugin vulnerabilities
Get the code for exploit 42315
```

## License

MIT
