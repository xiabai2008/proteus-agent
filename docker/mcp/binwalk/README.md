# Binwalk MCP Server

A Model Context Protocol server that provides firmware analysis capabilities using [binwalk](https://github.com/ReFirmLabs/binwalk).

## Tools

| Tool | Description |
|------|-------------|
| `binwalk_scan` | Scan firmware for embedded files, filesystems, and signatures |
| `binwalk_extract` | Extract embedded files and filesystems recursively |
| `binwalk_entropy` | Analyze entropy to detect compression/encryption |
| `binwalk_hexdump` | Display hex dump of file sections |
| `get_scan_results` | Retrieve results from a previous scan |
| `list_extractions` | List completed extractions |
| `list_active_scans` | Show currently running scans |

## Features

- **Signature Scanning**: Identify embedded files, bootloaders, kernels, filesystems
- **Recursive Extraction**: Extract SquashFS, JFFS2, CPIO, cramfs, and compressed archives
- **Entropy Analysis**: Detect encrypted or compressed regions
- **Hex Dump**: Examine specific offsets in firmware
- **Multiple Format Support**: gzip, bzip2, lzma, xz, lz4, zstd, 7z, and more

## Supported Filesystem Types

- SquashFS (including non-standard variants via sasquatch)
- JFFS2
- CPIO
- cramfs
- UBIFS
- ext2/3/4 images
- YAFFS2

## Docker

### Build

```bash
docker build -t binwalk-mcp .
```

### Run

```bash
docker run --rm -i binwalk-mcp
```

### With firmware volume

```bash
docker run --rm -i \
  -v /path/to/firmware:/app/uploads:ro \
  -v /path/to/output:/app/output \
  binwalk-mcp
```

## Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "binwalk": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "/path/to/firmware:/app/uploads:ro",
        "-v", "/tmp/binwalk-output:/app/output",
        "binwalk-mcp"
      ]
    }
  }
}
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BINWALK_OUTPUT_DIR` | `/app/output` | Directory for extractions and results |
| `BINWALK_UPLOAD_DIR` | `/app/uploads` | Directory for firmware uploads |
| `BINWALK_TIMEOUT` | `300` | Default scan timeout (seconds) |
| `BINWALK_MAX_CONCURRENT` | `2` | Maximum concurrent scans |
| `BINWALK_MAX_FILE_SIZE` | `104857600` | Max file size (100MB) |

## Example Usage

### Scan firmware for signatures

```
Scan the firmware file /app/uploads/router.bin for embedded files and filesystems
```

### Extract firmware contents

```
Extract all embedded files from /app/uploads/router.bin
```

### Analyze entropy

```
Analyze the entropy of /app/uploads/firmware.bin to detect encrypted sections
```

### Examine specific offset

```
Show me a hex dump of /app/uploads/firmware.bin starting at offset 0x1000
```

## Common Firmware Analysis Workflow

1. **Signature Scan**: Identify what's inside the firmware
2. **Entropy Analysis**: Check for encrypted/compressed regions
3. **Extract**: Pull out filesystems and embedded files
4. **Examine**: Use hexdump to look at specific offsets

## Security Notice

This tool is designed for authorized security research and analysis only. Only analyze firmware you own or have explicit permission to examine.

## License

MIT
