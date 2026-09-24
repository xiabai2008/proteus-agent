#!/usr/bin/env python3
"""
YARA MCP Server

A Model Context Protocol server that provides malware detection
and pattern matching capabilities using YARA rules.

Tools:
    - yara_scan: Scan files/directories with YARA rules
    - yara_scan_with_rules: Scan with custom inline rules
    - list_rulesets: List available YARA rule sets
    - get_scan_results: Retrieve previous scan results
    - list_active_scans: Show running scans
"""

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Resource,
    TextContent,
    Tool,
)
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("yara-mcp")


class Settings(BaseSettings):
    """Server configuration from environment variables."""

    rules_dir: str = Field(default="/app/rules", alias="YARA_RULES_DIR")
    output_dir: str = Field(default="/app/output", alias="YARA_OUTPUT_DIR")
    default_timeout: int = Field(default=300, alias="YARA_TIMEOUT")
    max_concurrent_scans: int = Field(default=2, alias="YARA_MAX_CONCURRENT")
    max_file_size: int = Field(default=104857600, alias="YARA_MAX_FILE_SIZE")  # 100MB

    class Config:
        env_prefix = "YARA_"


settings = Settings()


class YaraMatch(BaseModel):
    """Model for a YARA rule match."""

    rule: str
    namespace: str | None = None
    tags: list[str] = []
    meta: dict[str, Any] = {}
    strings: list[dict[str, Any]] = []
    file: str | None = None


class ScanResult(BaseModel):
    """Model for scan results."""

    scan_id: str
    target: str
    scan_type: str
    started_at: datetime
    completed_at: datetime | None = None
    status: str = "running"
    matches: list[YaraMatch] = []
    files_scanned: int = 0
    stats: dict[str, Any] = {}
    error: str | None = None
    raw_output: str | None = None


# In-memory storage for scan results
scan_results: dict[str, ScanResult] = {}
active_scans: set[str] = set()


def parse_yara_output(output: str) -> list[YaraMatch]:
    """Parse YARA command line output."""
    matches = []

    for line in output.strip().split("\n"):
        if not line.strip():
            continue

        # YARA output format: rule_name [tags] file_path
        # Or with -s: rule_name file_path
        # 0x123:$string_id: matched_data
        parts = line.split(" ", 1)
        if len(parts) >= 2:
            rule_name = parts[0]
            file_path = parts[1].strip()

            # Skip string match lines (start with hex offset)
            if rule_name.startswith("0x"):
                continue

            matches.append(YaraMatch(
                rule=rule_name,
                file=file_path,
            ))

    return matches


def get_available_rulesets() -> list[dict[str, Any]]:
    """List available YARA rule files."""
    rulesets = []
    rules_path = Path(settings.rules_dir)

    if rules_path.exists():
        for rule_file in rules_path.rglob("*.yar"):
            relative_path = rule_file.relative_to(rules_path)
            rulesets.append({
                "name": rule_file.stem,
                "path": str(relative_path),
                "full_path": str(rule_file),
                "size": rule_file.stat().st_size,
            })

        for rule_file in rules_path.rglob("*.yara"):
            relative_path = rule_file.relative_to(rules_path)
            rulesets.append({
                "name": rule_file.stem,
                "path": str(relative_path),
                "full_path": str(rule_file),
                "size": rule_file.stat().st_size,
            })

    return rulesets


async def run_yara_scan(
    target: str,
    rules: str | None = None,
    rules_file: str | None = None,
    recursive: bool = True,
    timeout: int | None = None,
) -> ScanResult:
    """Execute a YARA scan asynchronously."""
    scan_id = str(uuid.uuid4())[:8]

    result = ScanResult(
        scan_id=scan_id,
        target=target,
        scan_type="file" if Path(target).is_file() else "directory",
        started_at=datetime.now(),
    )
    scan_results[scan_id] = result
    active_scans.add(scan_id)

    # Determine rules to use
    if rules:
        # Custom inline rules - write to temp file
        rules_path = Path(settings.output_dir) / f"rules_{scan_id}.yar"
        rules_path.write_text(rules)
        rules_arg = str(rules_path)
    elif rules_file:
        # Specific rules file
        if not Path(rules_file).is_absolute():
            rules_arg = str(Path(settings.rules_dir) / rules_file)
        else:
            rules_arg = rules_file
    else:
        # Use all rules in rules directory
        rules_arg = str(Path(settings.rules_dir) / "index.yar")
        if not Path(rules_arg).exists():
            # Fall back to scanning with all .yar files
            rules_arg = settings.rules_dir

    # Build YARA command
    cmd = ["yara"]

    if recursive and Path(target).is_dir():
        cmd.append("-r")

    # Add warnings for better output
    cmd.append("-w")

    cmd.extend([rules_arg, target])

    logger.info(f"Starting YARA scan {scan_id} for target: {target}")
    logger.debug(f"Command: {' '.join(cmd)}")

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=float(timeout or settings.default_timeout),
        )

        result.completed_at = datetime.now()
        stdout_text = stdout.decode()
        result.raw_output = stdout_text

        # Parse output
        result.matches = parse_yara_output(stdout_text)

        # Count files scanned
        if Path(target).is_dir():
            result.files_scanned = sum(1 for _ in Path(target).rglob("*") if _.is_file())
        else:
            result.files_scanned = 1

        # Generate stats
        rules_matched = set(m.rule for m in result.matches)
        files_matched = set(m.file for m in result.matches if m.file)

        result.stats = {
            "total_matches": len(result.matches),
            "unique_rules_matched": len(rules_matched),
            "files_with_matches": len(files_matched),
            "files_scanned": result.files_scanned,
            "rules_matched": list(rules_matched),
        }

        if process.returncode == 0:
            result.status = "completed"
            logger.info(f"Scan {scan_id} completed: {len(result.matches)} matches")
        else:
            stderr_text = stderr.decode()
            if "error" in stderr_text.lower():
                result.status = "failed"
                result.error = stderr_text
                logger.error(f"Scan {scan_id} failed: {stderr_text}")
            else:
                result.status = "completed"
                if stderr_text:
                    result.error = stderr_text

    except asyncio.TimeoutError:
        result.status = "timeout"
        result.error = f"Scan timed out after {timeout or settings.default_timeout} seconds"
        result.completed_at = datetime.now()
        logger.error(f"Scan {scan_id} timed out")

    except Exception as e:
        result.status = "error"
        result.error = str(e)
        result.completed_at = datetime.now()
        logger.exception(f"Scan {scan_id} error: {e}")

    finally:
        active_scans.discard(scan_id)
        scan_results[scan_id] = result

        # Clean up temp rules file
        if rules:
            temp_rules = Path(settings.output_dir) / f"rules_{scan_id}.yar"
            temp_rules.unlink(missing_ok=True)

    return result


def format_scan_summary(result: ScanResult) -> dict[str, Any]:
    """Format scan result for response."""
    matches_summary = []
    for match in result.matches[:100]:  # Limit to 100
        matches_summary.append({
            "rule": match.rule,
            "file": match.file,
            "tags": match.tags,
        })

    return {
        "scan_id": result.scan_id,
        "target": result.target,
        "scan_type": result.scan_type,
        "status": result.status,
        "stats": result.stats,
        "matches": matches_summary,
        "error": result.error,
    }


# Create MCP server
app = Server("yara-mcp")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available tools."""
    return [
        Tool(
            name="yara_scan",
            description="Scan files or directories using YARA rules for malware detection "
            "and pattern matching. Uses pre-installed rule sets by default.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "File or directory path to scan",
                    },
                    "rules_file": {
                        "type": "string",
                        "description": "Specific YARA rules file to use (relative to rules dir)",
                    },
                    "recursive": {
                        "type": "boolean",
                        "description": "Scan directories recursively",
                        "default": True,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Scan timeout in seconds",
                        "default": 300,
                    },
                },
                "required": ["target"],
            },
        ),
        Tool(
            name="yara_scan_with_rules",
            description="Scan files using custom inline YARA rules. "
            "Provide your own YARA rule definitions.",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "File or directory path to scan",
                    },
                    "rules": {
                        "type": "string",
                        "description": "YARA rules as a string (e.g., 'rule test { strings: $a = \"malware\" condition: $a }')",
                    },
                    "recursive": {
                        "type": "boolean",
                        "description": "Scan directories recursively",
                        "default": True,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Scan timeout in seconds",
                        "default": 300,
                    },
                },
                "required": ["target", "rules"],
            },
        ),
        Tool(
            name="list_rulesets",
            description="List available YARA rule sets and their details.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        Tool(
            name="get_scan_results",
            description="Retrieve results from a previous scan by scan ID.",
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Scan ID returned from a previous scan",
                    },
                    "include_raw": {
                        "type": "boolean",
                        "description": "Include raw YARA output",
                        "default": False,
                    },
                },
                "required": ["scan_id"],
            },
        ),
        Tool(
            name="list_active_scans",
            description="List currently running scans.",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle tool calls."""
    try:
        if name == "yara_scan":
            if len(active_scans) >= settings.max_concurrent_scans:
                return [
                    TextContent(
                        type="text",
                        text=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached.",
                    )
                ]

            target = arguments["target"]
            if not Path(target).exists():
                return [
                    TextContent(type="text", text=f"Target not found: {target}")
                ]

            result = await run_yara_scan(
                target=target,
                rules_file=arguments.get("rules_file"),
                recursive=arguments.get("recursive", True),
                timeout=arguments.get("timeout"),
            )

            return [
                TextContent(
                    type="text",
                    text=json.dumps(format_scan_summary(result), indent=2),
                )
            ]

        elif name == "yara_scan_with_rules":
            if len(active_scans) >= settings.max_concurrent_scans:
                return [
                    TextContent(
                        type="text",
                        text=f"Maximum concurrent scans ({settings.max_concurrent_scans}) reached.",
                    )
                ]

            target = arguments["target"]
            if not Path(target).exists():
                return [
                    TextContent(type="text", text=f"Target not found: {target}")
                ]

            rules = arguments["rules"]
            if not rules.strip():
                return [
                    TextContent(type="text", text="Rules cannot be empty")
                ]

            result = await run_yara_scan(
                target=target,
                rules=rules,
                recursive=arguments.get("recursive", True),
                timeout=arguments.get("timeout"),
            )

            return [
                TextContent(
                    type="text",
                    text=json.dumps(format_scan_summary(result), indent=2),
                )
            ]

        elif name == "list_rulesets":
            rulesets = get_available_rulesets()

            return [
                TextContent(
                    type="text",
                    text=json.dumps({
                        "rules_directory": settings.rules_dir,
                        "rulesets": rulesets,
                        "total_rulesets": len(rulesets),
                    }, indent=2),
                )
            ]

        elif name == "get_scan_results":
            scan_id = arguments["scan_id"]
            result = scan_results.get(scan_id)

            if result:
                output = format_scan_summary(result)
                if arguments.get("include_raw") and result.raw_output:
                    output["raw_output"] = result.raw_output[:10000]
                return [
                    TextContent(
                        type="text",
                        text=json.dumps(output, indent=2),
                    )
                ]
            else:
                return [
                    TextContent(type="text", text=f"Scan '{scan_id}' not found")
                ]

        elif name == "list_active_scans":
            active = [
                {
                    "scan_id": scan_id,
                    "target": scan_results[scan_id].target,
                    "scan_type": scan_results[scan_id].scan_type,
                    "started_at": scan_results[scan_id].started_at.isoformat(),
                }
                for scan_id in active_scans
                if scan_id in scan_results
            ]

            return [
                TextContent(
                    type="text",
                    text=json.dumps(
                        {
                            "active_scans": active,
                            "count": len(active),
                            "max_concurrent": settings.max_concurrent_scans,
                        },
                        indent=2,
                    ),
                )
            ]

        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]

    except Exception as e:
        logger.exception(f"Error executing tool {name}: {e}")
        return [TextContent(type="text", text=f"Error: {str(e)}")]


@app.list_resources()
async def list_resources() -> list[Resource]:
    """List available resources."""
    resources = []

    for scan_id, result in scan_results.items():
        if result.status == "completed":
            match_count = len(result.matches)
            resources.append(
                Resource(
                    uri=f"yara://results/{scan_id}",
                    name=f"Scan Results: {result.target} ({match_count} matches)",
                    description=f"{result.scan_type} scan completed at {result.completed_at}",
                    mimeType="application/json",
                )
            )

    return resources


@app.read_resource()
async def read_resource(uri: str) -> str:
    """Read a resource."""
    if uri.startswith("yara://results/"):
        scan_id = uri.replace("yara://results/", "")
        result = scan_results.get(scan_id)
        if result:
            return json.dumps(format_scan_summary(result), indent=2)

    return json.dumps({"error": "Resource not found"})


async def main():
    """Run the MCP server."""
    logger.info("Starting YARA MCP Server")
    logger.info(f"Rules directory: {settings.rules_dir}")
    logger.info(f"Output directory: {settings.output_dir}")

    # Ensure directories exist
    Path(settings.output_dir).mkdir(parents=True, exist_ok=True)
    Path(settings.rules_dir).mkdir(parents=True, exist_ok=True)

    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
