#!/usr/bin/env python3
"""
Capa MCP Server

A Model Context Protocol server that provides binary capability
detection using Mandiant's capa tool.

Tools:
    - capa_analyze: Analyze binary capabilities
    - capa_rules: List matching rules for a binary
    - get_analysis_results: Retrieve previous analysis
    - list_active_scans: Show running analyses
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Resource, TextContent, Tool
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("capa-mcp")


class Settings(BaseSettings):
    output_dir: str = Field(default="/app/output", alias="CAPA_OUTPUT_DIR")
    rules_dir: str = Field(default="/app/rules", alias="CAPA_RULES_DIR")
    default_timeout: int = Field(default=300, alias="CAPA_TIMEOUT")
    max_concurrent_scans: int = Field(default=2, alias="CAPA_MAX_CONCURRENT")

    class Config:
        env_prefix = "CAPA_"


settings = Settings()


class Capability(BaseModel):
    name: str
    namespace: str | None = None
    scope: str | None = None
    attack: list[str] = []
    mbc: list[str] = []


class AnalysisResult(BaseModel):
    scan_id: str
    filepath: str
    started_at: datetime
    completed_at: datetime | None = None
    status: str = "running"
    capabilities: list[Capability] = []
    stats: dict[str, Any] = {}
    error: str | None = None
    raw_output: str | None = None


scan_results: dict[str, AnalysisResult] = {}
active_scans: set[str] = set()


def parse_capa_json(output: str) -> list[Capability]:
    capabilities = []
    try:
        data = json.loads(output)
        rules = data.get("rules", {})

        for rule_name, rule_data in rules.items():
            meta = rule_data.get("meta", {})

            attack_ids = []
            for att in meta.get("attack", []):
                if isinstance(att, dict):
                    attack_ids.append(f"{att.get('technique', '')} - {att.get('id', '')}")

            mbc_ids = []
            for mbc in meta.get("mbc", []):
                if isinstance(mbc, dict):
                    mbc_ids.append(f"{mbc.get('objective', '')} - {mbc.get('id', '')}")

            capabilities.append(Capability(
                name=rule_name,
                namespace=meta.get("namespace"),
                scope=meta.get("scope"),
                attack=attack_ids,
                mbc=mbc_ids,
            ))
    except json.JSONDecodeError as e:
        logger.warning(f"Error parsing capa output: {e}")
    return capabilities


async def run_capa_analysis(
    filepath: str,
    timeout: int | None = None,
) -> AnalysisResult:
    scan_id = str(uuid.uuid4())[:8]
    output_file = Path(settings.output_dir) / f"capa_{scan_id}.json"

    result = AnalysisResult(
        scan_id=scan_id,
        filepath=filepath,
        started_at=datetime.now(),
    )
    scan_results[scan_id] = result
    active_scans.add(scan_id)

    cmd = ["capa", "-j", filepath]

    # Add rules directory if exists
    if Path(settings.rules_dir).exists():
        cmd.extend(["-r", settings.rules_dir])

    logger.info(f"Starting capa analysis {scan_id} for: {filepath}")

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
        output_content = stdout.decode()
        result.raw_output = output_content

        # Save to file
        output_file.write_text(output_content)

        result.capabilities = parse_capa_json(output_content)

        # Generate stats
        namespace_counts = {}
        attack_techniques = set()
        for cap in result.capabilities:
            if cap.namespace:
                ns = cap.namespace.split("/")[0] if "/" in cap.namespace else cap.namespace
                namespace_counts[ns] = namespace_counts.get(ns, 0) + 1
            for att in cap.attack:
                attack_techniques.add(att)

        result.stats = {
            "total_capabilities": len(result.capabilities),
            "by_namespace": namespace_counts,
            "attack_techniques": list(attack_techniques)[:20],
        }

        result.status = "completed" if process.returncode == 0 else "failed"
        if process.returncode != 0:
            result.error = stderr.decode()

    except asyncio.TimeoutError:
        result.status = "timeout"
        result.error = f"Analysis timed out after {timeout or settings.default_timeout} seconds"
        result.completed_at = datetime.now()

    except Exception as e:
        result.status = "error"
        result.error = str(e)
        result.completed_at = datetime.now()

    finally:
        active_scans.discard(scan_id)
        scan_results[scan_id] = result

    return result


def format_analysis_summary(result: AnalysisResult) -> dict[str, Any]:
    caps = []
    for c in result.capabilities[:100]:
        caps.append({
            "name": c.name,
            "namespace": c.namespace,
            "attack": c.attack,
            "mbc": c.mbc,
        })

    return {
        "scan_id": result.scan_id,
        "filepath": result.filepath,
        "status": result.status,
        "stats": result.stats,
        "capabilities": caps,
        "error": result.error,
    }


app = Server("capa-mcp")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="capa_analyze",
            description="Analyze a binary file for capabilities using Mandiant's capa. "
            "Detects malware behaviors, techniques, and capabilities mapped to MITRE ATT&CK.",
            inputSchema={
                "type": "object",
                "properties": {
                    "filepath": {
                        "type": "string",
                        "description": "Path to the binary file to analyze",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Analysis timeout in seconds",
                        "default": 300,
                    },
                },
                "required": ["filepath"],
            },
        ),
        Tool(
            name="get_analysis_results",
            description="Retrieve results from a previous analysis.",
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string", "description": "Analysis ID"},
                },
                "required": ["scan_id"],
            },
        ),
        Tool(
            name="list_active_scans",
            description="List running analyses.",
            inputSchema={"type": "object", "properties": {}},
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    try:
        if name == "capa_analyze":
            if len(active_scans) >= settings.max_concurrent_scans:
                return [TextContent(type="text", text="Max concurrent scans reached.")]

            filepath = arguments["filepath"]
            if not Path(filepath).exists():
                return [TextContent(type="text", text=f"File not found: {filepath}")]

            result = await run_capa_analysis(
                filepath=filepath,
                timeout=arguments.get("timeout"),
            )
            return [TextContent(type="text", text=json.dumps(format_analysis_summary(result), indent=2))]

        elif name == "get_analysis_results":
            result = scan_results.get(arguments["scan_id"])
            if result:
                return [TextContent(type="text", text=json.dumps(format_analysis_summary(result), indent=2))]
            return [TextContent(type="text", text="Analysis not found")]

        elif name == "list_active_scans":
            active = [{"scan_id": s, "filepath": scan_results[s].filepath} for s in active_scans if s in scan_results]
            return [TextContent(type="text", text=json.dumps({"active_scans": active}, indent=2))]

        return [TextContent(type="text", text=f"Unknown tool: {name}")]

    except Exception as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]


@app.list_resources()
async def list_resources() -> list[Resource]:
    return [
        Resource(
            uri=f"capa://results/{scan_id}",
            name=f"Capa: {Path(result.filepath).name}",
            mimeType="application/json",
        )
        for scan_id, result in scan_results.items()
        if result.status == "completed"
    ]


@app.read_resource()
async def read_resource(uri: str) -> str:
    if uri.startswith("capa://results/"):
        scan_id = uri.replace("capa://results/", "")
        result = scan_results.get(scan_id)
        if result:
            return json.dumps(format_analysis_summary(result), indent=2)
    return json.dumps({"error": "Resource not found"})


async def main():
    logger.info("Starting Capa MCP Server")
    Path(settings.output_dir).mkdir(parents=True, exist_ok=True)
    Path(settings.rules_dir).mkdir(parents=True, exist_ok=True)

    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
