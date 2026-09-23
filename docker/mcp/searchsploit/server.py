#!/usr/bin/env python3
"""
SearchSploit MCP Server

A Model Context Protocol server that provides exploit database
searching using SearchSploit (Exploit-DB offline search).

Tools:
    - searchsploit_search: Search for exploits by keyword
    - searchsploit_examine: Get exploit details/code
    - searchsploit_nmap: Search exploits for nmap XML results
    - list_recent_searches: Show recent search history
"""

import asyncio
import json
import logging
import re
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
logger = logging.getLogger("searchsploit-mcp")


class Settings(BaseSettings):
    output_dir: str = Field(default="/app/output", alias="SEARCHSPLOIT_OUTPUT_DIR")
    exploitdb_path: str = Field(default="/usr/share/exploitdb", alias="EXPLOITDB_PATH")
    default_timeout: int = Field(default=60, alias="SEARCHSPLOIT_TIMEOUT")

    class Config:
        env_prefix = "SEARCHSPLOIT_"


settings = Settings()


class Exploit(BaseModel):
    title: str
    edb_id: str
    date: str | None = None
    author: str | None = None
    platform: str | None = None
    type: str | None = None
    path: str | None = None


class SearchResult(BaseModel):
    search_id: str
    query: str
    searched_at: datetime
    exploits: list[Exploit] = []
    stats: dict[str, Any] = {}
    error: str | None = None


search_results: dict[str, SearchResult] = {}


def parse_searchsploit_json(output: str) -> list[Exploit]:
    exploits = []
    try:
        data = json.loads(output)
        for exp in data.get("RESULTS_EXPLOIT", []):
            exploits.append(Exploit(
                title=exp.get("Title", ""),
                edb_id=exp.get("EDB-ID", ""),
                date=exp.get("Date"),
                author=exp.get("Author"),
                platform=exp.get("Platform"),
                type=exp.get("Type"),
                path=exp.get("Path"),
            ))
    except json.JSONDecodeError:
        pass
    return exploits


async def search_exploits(
    query: str,
    exact: bool = False,
    exclude: list[str] | None = None,
    timeout: int | None = None,
) -> SearchResult:
    search_id = str(uuid.uuid4())[:8]

    result = SearchResult(
        search_id=search_id,
        query=query,
        searched_at=datetime.now(),
    )
    search_results[search_id] = result

    cmd = ["searchsploit", "-j"]

    if exact:
        cmd.append("-e")

    if exclude:
        for term in exclude:
            cmd.extend(["--exclude", term])

    cmd.append(query)

    logger.info(f"Searching exploits for: {query}")

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

        output = stdout.decode()
        result.exploits = parse_searchsploit_json(output)

        platform_counts = {}
        type_counts = {}
        for exp in result.exploits:
            if exp.platform:
                platform_counts[exp.platform] = platform_counts.get(exp.platform, 0) + 1
            if exp.type:
                type_counts[exp.type] = type_counts.get(exp.type, 0) + 1

        result.stats = {
            "total_exploits": len(result.exploits),
            "by_platform": platform_counts,
            "by_type": type_counts,
        }

    except asyncio.TimeoutError:
        result.error = "Search timed out"

    except Exception as e:
        result.error = str(e)

    return result


async def get_exploit_code(edb_id: str) -> str:
    """Get the exploit code/content."""
    cmd = ["searchsploit", "-x", edb_id]

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=30.0)
        return stdout.decode()

    except Exception as e:
        return f"Error retrieving exploit: {e}"


def format_search_summary(result: SearchResult) -> dict[str, Any]:
    return {
        "search_id": result.search_id,
        "query": result.query,
        "stats": result.stats,
        "exploits": [
            {
                "edb_id": e.edb_id,
                "title": e.title,
                "platform": e.platform,
                "type": e.type,
                "date": e.date,
            }
            for e in result.exploits[:50]
        ],
        "error": result.error,
    }


app = Server("searchsploit-mcp")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="searchsploit_search",
            description="Search Exploit-DB for exploits by keyword. "
            "Searches titles, paths, and descriptions offline.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query (e.g., 'apache 2.4', 'wordpress', 'windows smb')",
                    },
                    "exact": {
                        "type": "boolean",
                        "description": "Exact match only",
                        "default": False,
                    },
                    "exclude": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Terms to exclude from results",
                    },
                },
                "required": ["query"],
            },
        ),
        Tool(
            name="searchsploit_examine",
            description="Get the code/content of a specific exploit by EDB-ID.",
            inputSchema={
                "type": "object",
                "properties": {
                    "edb_id": {
                        "type": "string",
                        "description": "Exploit-DB ID (e.g., '42315')",
                    },
                },
                "required": ["edb_id"],
            },
        ),
        Tool(
            name="list_recent_searches",
            description="List recent exploit searches.",
            inputSchema={"type": "object", "properties": {}},
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    try:
        if name == "searchsploit_search":
            result = await search_exploits(
                query=arguments["query"],
                exact=arguments.get("exact", False),
                exclude=arguments.get("exclude"),
            )
            return [TextContent(type="text", text=json.dumps(format_search_summary(result), indent=2))]

        elif name == "searchsploit_examine":
            code = await get_exploit_code(arguments["edb_id"])
            # Truncate if too long
            if len(code) > 15000:
                code = code[:15000] + "\n\n... [truncated]"
            return [TextContent(type="text", text=json.dumps({
                "edb_id": arguments["edb_id"],
                "content": code,
            }, indent=2))]

        elif name == "list_recent_searches":
            recent = [
                {"search_id": s.search_id, "query": s.query, "results": len(s.exploits)}
                for s in list(search_results.values())[-10:]
            ]
            return [TextContent(type="text", text=json.dumps({"recent_searches": recent}, indent=2))]

        return [TextContent(type="text", text=f"Unknown tool: {name}")]

    except Exception as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]


@app.list_resources()
async def list_resources() -> list[Resource]:
    return [
        Resource(
            uri=f"searchsploit://search/{result.search_id}",
            name=f"Search: {result.query}",
            mimeType="application/json",
        )
        for result in search_results.values()
    ]


@app.read_resource()
async def read_resource(uri: str) -> str:
    if uri.startswith("searchsploit://search/"):
        search_id = uri.replace("searchsploit://search/", "")
        result = search_results.get(search_id)
        if result:
            return json.dumps(format_search_summary(result), indent=2)
    return json.dumps({"error": "Resource not found"})


async def main():
    logger.info("Starting SearchSploit MCP Server")
    Path(settings.output_dir).mkdir(parents=True, exist_ok=True)

    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
