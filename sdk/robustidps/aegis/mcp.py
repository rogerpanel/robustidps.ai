"""MCP wrapper — verdict-check tool manifests at server-startup time and
every tool-call argument at request time. No MCP framework dependency
is required — the wrapper operates on dicts that follow the MCP shape.

    from robustidps.aegis import MambaGuardClient
    from robustidps.aegis.mcp import scan_manifest, check_tool_call

    cli = MambaGuardClient()
    static = scan_manifest(server_manifest, cli)   # at startup
    runtime = check_tool_call(tool_name, args, cli) # per call
"""
from __future__ import annotations

import json
from typing import Any

from robustidps.aegis.client import MambaGuardClient, Verdict


def scan_manifest(manifest: dict[str, Any], client: MambaGuardClient | None = None) -> Verdict:
    """Run the 12-check scanner over a serialised MCP manifest at startup."""
    client = client or MambaGuardClient()
    text = json.dumps(manifest, indent=2, default=str)
    return client.check(text, input_kind="mcp_manifest",
                        context={"server_name": manifest.get("name")})


def check_tool_call(tool_name: str, arguments: dict[str, Any],
                    client: MambaGuardClient | None = None) -> Verdict:
    """Per-request verdict check on the tool name + JSON-serialised arguments."""
    client = client or MambaGuardClient()
    text = f"tool: {tool_name}\narguments: {json.dumps(arguments, default=str)}"
    return client.check(text, input_kind="tool_list",
                        context={"tool_name": tool_name})
