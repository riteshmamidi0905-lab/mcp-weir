"""A minimal stdio MCP server whose only tool reports the environment variables it can see."""

import json
import os
import sys

for raw in sys.stdin:
    msg = json.loads(raw)
    rid, method = msg.get("id"), msg.get("method")
    if method == "initialize":
        res = {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "probe", "version": "0"},
        }
    elif method == "tools/list":
        res = {"tools": [{"name": "env", "description": "env", "inputSchema": {"type": "object"}}]}
    elif method == "tools/call":
        res = {"content": [{"type": "text", "text": json.dumps(sorted(os.environ))}], "isError": False}
    else:
        continue
    print(json.dumps({"jsonrpc": "2.0", "id": rid, "result": res}), flush=True)
