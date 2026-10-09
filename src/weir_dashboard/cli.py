"""``weir-dashboard`` (or ``python -m weir_dashboard``): serve the control center on 127.0.0.1.

This is a separate command on purpose. ``weir`` lives in ``mcp_weir/cli.py``, which is one of the files the evaluation
froze; adding a subcommand there would change the frozen set.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import webbrowser
from pathlib import Path

from .server import HOST, App, create_server


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="weir-dashboard",
        description="Local browser view of a Weir database (127.0.0.1 only). Read-only except for APPROVE/DENY of held calls.",
    )
    ap.add_argument("--db", help="Weir SQLite database (default: $WEIR_DB or ./weir.db). Need not exist yet.")
    ap.add_argument("--policy", help="policy TOML the gateway runs with (enables the Policy view and rule settings)")
    ap.add_argument("--lock", help="tool-definition lock file (shown in the Policy view)")
    ap.add_argument("--port", type=int, default=8731, help="port on 127.0.0.1 (default 8731; 0 picks a free one)")
    ap.add_argument("--mask", action="store_true", help="start with destinations and clear arguments masked on screen")
    ap.add_argument("--demo-dir", help="where Demo runs are written (default: a temporary directory)")
    ap.add_argument("--open", action="store_true", help="open the page in the default browser")
    a = ap.parse_args(argv)
    if not 0 <= a.port <= 65535:
        ap.error("--port must be between 0 and 65535")
    db = a.db or os.environ.get("WEIR_DB") or "weir.db"
    demo_dir = Path(a.demo_dir) if a.demo_dir else Path(tempfile.mkdtemp(prefix="weir-dashboard-demo-"))
    app = App(db, a.policy, a.lock, a.mask, demo_dir)
    try:
        srv = create_server(app, a.port)
    except OSError as e:
        print(f"weir-dashboard: cannot listen on {HOST}:{a.port}: {e.strerror or e}", file=sys.stderr)
        return 2
    url = f"http://{HOST}:{app.port}/"
    print(f"Weir Control Center  {url}", file=sys.stderr)
    print(
        f"  database  {db}{'' if Path(db).exists() else '  (not created yet; the page will wait for it)'}",
        file=sys.stderr,
    )
    print("  listening on 127.0.0.1 only; Ctrl-C to stop", file=sys.stderr)
    if a.open:
        webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
