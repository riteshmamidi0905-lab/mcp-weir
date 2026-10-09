"""Make one more call in an existing session through the real gateway (used by the UI test to prove live updates)."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from helpers import FIXTURE, POLICY_FILE, make_gateway

from mcp_weir.policy import load_policy
from mcp_weir.store import Store
from weir_testbed.world import World


async def main(db: str) -> None:
    st = Store(db)
    gw = make_gateway(load_policy(POLICY_FILE), st, World.from_fixture(FIXTURE))
    await gw.start()
    s = gw.open_session("live-1")
    o = await gw.call_tool_detailed(s, "web__fetch_url", {"url": "https://docs.example/api"})
    print(o.call_id)
    st.close()


asyncio.run(main(sys.argv[1]))
