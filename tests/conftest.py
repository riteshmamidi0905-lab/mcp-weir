import asyncio

import pytest
from helpers import FIXTURE, POLICY_FILE, make_gateway

from mcp_weir.policy import Policy, load_policy
from mcp_weir.store import Store
from weir_testbed.world import World


@pytest.fixture
def policy() -> Policy:
    return load_policy(POLICY_FILE)


@pytest.fixture
def world() -> World:
    return World.from_fixture(FIXTURE)


@pytest.fixture
def store(tmp_path):
    s = Store(str(tmp_path / "weir.db"))
    yield s
    s.close()


@pytest.fixture
def gw(policy, store, world):
    g = make_gateway(policy, store, world)
    asyncio.run(g.start())
    return g
