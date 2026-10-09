"""Weir Control Center: a local, read-mostly browser view of a Weir database.

This package is *not* part of the gateway and not part of the frozen evaluation. It imports from ``mcp_weir`` (the
store and the report builder) and nothing under ``mcp_weir`` imports it. It opens the database read-only, except for
one call, ``Store.resolve_approval``, that it makes on a separate connection when a person presses APPROVE or DENY.
"""

__version__ = "0.1.0"

# These sentences are part of the interface contract; tests/test_dashboard_claims.py fails if they change or vanish.
ANSWER_CHANNEL_NOTE = "Weir mediates MCP tool calls and results. It does not inspect the model's final answer."
SYNTHETIC_NOTE = "SYNTHETIC DEMONSTRATION: a scripted agent and a simulated approver in an invented world."
