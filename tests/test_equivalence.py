import asyncio

from weir_eval.equivalence import compare
from weir_eval.scenarios import attack, benign


def test_in_process_and_real_stdio_gateway_agree_on_a_few_scenarios():
    """The full check (many scenarios, several arms) is `python -m weir_eval.equivalence`; this keeps it from rotting."""
    scns = [attack("F1", "value", "untrusted_first", "web", 1, "dev"), benign("B06", 1, "dev")]
    rows = [asyncio.run(compare(s, "A3", m)) for s in scns for m in ("strict", "careless")]
    assert all(r["agree"] for r in rows), [r for r in rows if not r["agree"]]
