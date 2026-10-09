import pytest

from mcp_weir.labels import Conf, Integ, Label
from mcp_weir.policy import Action, Effect, PolicyError, ResultRule, load_policy, parse_policy

BASE = {"policy": {"name": "t", "internal_domains": ["corp.example"]}}


def test_example_policy_loads(policy):
    assert policy.name == "workspace" and len(policy.tools) == 10 and len(policy.upstreams) == 4
    assert policy.tool("mail__send_message").effect is Effect.EGRESS
    assert policy.tool("nope") is None


def test_digest_is_stable_and_sensitive(policy):
    assert policy.digest == load_policy("examples/policies/workspace.toml").digest
    assert policy.with_rules(trifecta="off").digest != policy.digest


def test_with_rules(policy):
    p = policy.with_rules(trifecta="deny", egress_budget_limit=9)
    assert (
        p.rules.trifecta is Action.DENY and p.rules.egress_budget_limit == 9 and policy.rules.trifecta is Action.APPROVE
    )
    with pytest.raises(PolicyError):
        policy.with_rules(nonsense="off")
    with pytest.raises(ValueError):
        policy.with_rules(trifecta="maybe")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(extra=1),  # unknown top-level key
        lambda d: d["policy"].update(nme="x"),
        lambda d: d.update(rules={"trifecta": "sometimes"}),
        lambda d: d.update(rules={"unknown_rule": "off"}),
        lambda d: d.update(tracker={"k_secret": 30, "k_internal": 10}),
        lambda d: d.update(tracker={"k_secret": "8"}),
        lambda d: d.update(tools={"mail_send": {"effect": "egress", "content": ["body"]}}),  # no <server>__<tool>
        lambda d: d.update(tools={"mail__send": {"effect": "launch"}}),
        lambda d: d.update(tools={"mail__send": {"effect": "egress"}}),  # egress needs target/content
        lambda d: d.update(tools={"mail__send": {"effect": "read", "result": {"conf": "top-secret"}}}),
        lambda d: d.update(tools={"mail__send": {"effect": "write", "target": {"to": "carrier-pigeon"}}}),
        lambda d: d.update(tools={"mail__send": {"effect": "read", "result_rules": [{"arg": "p"}]}}),
        lambda d: d.update(tools={"mail__send": {"effect": "read", "rules": {"trifecta": "x"}}}),
        lambda d: d.update(upstreams={"Mail": {"command": ["x"]}}),  # uppercase
        lambda d: d.update(upstreams={"ma__il": {"command": ["x"]}}),  # double underscore
        lambda d: d.update(upstreams={"mail": {"command": []}}),
        lambda d: d.update(upstreams={"mail": {"command": ["x"], "env": {"A": 1}}}),
        lambda d: d.update(
            upstreams={"mail": {"command": ["x"]}}, tools={"files__read": {"effect": "read"}}
        ),  # undeclared server
        lambda d: d["policy"].update(internal_domains="corp.example"),
        lambda d: d["policy"].update(max_arg_bytes=1),
    ],
)
def test_invalid_policies_are_rejected(mutate):
    d = {"policy": dict(BASE["policy"])}
    mutate(d)
    with pytest.raises(PolicyError):
        parse_policy(d)


def test_missing_name_and_unreadable_file(tmp_path):
    with pytest.raises(PolicyError):
        parse_policy({"policy": {}})
    with pytest.raises(PolicyError):
        load_policy(tmp_path / "missing.toml")
    bad = tmp_path / "bad.toml"
    bad.write_text("this is = = not toml")
    with pytest.raises(PolicyError):
        load_policy(bad)


SECRET = Label(Conf.SECRET, Integ.TRUSTED)


@pytest.mark.parametrize(
    ("path", "secret"),
    [
        ("/secrets/payroll.txt", True),
        ("/secrets/nested/deep.txt", True),
        ("/docs/../secrets/payroll.txt", True),  # traversal is normalised
        ("//secrets//payroll.txt", True),
        ("secrets/payroll.txt", True),  # relative paths are tried as absolute too
        ("/docs/%2e%2e/secrets/payroll.txt", True),  # percent-encoded traversal
        ("%2Fsecrets%2Fpayroll.txt", True),
        ("/docs/q3.txt", False),
        ("/secretsx/a.txt", False),
    ],
)
def test_result_rule_path_matching_fails_closed(policy, path, secret):
    spec = policy.tool("files__read_file")
    assert (spec.result_label_for({"path": path}).conf is Conf.SECRET) == secret


def test_result_rule_missing_or_odd_argument_is_over_labelled(policy):
    spec = policy.tool("files__read_file")
    assert spec.result_label_for({}).conf is Conf.SECRET  # unknown path: assume the worst
    assert spec.result_label_for({"path": 123}).conf is Conf.SECRET
    assert ResultRule("p", SECRET, equals="/x").matches({"p": "/x"})


def test_public_rule_does_not_lower_the_label(policy):
    # a /public/ rule can only raise a label via join; the base label stays internal
    assert policy.tool("files__read_file").result_label_for({"path": "/public/sheet.txt"}).conf is Conf.INTERNAL
