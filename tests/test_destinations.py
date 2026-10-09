import pytest

from mcp_weir.destinations import (
    classify_target,
    is_internal_host,
    normalize_path,
    parse_addresses,
    parse_url,
    valid_host,
)

D = ["corp.example"]


@pytest.mark.parametrize(
    "addr",
    [
        "lee@corp.example",
        "Lee <lee@corp.example>",
        "a@b.corp.example",
        "LEE@CORP.EXAMPLE",
        "a@corp.example, b@corp.example",
    ],
)
def test_internal_addresses(addr):
    assert classify_target("email", addr, D).kind == "internal"


@pytest.mark.parametrize(
    "addr",
    [
        "x@corp.example.evil.net",  # suffix trick
        "x@evilcorp.example",  # not a subdomain
        "x@corp-example.com",  # lookalike
        "lee@corp.example, x@evil.net",  # one external recipient taints the list
        "x%evil.net@corp.example",  # percent-hack source route
        "x@corp.example@evil.net",  # two @
        "lee@corp.example\n@evil.net",
        "<lee@corp.example> trailing",
        "",
        "no-at-sign",
        "x@localhost",  # single label host
        "x@corp.example.",  # trailing dot is normalised -> internal; checked separately
    ][:-1],
)
def test_lookalike_and_ambiguous_addresses_are_external(addr):
    assert classify_target("email", addr, D).external


def test_trailing_dot_is_normalised():
    assert classify_target("email", "x@corp.example.", D).kind == "internal"


def test_non_string_and_lists():
    assert classify_target("email", ["a@corp.example", "b@corp.example"], D).kind == "internal"
    assert classify_target("email", ["a@corp.example", 7], D).external
    assert classify_target("email", None, D).external
    assert parse_addresses({"a": 1}) == ([], False)


@pytest.mark.parametrize("url", ["https://corp.example/a", "http://wiki.corp.example:8080/x?y=1"])
def test_internal_urls(url):
    assert classify_target("url", url, D).kind == "internal"


@pytest.mark.parametrize(
    "url",
    [
        "https://corp.example@evil.net/",  # userinfo trick: the host is evil.net
        "https://corp.example.evil.net/",
        "https://evil.net\\@corp.example/",  # backslash: parsers disagree, so rejected
        "https://evil.net#@corp.example/",
        "https://corp.example:pw@a@evil.net/",  # two @
        "ftp://corp.example/",
        "//corp.example/path",
        "https://corp.example /x",  # whitespace
        "https://\x00corp.example/",
        "https://[::1]/",
        "https://localhost/",
        "not a url",
        "",
        "https://xn--corp-example-9x.com/",
    ],
)
def test_url_tricks_are_external(url):
    assert classify_target("url", url, D).external


def test_url_parsing_details():
    u = parse_url("HTTPS://Docs.Example:8443/A/b?q=1#f")
    assert u is not None and (u.host, u.port, u.path, u.query) == ("docs.example", 8443, "/A/b", "q=1")
    assert parse_url(5) is None


def test_entities_for_tracking():
    d = classify_target("email", "Bob <bob@partner.example>", D)
    assert "bob@partner.example" in d.entities and "partner.example" in d.entities
    u = classify_target("url", "https://evil.example/collect?d=1", D)
    assert "evil.example" in u.entities and "evil.example/collect" in u.entities


def test_paths_and_objects():
    d = classify_target("path", "/docs/../secrets/key.txt", D)
    assert d.kind == "object" and d.entities[0] == "/secrets/key.txt" and "key.txt" in d.entities
    assert normalize_path("relative/x") is None and normalize_path("/a\x00b") is None
    assert classify_target("other", 12345678, D).kind == "object"


def test_host_validation():
    assert valid_host("Example.COM.") == "example.com"
    assert (
        valid_host("exa mple.com") is None
        and valid_host("-bad.example.com") is None
        and valid_host("a" * 64 + ".com") is None
    )
    assert is_internal_host("a.b.corp.example", D) and not is_internal_host("xcorp.example", D)
