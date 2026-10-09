from hypothesis import given
from hypothesis import strategies as st

from mcp_weir.labels import BOTTOM, Conf, Integ, Label, join_all

labels = st.builds(Label, st.sampled_from(Conf), st.sampled_from(Integ))


@given(labels, labels)
def test_join_is_commutative(a, b):
    assert a.join(b) == b.join(a)


@given(labels, labels, labels)
def test_join_is_associative(a, b, c):
    assert a.join(b).join(c) == a.join(b.join(c))


@given(labels)
def test_join_is_idempotent_and_bottom_is_identity(a):
    assert a.join(a) == a
    assert a.join(BOTTOM) == a


@given(labels, labels)
def test_join_is_least_upper_bound(a, b):
    j = a.join(b)
    assert a.leq(j) and b.leq(j)


@given(labels, labels)
def test_leq_is_consistent_with_join(a, b):
    assert a.leq(b) == (a.join(b) == b)


def test_join_all_and_parse_and_str():
    assert join_all([]) == BOTTOM
    assert join_all([Label(Conf.INTERNAL), Label(Conf.PUBLIC, Integ.UNTRUSTED)]) == Label(
        Conf.INTERNAL, Integ.UNTRUSTED
    )
    assert Label.parse("secret", "untrusted") == Label(Conf.SECRET, Integ.UNTRUSTED)
    assert str(Label(Conf.SECRET, Integ.TRUSTED)) == "secret/trusted"
    try:
        Label.parse("top-secret")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown label accepted")
