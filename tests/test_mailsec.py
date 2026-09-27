from tracex.analysis.mailsec import find_dmarc, find_spf


def test_find_spf():
    assert find_spf(["google-site-verification=abc", "v=spf1 include:_spf.google.com ~all"]) \
        == "v=spf1 include:_spf.google.com ~all"
    assert find_spf(["hello"]) is None


def test_find_dmarc_parses_policy():
    d = find_dmarc(["v=DMARC1; p=reject; pct=100; rua=mailto:x@example.com"])
    assert d is not None
    assert d["policy"] == "reject"
    assert d["pct"] == "100"


def test_find_dmarc_none():
    assert find_dmarc(["v=spf1 -all"]) is None