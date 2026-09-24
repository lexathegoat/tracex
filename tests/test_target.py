import pytest 

from tracex.core.target import Target, TargetType

def test_email_is_normalized():
    t = Target.parse(TargetType.EMAIL, " Test.User@EXAMPLE.com")
    assert t.value == "test.user@example.com"
    assert t.domain == "example.com"

@pytest.mark.parametrize("bad", ["", "no-at.com", "a@b", "@example.com", "a..b@example.com", "a@-x.com"])
def test_invalid_emails(bad):
    with pytest.raises(ValueError):
        Target.parse(TargetType.EMAIL, bad)

def test_domain_and_ip():
    assert Target.parse(TargetType.DOMAIN, "Example.COM.").value == "example.com"
    assert Target.parse(TargetType.IP, "8.8.8.8").value == "8.8.8.8"
    with pytest.raises(ValueError):
        Target.parse(TargetType.DOMAIN, "1.2.3.4")

def test_username_stripts_at():
    assert Target.parse(TargetType.USERNAME, "@lexa").value == "lexa"

@pytest.mark.parametrize(
    "raw, excepted",
    [
        ("a@example.com", TargetType.EMAIL),
        ("8.8.8.8", TargetType.IP),
        ("2001:4860:4860::8888", TargetType.IP),
        ("example.com", TargetType.DOMAIN),
        ("lexa", TargetType.USERNAME),
    ],
)
def test_detect(raw, excepted):
    assert Target.detect(raw).type is excepted