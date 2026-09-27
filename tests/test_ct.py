from tracex.sources.ct import parse_hostnames


def test_parse_hostnames_dedups_and_strips_wildcards():
    records = [
        {"name_value": "*.example.com\nexample.com"},
        {"name_value": "api.example.com\nmail.example.com"},
        {"name_value": "example.com"},  # duplicate
    ]
    assert parse_hostnames(records, "example.com") == [
        "api.example.com", "example.com", "mail.example.com",
    ]


def test_parse_hostnames_ignores_unrelated_domains():
    records = [{"name_value": "evil.com\nsub.example.com"}]
    assert parse_hostnames(records, "example.com") == ["sub.example.com"]