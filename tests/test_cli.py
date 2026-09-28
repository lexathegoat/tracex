import pytest
from typer.testing import CliRunner

from tracex.cli import app

runner = CliRunner()


def test_help_lists_commands():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for cmd in ("email", "username", "domain", "ip"):
        assert cmd in result.stdout


def test_email_rejects_invalid_input():
    result = runner.invoke(app, ["email", "not-an-email"])
    assert result.exit_code == 2


def test_domain_rejects_invalid_input():
    result = runner.invoke(app, ["domain", "not a domain"])
    assert result.exit_code == 2


def test_domain_accepts_valid_syntax():
    result = runner.invoke(app, ["domain", "example.com"])
    assert result.exit_code == 0


def test_ip_rejects_invalid_input():
    result = runner.invoke(app, ["ip", "not-an-ip"])
    assert result.exit_code == 2


def test_ip_accepts_valid_syntax():
    result = runner.invoke(app, ["ip", "8.8.8.8"])
    assert result.exit_code == 0


def test_username_rejects_invalid_input():
    result = runner.invoke(app, ["username", ""])
    assert result.exit_code != 0


def test_username_accepts_valid_syntax():
    result = runner.invoke(app, ["username", "lexathegoat"])
    assert result.exit_code == 0