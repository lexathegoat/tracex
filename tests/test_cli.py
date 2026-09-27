import pytest
from typer.testing import CliRunner

from tracex.cli import app

runner = CliRunner()


def test_help_lists_commands():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for cmd in ("email", "username", "domain", "ip"):
        assert cmd in result.stdout


@pytest.mark.parametrize("cmd", ["username", "ip"])
def test_remaining_commands_are_stubs(cmd):
    result = runner.invoke(app, [cmd, "x"])
    assert result.exit_code == 1


def test_domain_rejects_invalid_input():
    result = runner.invoke(app, ["domain", "not a domain"])
    assert result.exit_code == 2


def test_domain_accepts_valid_syntax():
    # gerçek ağ isteği atar; sadece CLI'nin komutu doğru yönlendirdiğini doğruluyoruz
    result = runner.invoke(app, ["domain", "example.com"])
    assert result.exit_code == 0


def test_email_rejects_invalid_input():
    result = runner.invoke(app, ["email", "not-an-email"])
    assert result.exit_code == 2