import pytest
from typer.testing import CliRunner

from tracex.cli import app

runner = CliRunner()


def test_help_lists_commands():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for cmd in ("email", "username", "domain", "ip"):
        assert cmd in result.stdout


@pytest.mark.parametrize("cmd", ["email", "username", "domain", "ip"])
def test_commands_are_stubs(cmd):
    result = runner.invoke(app, [cmd, "x"])
    assert result.exit_code == 1