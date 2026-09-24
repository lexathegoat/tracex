from __future__ import annotations

from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape

from tracex import __version__

app = typer.Typer(
    name="tracex",
    help="TRACE-X: Terminal OSINT & Exposure Intelligence Framework",
    no_args_is_help=True,
    add_completion=False,
)
err = Console(stderr=True)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"tracex {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True,
                     help="Show version and exit."),
    ] = False,
) -> None:
    """TRACE-X: passive OSINT and exposure analysis for targets you are authorized to investigate."""


def _not_implemented(module: str, target: str) -> None:
    err.print(f"[yellow]Not implemented yet:[/] {module} ({escape(target)})")
    raise typer.Exit(code=1)


@app.command()
def email(target: Annotated[str, typer.Argument(help="Email address")]) -> None:
    _not_implemented("email", target)


@app.command()
def username(target: Annotated[str, typer.Argument(help="Username")]) -> None:
    _not_implemented("username", target)


@app.command()
def domain(target: Annotated[str, typer.Argument(help="Domain name")]) -> None:
    _not_implemented("domain", target)


@app.command()
def ip(target: Annotated[str, typer.Argument(help="IPv4/IPv6 address")]) -> None:
    _not_implemented("ip", target)