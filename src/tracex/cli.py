from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape

from tracex import __version__
from tracex.core.target import Target, TargetType
from tracex.modules.email import analyze_email
from tracex.output.terminal import render_email
from tracex.utils.logging import setup_logging
from tracex.modules.domain import analyze_domain
from tracex.output.terminal import render_domain

app = typer.Typer(
    name="tracex",
    help="TRACE-X: Terminal OSINT & Exposure Intelligence Framework",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err = Console(stderr=True)


@dataclass
class Settings:
    timeout: float = 10.0
    use_cache: bool = True
    quiet: bool = False


JsonOpt = Annotated[bool, typer.Option("--json", help="Machine-readable JSON output.")]


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"tracex {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context,
    version: Annotated[bool, typer.Option("--version", callback=_version_callback,
                                          is_eager=True, help="Show version and exit.")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Show progress logs.")] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Only show errors.")] = False,
    timeout: Annotated[float, typer.Option("--timeout", min=1, max=120,
                                           help="Per-source timeout (seconds).")] = 10.0,
    no_cache: Annotated[bool, typer.Option("--no-cache", help="Disable caching.")] = False,
) -> None:
    """TRACE-X: passive OSINT and exposure analysis for targets you are authorized to investigate."""
    setup_logging(verbose=verbose, quiet=quiet)
    ctx.obj = Settings(timeout=timeout, use_cache=not no_cache, quiet=quiet)


def _parse_or_exit(type_: TargetType, raw: str) -> Target:
    try:
        return Target.parse(type_, raw)
    except ValueError as exc:
        err.print(f"[red]Error:[/] {escape(str(exc))}")
        raise typer.Exit(code=2) from exc


def _not_implemented(module: str, target: str) -> None:
    err.print(f"[yellow]Not implemented yet:[/] {module} ({escape(target)})")
    raise typer.Exit(code=1)


@app.command()
def email(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Email address")],
    json_out: JsonOpt = False,
) -> None:
    """Analyze an email address (syntax, DNS, MX, SPF, DMARC, DKIM)."""
    settings: Settings = ctx.obj
    parsed = _parse_or_exit(TargetType.EMAIL, target)
    report = asyncio.run(analyze_email(parsed, timeout=settings.timeout))
    if json_out:
        typer.echo(report.to_json())
    else:
        render_email(report, console)


@app.command()
def username(target: Annotated[str, typer.Argument(help="Username")]) -> None:
    """Look up a username on public sources."""
    _not_implemented("username", target)


# @app.command()
# def domain(target: Annotated[str, typer.Argument(help="Domain name")]) -> None:
#     """Analyze a domain."""
#     _not_implemented("domain", target)


@app.command()
def ip(target: Annotated[str, typer.Argument(help="IPv4/IPv6 address")]) -> None:
    """Analyze an IP address."""
    _not_implemented("ip", target)

@app.command()
def domain(
    ctx: typer.Context,
    target: Annotated[str, typer.Argument(help="Domain name")],
    json_out: JsonOpt = False,
) -> None:
    """Analyze a domain (DNS, SPF/DMARC, subdomains via certificate transparency)."""
    settings: Settings = ctx.obj
    parsed = _parse_or_exit(TargetType.DOMAIN, target)
    report = asyncio.run(analyze_domain(parsed, timeout=settings.timeout))
    if json_out:
        typer.echo(report.to_json())
    else:
        render_domain(report, console)