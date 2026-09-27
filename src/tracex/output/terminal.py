from __future__ import annotations

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from tracex.core.status import SourceStatus
from tracex.modules.email import Check, EmailReport
from tracex.modules.ip import IpReport
from tracex.modules.domain import DomainReport

_MARK = {Check.OK: "[green]✓[/]", Check.FAIL: "[red]✗[/]", Check.UNKNOWN: "[yellow]?[/]"}
_STATUS_STYLE = {
    SourceStatus.FOUND: "green",
    SourceStatus.NOT_FOUND: "yellow",
    SourceStatus.UNKNOWN: "yellow",
}


def _section(title: str, rows: list[tuple[str, Check]]) -> Table:
    table = Table(show_header=False, box=None, padding=(0, 2), title=title,
                  title_justify="left", title_style="bold cyan")
    table.add_column(style="dim", min_width=12)
    table.add_column()
    for label, check in rows:
        table.add_row(label, _MARK[check])
    return table


def render_email(report: EmailReport, console: Console) -> None:
    console.print(Panel.fit("[bold]EMAIL ANALYSIS[/]", border_style="cyan"))
    console.print(f"[dim]Target[/]\n  {escape(report.target.value)}\n")

    console.print(_section("Validation", [
        ("Format", report.format),
        ("Local part", report.local_part),
        ("Domain", report.domain),
        ("MX", report.mx),
    ]))
    console.print()
    console.print(_section("Mail Security", [
        ("SPF", report.spf),
        ("DMARC", report.dmarc),
        ("DKIM", report.dkim),
    ]))
    if report.dkim is Check.UNKNOWN:
        console.print("[dim]  ? = could not be determined (DKIM selector is not publicly known)[/]")

    console.print()
    sources = Table(show_header=True, header_style="bold", box=None, padding=(0, 2),
                    title="Sources", title_justify="left", title_style="bold cyan")
    sources.add_column("Source")
    sources.add_column("Status")
    sources.add_column("Time", justify="right")
    sources.add_column("Note", style="dim")
    for r in report.results:
        style = _STATUS_STYLE.get(r.status, "red")
        sources.add_row(r.source, f"[{style}]{r.status.value}[/]", f"{r.elapsed_ms} ms",
                        escape(r.error or ""))
    console.print(sources)
    console.print(f"\n[dim]{len(report.results)} sources checked[/]")

def render_domain(report: DomainReport, console: Console) -> None:
    console.print(Panel.fit("[bold]DOMAIN ANALYSIS[/]", border_style="cyan"))
    console.print(f"[dim]Target[/]\n  {escape(report.target.value)}\n")

    console.print(_section("Validation", [
        ("Exists", report.exists),
        ("SPF", report.spf),
        ("DMARC", report.dmarc),
    ]))

    console.print()
    if report.subdomains:
        sub_table = Table(show_header=False, box=None, padding=(0, 2), title="Subdomains",
                          title_justify="left", title_style="bold cyan")
        sub_table.add_column()
        for host in report.subdomains[:25]:
            sub_table.add_row(escape(host))
        console.print(sub_table)
        if len(report.subdomains) > 25:
            console.print(f"[dim]  ... and {len(report.subdomains) - 25} more[/]")
    else:
        console.print("[dim]No subdomains observed in certificate transparency logs[/]")

    console.print()
    sources = Table(show_header=True, header_style="bold", box=None, padding=(0, 2),
                    title="Sources", title_justify="left", title_style="bold cyan")
    sources.add_column("Source")
    sources.add_column("Status")
    sources.add_column("Time", justify="right")
    sources.add_column("Note", style="dim")
    for r in report.results:
        style = _STATUS_STYLE.get(r.status, "red")
        sources.add_row(r.source, f"[{style}]{r.status.value}[/]", f"{r.elapsed_ms} ms",
                        escape(r.error or ""))
    console.print(sources)
    console.print(f"\n[dim]{len(report.results)} sources checked[/]")

def render_ip(report: IpReport, console: Console) -> None:
    console.print(Panel.fit("[bold]IP ANALYSIS[/]", border_style="cyan"))
    console.print(f"[dim]Target[/]\n  {escape(report.target.value)}\n")

    if report.reverse_dns:
        console.print(f"[dim]Reverse DNS[/]\n  {escape(', '.join(report.reverse_dns))}\n")
    else:
        console.print("[dim]Reverse DNS[/]\n  (none)\n")

    for r in report.results:
        for f in r.findings:
            console.print(f"  [cyan]{f.title}:[/] {escape(f.detail) or '-'}")

    console.print()
    sources = Table(show_header=True, header_style="bold", box=None, padding=(0, 2),
                    title="Sources", title_justify="left", title_style="bold cyan")
    sources.add_column("Source")
    sources.add_column("Status")
    sources.add_column("Time", justify="right")
    sources.add_column("Note", style="dim")
    for r in report.results:
        style = _STATUS_STYLE.get(r.status, "red")
        sources.add_row(r.source, f"[{style}]{r.status.value}[/]", f"{r.elapsed_ms} ms",
                        escape(r.error or ""))
    console.print(sources)
    console.print(f"\n[dim]{len(report.results)} sources checked[/]")