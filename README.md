# TRACE-X

**Terminal OSINT & Exposure Intelligence Framework**

> Status: early development (v0.5.1+) — email, domain, IP, and username analysis modules complete with SQLite caching. Correlation engine, investigation pipeline, and exposure/breach lookup not yet implemented.

TRACE-X analyzes emails, usernames, domains, and IPs using information you are
authorized to access or that is available through public/legal sources. It is
**not** a system for storing or distributing stolen credentials or leak dumps.

Every finding is tagged with its source, a confidence level, and a timestamp —
TRACE-X reports evidence, it never asserts identity ("this email belongs to X").

## Features

**Implemented**
- `tracex email <target>` — format/local-part validation, domain + MX check, SPF/DMARC/DKIM detection
- `tracex domain <target>` — DNS records, SPF/DMARC, subdomain discovery via certificate transparency (crt.sh)
- `tracex ip <target>` — reverse DNS (PTR), ASN/org lookup, rough geolocation
- `tracex username <target>` — GitHub, GitLab, and Reddit profile discovery
- `--json` on every command for machine-readable output
- CLI global options: `--verbose`, `--quiet`, `--timeout`, `--no-cache`
- SQLite-backed TTL cache — repeated lookups skip the network (per-source TTLs: DNS 5min, profiles/subdomains 30min)
- `Target` model — validates and normalizes email/domain/IP/username input, with type auto-detection
- `Entity`, `Finding`, `SourceResult` data models (source + confidence + timestamp on everything)
- Explicit source status states: `FOUND`, `NOT_FOUND`, `UNKNOWN`, `TIMEOUT`, `RATE_LIMITED`, `AUTH_REQUIRED`, `SOURCE_ERROR`
  (an HTTP 404 is not the same as "definitely doesn't exist" — TRACE-X keeps these apart)
- `SourceAdapter` interface — every data source implements `query()` → `normalize()` → `SourceResult`
- Async engine — runs all applicable sources concurrently, one failing source never blocks the others
- Rich-based stderr logging (`--verbose`/`--quiet`)

**Not yet implemented**
- `tracex investigate <target>` — auto-detect target type and run the full pipeline
- Correlation engine — linking discovered entities into evidence-backed relationships
- `tracex exposure <target>` — breach/exposure metadata lookup (legal/public sources only, no raw dumps)
- Investigation sessions (`--save case-001`, `tracex session list/open`)
- Reports (`tracex report` → HTML/JSON/TXT)
- `~/.config/tracex/config.toml` configuration support

See [Roadmap](#roadmap).

## Architecture

TraceX is organized around a modular, source-driven architecture. Each OSINT source is isolated behind a common adapter interface, while the core engine handles target normalization, concurrent execution, result aggregation, and error handling.

```text
tracex/
├── src/
│   └── tracex/
│       ├── cli.py
│       │   └── Typer CLI entrypoint
│       │
│       ├── core/
│       │   ├── target.py
│       │   │   └── Target + TargetType — input validation & normalization
│       │   ├── entity.py
│       │   │   └── Entity — discovered OSINT entity
│       │   ├── finding.py
│       │   │   └── Finding — observation tied to a source
│       │   ├── result.py
│       │   │   └── SourceResult — adapter execution result
│       │   ├── status.py
│       │   │   └── SourceStatus — source execution status
│       │   ├── confidence.py
│       │   │   └── Confidence — finding confidence level
│       │   ├── source.py
│       │   │   └── SourceAdapter — abstract source interface
│       │   ├── engine.py
│       │   │   └── run_sources() — concurrent source execution
│       │   ├── errors.py
│       │   │   └── SourceError / NXDomainError
│       │   └── logging.py
│       │       └── Rich stderr logging
│       │
│       ├── sources/
│       │   ├── dns.py
│       │   │   └── DNS records: A, AAAA, MX, NS, TXT, CNAME, SOA
│       │   └── mailsec.py
│       │       └── SPF / DMARC / DKIM probing
│       │
│       ├── analysis/
│       │   └── mailsec.py
│       │       └── Pure SPF / DMARC parsing & analysis
│       │
│       ├── modules/
│       │   └── email.py
│       │
```

Every data source implements the `SourceAdapter` interface
(`query()` → `normalize()` → `SourceResult`), so adding a new source later means
writing one adapter class, not touching the CLI or engine.

## Installation

Requires Python 3.12+.

```bash
git clone https://github.com/lexathegoat/tracex.git
cd tracex
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -e ".[dev]"
```

## Usage

```bash
tracex --help
tracex --version

tracex email test@example.com
tracex --verbose email test@gmail.com
tracex email test@gmail.com --json | python -m json.tool

tracex username lexathegoat       # currently: "Not implemented yet"
tracex domain example.com         # currently: "Not implemented yet"
tracex ip 8.8.8.8                 # currently: "Not implemented yet"
```
