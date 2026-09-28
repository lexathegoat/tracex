# TRACE-X

**Terminal OSINT & Exposure Intelligence Framework**

> Status: early development (v0.5) — email analysis module complete; username/domain/ip modules not yet implemented.

TRACE-X analyzes emails, usernames, domains, and IPs using information you are
authorized to access or that is available through public/legal sources. It is
**not** a system for storing or distributing stolen credentials or leak dumps.

Every finding is tagged with its source, a confidence level, and a timestamp —
TRACE-X reports evidence, it never asserts identity ("this email belongs to X").

## Features

**Implemented**
- `tracex email <target>` — full email analysis:
  - format/local-part validation
  - domain existence + MX check (via DNS)
  - SPF, DMARC, and DKIM (common selectors) detection
  - Rich terminal output, plus `--json` for machine-readable output
- CLI global options: `--verbose`, `--quiet`, `--timeout`, `--no-cache`
- `Target` model — validates and normalizes email/domain/IP/username input
- `Entity`, `Finding`, `SourceResult` data models (source + confidence + timestamp on everything)
- Explicit source status states: `FOUND`, `NOT_FOUND`, `UNKNOWN`, `TIMEOUT`, `RATE_LIMITED`, `AUTH_REQUIRED`, `SOURCE_ERROR`
  (an HTTP 404 is not the same as "definitely doesn't exist" — TRACE-X keeps these apart)
- `SourceAdapter` interface — every data source implements `query()` → `normalize()` → `SourceResult`
- Async engine — runs all applicable sources concurrently, one failing source never blocks the others
- `DnsSource` and `MailSecSource` adapters (async DNS lookups, SPF/DMARC/DKIM probing)
- Rich-based stderr logging (`--verbose`/`--quiet`)

**Not yet implemented** (these commands currently print "Not implemented yet"):
- `tracex username <target>` — GitHub, GitLab, Reddit, Dev.to, Stack Overflow discovery
- `tracex domain <target>` — DNS records, certificate transparency, subdomain discovery
- `tracex ip <target>` — reverse DNS, ASN/org lookup, reputation signals
- Exposure/breach metadata lookup (`tracex exposure <target>`)
- Correlation engine, `tracex investigate`, investigation sessions
- HTML/TXT reports, SQLite storage, caching layer

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
git clone https://github.com/<your-username>/tracex.git
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

## Email Analysis

Example output from the email analysis module:

```text
EMAIL ANALYSIS
────────────────────────────

Target
  test@example.com

Validation
  Format       ✓
  Local part   ✓
  Domain       ✓
  MX           ✓

Mail Security
  SPF          ✓
  DMARC        ✓
  DKIM         ?
  ? = could not be determined
      (DKIM selector is not publicly known)

Sources
  dns          FOUND       12 ms
  mailsec      FOUND       45 ms

2 sources checked
```

The analysis pipeline validates the target address, checks the domain's mail infrastructure, evaluates available email security records, and reports which sources contributed to the result.


## Testing

```bash
pytest
```

## Security / Privacy

- TRACE-X does not collect, store, or distribute stolen credentials or raw breach dumps.
- Passive/public sources only — no active exploitation, no credential stuffing.
- Confidence and source are always reported separately: TRACE-X never claims an
  email or username definitely belongs to a specific person.

## Roadmap

| Version | Scope |
|---|---|
| v0.0.x | Core models, adapter interface, engine, email analysis module *(current)* |
| v0.1.0 | Domain + IP modules, `cli/` package split |
| v0.2.0 | Username discovery, exposure metadata, caching |
| v0.3.0 | Investigation sessions, SQLite storage, correlation engine, HTML reports |
| v1.0.0 | Stable plugin architecture, full docs, tests, CI/CD |

## License

MIT