# TRACE-X

**Terminal OSINT & Exposure Intelligence Framework**

> Status: early development (v0.0.4) - core architecture in place, target modules (email/username/domain/ip) not yet implemented

TRACE-X analyzes emails, usernames, domains, and IPs using information you are
authorized to access or that is available through public/legal sources. It is
**not** a system for storing or distributing stolen credentials or leak dumps

Every finding is a tagged with its source, a confidence level, and a timestamp
TRACE-X reports evidence, it never asserts identity ("this email blongs to X")

## Features

**Implemented**
- CLI Skeleton ('tracex email|username|domain|ip <target>')
- 'Target' model - validates and normalizes email/domain/IP/username input
- 'Entity', 'Finding', 'SourceResult', data models (source + confidence + timestamp on everything)
- Explicit source status states: `FOUND`, `NOT_FOUND`, `UNKNOWN`, `TIMEOUT`, `RATE_LIMITED`, `AUTH_REQUIRED`, `SOURCE_ERROR`
  (an HTTP 404 is not the same as "definitely doesn't exist" — TRACE-X keeps these apart)
- `SourceAdapter` interface — every data source implements `query()` → `normalize()` → `SourceResult`
- Async engine — runs all applicable sources concurrently, one failing source never blocks the others
- Rich-based stderr logging helper (`setup_logging`)

**Not yet implemented** (all four target commands currently print "Not implemented yet"):
- Email analysis (DNS, MX, SPF, DMARC, DKIM)
- Domain analysis (DNS records, certificate transparency)
- Username discovery (GitHub, GitLab, Reddit, etc.)
- IP analysis (reverse DNS, ASN, reputation signals)
- Exposure/breach metadata lookup
- Correlation engine, investigation sessions, JSON/HTML reports

See [Roadmap](#roadmap).

## Architecture