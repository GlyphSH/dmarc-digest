# dmarc-digest

[![CI](https://github.com/GlyphSH/dmarc-digest/actions/workflows/ci.yml/badge.svg)](https://github.com/GlyphSH/dmarc-digest/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/GlyphSH/dmarc-digest.svg)](https://pkg.go.dev/github.com/GlyphSH/dmarc-digest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Turn unreadable DMARC aggregate (RUA) XML reports into a digest a human can act on:
**who sends as your domain, who is spoofing it, and what to fix.**

Mailbox providers email these reports to the `rua=` address in your DMARC record as
`.xml`, `.xml.gz`, or `.zip` attachments. Almost nobody reads them - which means almost
nobody notices spoofing attempts or misconfigured senders. `dmarc-digest` reads them
for you. Zero dependencies, single static binary.

## Demo

```
$ dmarc-digest reports/            # or: dmarc-digest google.xml yahoo.xml.gz outlook.zip

3 report(s) · example.com · 2026-05-01 → 2026-05-03 · 514 messages

SOURCE         PTR                      MSGS  SPF   DKIM  DMARC  VERDICT
209.85.220.41  mail-sor-f41.google.com  412   pass  pass  pass   ok
167.89.12.7    o1.sendgrid.net          52    fail  fail  FAIL   third-party: passes SPF for sendgrid.net, DKIM for sendgrid.net (unaligned)
185.243.57.99  -                        37    fail  fail  FAIL   suspected-spoofing: no valid SPF or DKIM
40.92.18.21    ...outlook.com           13    pass  pass  pass   ok

WHAT TO DO
 ✗ 37 message(s) from 1 source(s) had no valid authentication - likely spoofing of
   example.com. example.com publishes p=none, so receivers delivered these anyway;
   consider p=quarantine.
 ⚠ 52 message(s) authenticate but are not aligned (passes SPF for sendgrid.net, DKIM
   for sendgrid.net (unaligned)). If these are your senders, set up a custom
   return-path and DKIM signing for your domain.
 ✓ 425 of 514 messages (83%) fully authenticated.
```

## Install

```sh
go install github.com/GlyphSH/dmarc-digest@latest
```

Or clone and `go build` - there are no dependencies beyond the Go standard library.

## Usage

```
dmarc-digest [flags] <report.xml | report.xml.gz | report.zip | dir> ...

  -json      emit the summary as JSON (for pipelines)
  -no-dns    skip reverse-DNS lookups of source IPs
  -version   print version and exit
```

Pass any mix of files and directories; a directory is scanned for `.xml`,
`.xml.gz`, and `.zip` reports. Reports from multiple providers and days are
merged into one digest per run.

### Exit codes (CI / cron friendly)

| Code | Meaning |
|------|---------|
| 0    | every source fully authenticated |
| 1    | alignment problems only (likely misconfigured legit senders) |
| 2    | suspected spoofing seen, or a report failed to parse |

A nightly cron like `dmarc-digest /var/dmarc/today/ -json | jq` plus an alert on
non-zero exit is all most domains need.

## How verdicts work

DMARC's `policy_evaluated` results are *alignment* results - SPF/DKIM must pass
**and** match the From: domain. `dmarc-digest` uses the raw `auth_results` to
separate two very different failure modes:

- **third-party** - SPF or DKIM passes, but for another domain (e.g. `sendgrid.net`).
  Usually a legit SaaS sender that needs a custom return-path / DKIM CNAMEs.
- **suspected-spoofing** - nothing valid at all. Someone else is sending as you.

## Development

```sh
go test ./...
```

Test fixtures in `internal/report/testdata/` are realistic reports in all three
wire formats (plain XML, gzip, zip).

## License

[MIT](LICENSE)
