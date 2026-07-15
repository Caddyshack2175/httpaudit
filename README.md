# httpaudit

**An HTTP security testing toolkit for security professionals — built to turn raw testing into client-ready findings.**

> ⚠️ **For use against systems you own or have written authorisation to test.** Unauthorised testing of systems you do not control is illegal in most jurisdictions.

httpaudit is a single Go binary covering the HTTP-layer checks that come up on most web and API engagements — security headers, clickjacking, fuzzing, rate-limit behaviour, artifact discovery, and Nuclei scanning — with a consistent JSON reporting format across all of them, and a feedback loop that turns findings back into reusable templates.

---

## Install

```bash
git clone https://github.com/Caddyshack2175/httpaudit.git
cd httpaudit/
go mod tidy
go build
./httpaudit --help
```

Global flags apply to every command: `--proxy` (route through Burp/ZAP), `--timeout`, `--verbose`, `--quiet`.

External dependencies: `framer` uses `wkhtmltoimage` for screenshots; `nuclei` wraps the Nuclei scanner.

---

## The reporting loop

The commands are designed to feed each other, not just run in isolation:

```bash
# 1. Scan with Nuclei templates, emit a structured JSON report
httpaudit nuclei --urls targets.txt --templates ./templates/ \
  --severity high,critical --report-json findings.json

# 2. Fold a finding's metadata back into the template that found it
httpaudit enhance-template --report findings.json \
  --name "Exposed .git directory" --template exposed-git.yaml
```

`nuclei` runs Nuclei's template engine but converts the output into httpaudit's own report format (with severity/tag filtering and response truncation for readable reports). `enhance-template` then reads that report and writes enhanced reporting metadata into a template — so the findings from one engagement improve the templates you carry into the next.

---

## Commands

### Header & clickjacking checks

```bash
# Security headers (accepts a request template, or URLs)
httpaudit headers --url https://example.com

# Clickjacking: checks X-Frame-Options and CSP, screenshots ONLY the vulnerable hosts
httpaudit framer --urls targets.txt -s -o screenshots/

# Authenticated pages, through Burp
httpaudit framer --urls targets.txt -s -H "Cookie: session=abc123" --proxy http://127.0.0.1:8080
```

`framer` only generates a screenshot when a host actually lacks framing protection — so the output directory *is* the evidence set, with no manual triage.

### Fuzzing

```bash
# Placeholder replacement from wordlists and numeric ranges (with zero-padding)
httpaudit fuzzer --request template.txt --USER users.txt --ID 1-1000 --threads 10

# Zero-padded IDs, filtered to interesting responses
httpaudit fuzzer --request template.txt --DOCID 0001-9999 --threads 20 --filter-status 200

# Match / negative-match on response content
httpaudit fuzzer --request template.txt --ID 1-100 --negative-match "404 Not Found"
```

Filtering works on status (`--filter-status`), response substring (`--match` / `--negative-match`), and rate (`--rate-limit total,concurrent`).

### Rate-limit testing

```bash
# Controlled concurrent requests to characterise an API's rate limiting
httpaudit rate-limiter --request req.txt --total 150 --concurrent 10

# Through a proxy, with a per-request delay
httpaudit rate-limiter --request req.txt --total 100 --concurrent 5 --delay 100 --proxy http://127.0.0.1:8080
```

### Staggered fuzzing

When a target has defences you don't want to trip, `stagger` is `fuzzer` with batching and cooldowns:

```bash
# Batches of 50, ten-minute cooldown between them
httpaudit stagger --request template.txt --USER users.txt -B 50 -C 10m

# Short batches, 30-second cooldown
httpaudit stagger --request template.txt --DOCID 0001-9999 -B 25 -C 30s
```

Cooldowns accept Go duration strings (`30s`, `5m`, `1h`). Same matching and filtering flags as `fuzzer`.

### Artifact discovery

```bash
# Walk a local source tree, generate the URIs those files would live at on a target
httpaudit uri-gen --directory /var/www/html --base-url https://example.com --output uris.txt
```

`uri-gen` turns a directory structure into a URL list — useful for finding config files, leftover source, and other exposed development artifacts that shipped to production.

---

## Command reference

| Command | Purpose | Required flags |
|---|---|---|
| `nuclei` | Run Nuclei templates, output httpaudit JSON report | `--report-json` |
| `enhance-template` | Write report metadata back into a Nuclei template | `--report`, `--name`, `--template` |
| `headers` | Check security headers (URL or fuzzer mode) | `--url`/`--urls` or `--request` |
| `framer` | Clickjacking check, screenshots vulnerable hosts | `--url`/`--urls` |
| `fuzzer` | Placeholder fuzzing with filtering | `--request` |
| `stagger` | Batched fuzzing with cooldowns | `--request` |
| `rate-limiter` | Concurrency-controlled rate-limit testing | `--request`, `--total`, `--concurrent` |
| `uri-gen` | Generate URIs from a directory tree | `--directory`, `--base-url` |

Run `httpaudit <command> --help` for full flags.

---

## Why

Most HTTP-layer testing produces raw output that still needs hours of turning into something a client can read. httpaudit exists to close that gap: consistent JSON reporting across every check, screenshots captured only where they're evidence of a finding, and a loop that feeds findings back into the templates. It started as a handful of scripts written mid-engagement and grew into the toolkit I wanted to reach for.

---

## Project layout

```
cmd/    — command definitions (Cobra)
pkg/    — request handling, reporting, and per-check logic
main.go — entrypoint
```

## Contributing

Issues and pull requests welcome.

## License

MIT
