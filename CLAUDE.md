# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A Python log analyzer that parses authentication logs (`/var/log/auth.log`) and web server logs (Apache/Nginx access logs) to detect suspicious activity — primarily failed SSH logins, brute force attempts, and anomalous request patterns. No third-party dependencies; standard library only.

## Running the Project

```bash
# Analyze a log file
python main.py --file /var/log/auth.log --type auth

# Run all tests
python -m unittest discover -s tests

# Run a single test module
python -m unittest tests.test_parsers

# Run a single test case
python -m unittest tests.test_parsers.TestAuthParser.test_failed_ssh
```

## Architecture

The project follows a pipeline pattern: **parse → detect → report**.

- `parsers/` — Log format parsers. Each parser ingests raw log lines and yields structured `LogEntry` objects. One parser per log type (e.g., `auth_parser.py`, `web_parser.py`).
- `detectors/` — Stateful detection rules that consume `LogEntry` streams and emit `Alert` objects. Detectors are composable and should not depend on each other.
- `reporters/` — Format and output `Alert` objects (console, JSON, etc.).
- `models.py` — Shared dataclasses: `LogEntry`, `Alert`. Keep this free of business logic.
- `main.py` — CLI entry point. Wires parsers → detectors → reporters together.

## Coding Standards

- **Python 3.10+** — use `match/case`, `dataclasses`, `pathlib`, and `datetime` from the standard library.
- All parsers must accept a file path or an iterable of strings (for testability without real log files).
- Regex patterns should be compiled once at module level, not inside loops.
- Detection thresholds (e.g., max failed logins before alert) belong in a `config.py` as named constants, not hardcoded inline.
- Parsers should skip malformed lines with a logged warning rather than raising exceptions.

## Key Conventions

- `LogEntry` and `Alert` are immutable `dataclasses(frozen=True)`.
- Timestamps are always stored as `datetime` objects in UTC, converted at parse time.
- Detectors track state internally (e.g., per-IP counters) using plain dicts — no global state.
- Test data lives in `tests/fixtures/` as real-format sample log snippets, one file per log type.
