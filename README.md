# HashCrack

AI-powered hash cracking platform with adaptive profiling, OSINT automation, multi-phase attack orchestration, and professional security audit reports.

[![CI](https://github.com/thesamgodson/HashCrack/actions/workflows/ci.yml/badge.svg)](https://github.com/thesamgodson/HashCrack/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **Smart attack orchestration** -- chains Dictionary, Rules, Profile, Hybrid, and Adaptive AI phases automatically
- **Adaptive AI profiling** -- multi-round LLM reasoning that adapts strategy based on failed attempts, with chain-of-thought reasoning visible in the TUI
- **OSINT automation** -- give a username, automatically enumerate platforms and build a target profile
- **Batch processing** -- crack thousands of hashes with deduplication and auto-type detection
- **Security audit reports** -- professional Markdown/HTML reports with entropy analysis, pattern detection, and policy compliance
- **Real hash support** -- MD5, SHA1, SHA256, SHA384, SHA512, bcrypt, argon2, NTLM
- **Plugin architecture** -- hashcat `.rule` file compatibility, extensible via entry points
- **Rule engine** -- 22 hashcat-compatible mutation rules (leet, case, append, rotate, etc.)
- **Parallel cracking** -- multi-core hash verification with adaptive batch sizing for slow hashes
- **Interactive TUI** -- real-time dashboard with AI reasoning display, phase tracking, progress bars
- **Session persistence** -- save and resume cracking sessions

## Architecture

```
CLI Input --> Hash ID --> Plan Attacks --> Orchestrator
                                           |-> Dictionary
                                           |-> Dictionary + Rules
                                           |-> Profile (Local/AI)
                                           |-> Profile + Rules
                                           |-> Adaptive AI (multi-round)
                                         --> Cracker (parallel/sequential)
                                         --> Analysis --> Audit Report
```

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Quick Start

### Smart attack with AI profiling

```bash
hashcrack smart -H "5d41402abc4b2a76b9719d911017c592" \
  --profile-name John \
  --profile-birthdate 1990-05-15 \
  --profile-pet Buddy
```

### OSINT-powered attack (one command does everything)

```bash
hashcrack smart -H <hash> --osint-target @johndoe
```

### Batch crack from file

```bash
hashcrack batch -f hashes.txt --audit
```

### Identify hash type

```bash
hashcrack identify -H <hash>
```

### OSINT username enumeration

```bash
hashcrack osint johndoe
```

### Interactive TUI

```bash
hashcrack smart -H <hash> --tui
```

### List plugins

```bash
hashcrack plugins
```

## Commands

| Command | Description |
|---------|-------------|
| `crack` | Simple dictionary attack |
| `smart` | Multi-phase intelligent attack with AI profiling |
| `batch` | Crack multiple hashes from a file |
| `identify` | Identify hash type(s) |
| `osint` | OSINT username enumeration |
| `plugins` | List installed plugins |
| `version` | Show version |

## Attack Phases

| Phase | Description |
|-------|-------------|
| 1. Dictionary | Plain wordlist candidates |
| 2. Dictionary + Rules | Wordlist with hashcat-compatible mutations |
| 3. Profile | AI or rule-based candidates from target info |
| 4. Profile + Rules | Profiled candidates with mutations |
| 5. Adaptive AI | Multi-round LLM reasoning that adapts on failure |

Phases run in order; stops on first match.

## Configuration

Copy `.env.example` to `.env` and fill in your LLM endpoint details.

| Variable | Description | Default |
|----------|-------------|---------|
| `HASHCRACK_LLM_BASE_URL` | OpenAI-compatible API base URL | -- |
| `HASHCRACK_LLM_API_KEY` | API bearer token | -- |
| `HASHCRACK_LLM_MODEL` | Model name | -- |
| `HASHCRACK_LLM_TIMEOUT` | Request timeout (seconds) | 90 |

## Development

```bash
pytest                          # run tests (293 passing)
pytest --cov=src               # with coverage
ruff check src/ tests/         # lint
mypy src/                      # type check
```

## Project Structure

```
src/hashcrack/
  cli.py              -- Typer CLI (crack, smart, batch, identify, osint, plugins)
  orchestrator.py      -- Smart attack phase chaining
  adaptive_profiler.py -- Multi-round AI profiling with chain-of-thought
  profiler.py          -- LocalProfiler (rules) + AIProfiler (LLM)
  cracker.py           -- Parallel + sequential cracking engines
  analysis.py          -- Password entropy, patterns, audit summaries
  batch.py             -- Batch hash processing with dedup
  hash_id.py           -- Hash type auto-identification
  hashers.py           -- Hash computation (MD5-SHA512 + bcrypt/argon2/NTLM)
  rules.py             -- Hashcat-compatible mutation rules
  models.py            -- Core dataclasses and enums
  config.py            -- Environment variable loading
  session.py           -- Session save/resume (JSON)
  report.py            -- Report generation (Markdown/JSON/HTML)
  wordlist.py          -- Wordlist I/O and streaming
  plugins/             -- Plugin architecture (entry_points, rule parser)
  osint/               -- OSINT username enumeration + profile builder
  tui/                 -- Textual interactive dashboard
  data/100K.txt        -- Bundled 100K password wordlist
```

## License

MIT
