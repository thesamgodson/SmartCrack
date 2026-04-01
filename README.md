# SmartCrack

AI-powered hash cracking platform with cultural knowledge expansion, 42 hash algorithms, exhaustive candidate generation, and professional security audit reports.

[![CI](https://github.com/thesamgodson/SmartCrack/actions/workflows/ci.yml/badge.svg)](https://github.com/thesamgodson/SmartCrack/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Hash Types](https://img.shields.io/badge/hash_types-42-green.svg)](#supported-algorithms)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## What Makes It Different

SmartCrack uses a single LLM call to extract **cultural knowledge** from a target profile — second-order associations that no wordlist contains. Tell it someone likes Arsenal and it knows Bergkamp wore #10, Highbury was the old stadium, and "COYG" is the fan chant. Then a mechanical engine exhaustively generates **82M+ candidates** from those tokens in seconds.

```bash
# Cracks "Bergkamp10!" — only possible if you know Arsenal's squad
smartcrack smart -H 5e30d55e3d9e5c84d08d2b40db4de72f \
  --profile-name Johnny --profile-keywords "arsenal,football" \
  --profile-birthdate 1990-01-15 --expand
```

## Features

- **Knowledge expansion** — one Gemini/OpenAI call extracts 300+ cultural tokens, cached to disk
- **Exhaustive combo engine** — 15-phase generation: every token × number × separator × suffix × leet variant × reversal × case variant. 82M candidates in 40s
- **42 hash algorithms** — Linux shadow ($1$/$5$/$6$/$y$), WordPress, Drupal, Django, MySQL, MSSQL, bcrypt, Argon2, NTLM, Kerberos, NetNTLMv2, DCC2, WPA2, KeePass, Office docs, and more
- **Prefix-based auto-detection** — 24 structural patterns for instant identification
- **Adaptive batch sizing** — memory-hard hashes get 50/batch with 2 workers; fast hashes get 50K/batch with all cores
- **Rainbow tables** — build and lookup with O(log n) binary search
- **HIBP breach checking** — k-anonymity API integration
- **Hashcat compatibility** — 38 mode mappings, .rule files, potfile parsing
- **OSINT automation** — username enumeration → automatic profile building
- **Export reports** — CSV, HTML dashboard (Chart.js), Markdown
- **Interactive TUI** — real-time dashboard with phase tracking
- **Session persistence** — save and resume cracking sessions

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Quick Start

```bash
# Basic crack (auto-detects hash type)
smartcrack smart -H "5f4dcc3b5aa765d61d8327deb882cf99"

# With target profile
smartcrack smart -H <hash> \
  --profile-name John --profile-pet Buddy \
  --profile-keywords "arsenal,gaming" --profile-birthdate 1990-05-15

# With LLM knowledge expansion (the killer feature)
export SMARTCRACK_API_KEY="your-gemini-key"
export SMARTCRACK_PROVIDER="gemini"
smartcrack smart -H <hash> --profile-name John --profile-keywords "arsenal" --expand

# Crack a WordPress hash
smartcrack smart -H '$P$B9xv18PXFDqXIrNOiRkHpNdyInuUbi1' --type wordpress

# Crack a Linux shadow hash
smartcrack smart -H '$6$rounds=5000$salt$hash' --type sha512crypt

# Hashcat mode compatibility
smartcrack smart -H <hash> -m 1000  # NTLM mode

# Batch crack with audit report
smartcrack batch -f hashes.txt --audit --report html --report-output report.html

# Rainbow table
smartcrack rainbow build -w wordlist.txt -t md5 -o table.rainbow
smartcrack rainbow lookup -H <hash> -T table.rainbow

# System check
smartcrack doctor
```

## Supported Algorithms

| Category | Types |
|----------|-------|
| **Fast** | MD5, SHA1, SHA224, SHA256, SHA384, SHA512, NTLM, LM |
| **Linux** | md5crypt ($1$), sha256crypt ($5$), sha512crypt ($6$), yescrypt ($y$) |
| **Web CMS** | WordPress/phpBB ($P$/$H$), Drupal7 ($S$) |
| **Windows AD** | NTLM, NetNTLMv1/v2, Kerberos TGS/ASREP, DCC1/DCC2, LM |
| **Databases** | MySQL 4.1, MSSQL 2012, Oracle 11g/12c, PostgreSQL md5/SCRAM |
| **Frameworks** | Django PBKDF2, bcrypt, Argon2, scrypt |
| **Files** | KeePass, MS Office, PDF, RAR5, 7-Zip |
| **Crypto** | Bitcoin, Ethereum |
| **Network** | WPA2 PMKID, Cisco type 8/9 |
| **Other** | macOS PBKDF2, LDAP SSHA |

## LLM Configuration

```bash
# Gemini (recommended — free tier)
export SMARTCRACK_API_KEY="AIza..."
export SMARTCRACK_PROVIDER="gemini"

# OpenAI
export SMARTCRACK_API_KEY="sk-..."
export SMARTCRACK_PROVIDER="openai"

# Auto-detect from key prefix (no --provider needed)
export SMARTCRACK_API_KEY="AIza..."  # auto-detects Gemini
```

Supported providers: `gemini`, `openai`, `groq`, `together`, `openrouter`. Any OpenAI-compatible endpoint works via `--llm-base-url`.

## Commands

| Command | Description |
|---------|-------------|
| `smart` | Multi-phase intelligent attack with knowledge expansion |
| `crack` | Simple dictionary attack |
| `batch` | Crack multiple hashes from a file |
| `identify` | Identify hash type(s) |
| `estimate` | Pre-attack probability and time estimate |
| `export` | Export results as CSV, HTML, or Markdown |
| `analyze` | Analyze passwords from a hashcat potfile |
| `rainbow build` | Build a rainbow table from a wordlist |
| `rainbow lookup` | Look up a hash in a rainbow table |
| `doctor` | Check system readiness |
| `quickstart` | Interactive first-time wizard |
| `osint` | OSINT username enumeration |
| `plugins` | List installed plugins |
| `version` | Show version |

## Development

```bash
pytest                          # 559 tests
pytest --cov=src               # with coverage
ruff check src/ tests/         # lint
```

## License

MIT
