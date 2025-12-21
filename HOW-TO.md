# SmartCrack -- How-To Guide

## Setup

### 1. Create virtual environment and install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### 2. Configure LLM (optional, enables AI profiling)

```bash
cp .env.example .env
```

Edit `.env` and fill in your LLM endpoint:

```
SMARTCRACK_LLM_BASE_URL=https://litellm.dev.bharatai.me/v1
SMARTCRACK_LLM_API_KEY=sk-ySqjC5hEgpSAy0VdvafZWA
SMARTCRACK_LLM_MODEL=qwen35b-opus
SMARTCRACK_LLM_TIMEOUT=90
```

Then load it into your shell:

```bash
export $(grep -v '^#' .env | xargs)
```

Or add the exports to your `.zshrc` / `.bashrc` for persistence.

**Available models on the team LiteLLM endpoint:**

| Model | Size | Best for | Speed |
|-------|------|----------|-------|
| `llama-8b-baseline` | 8B | Simple tasks, fast profiling | Fast |
| `devstral-24b-coder` | 24B | Code-heavy passwords | Medium |
| `qwen35b-opus` | 35B MoE | Reasoning, analysis | Medium |
| `nemotron-70b` | 70B | Complex reasoning | Slower |
| `qwen122b-power` | 122B MoE | Highest quality | Slowest |

For password profiling, `llama-8b-baseline` is the most reliable (fast, doesn't refuse). `qwen35b-opus` gives better quality but occasionally 504s under load.

---

## Commands

### Identify a hash type

```bash
smartcrack identify -H "5d41402abc4b2a76b9719d911017c592"
```

Output tells you the algorithm (MD5, SHA1, SHA256, etc.) with confidence scores.

### Basic dictionary crack

```bash
smartcrack crack -H "5d41402abc4b2a76b9719d911017c592"
```

Uses the bundled 100K wordlist. Specify your own with `-w`:

```bash
smartcrack crack -H "5d41402abc4b2a76b9719d911017c592" -w /path/to/rockyou.txt
```

### Smart crack (multi-phase, recommended)

This chains 4 attack phases automatically: Dictionary, Rules, Profile, Hybrid.

```bash
smartcrack smart -H "5d41402abc4b2a76b9719d911017c592"
```

#### With target profile (local rule-based)

```bash
smartcrack smart -H "5d41402abc4b2a76b9719d911017c592" \
  --profile-name John \
  --profile-lastname Smith \
  --profile-nickname Johnny \
  --profile-birthdate 1990-05-15 \
  --profile-pet Buddy \
  --profile-partner Jane \
  --profile-partner-birthdate 1992-08-20 \
  --profile-child Emma \
  --profile-keywords "arsenal,london,guitar" \
  --profile-numbers "42,007,1234"
```

#### With AI profiling (requires LLM config)

Same as above -- if `SMARTCRACK_LLM_BASE_URL` and `SMARTCRACK_LLM_API_KEY` are set, the AI profiler activates automatically in the Profile phase. No extra flags needed.

You can also pass the LLM config inline:

```bash
smartcrack smart -H "<hash>" \
  --profile-name John \
  --llm-base-url "https://litellm.dev.bharatai.me/v1" \
  --llm-model "llama-8b-baseline"
```

The API key must be set via env var `SMARTCRACK_LLM_API_KEY` (not exposed as a CLI flag for security).

#### With TUI dashboard

```bash
smartcrack smart -H "5d41402abc4b2a76b9719d911017c592" --tui
```

Interactive dashboard with real-time progress, phase tracking, and log output. Press `q` to quit.

### Options reference

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--hash` | `-H` | Hash to crack (required) | -- |
| `--wordlist` | `-w` | Wordlist file path | bundled 100K |
| `--salt` | `-s` | Salt to append to candidates | none |
| `--type` | `-t` | Hash type: auto, md5, sha1, sha256, sha384, sha512 | auto |
| `--rules` | `-r` | Rules preset: none, quick, thorough | quick |
| `--workers` | | Parallel worker count | CPU count |
| `--profile-name` | | Target first name | |
| `--profile-lastname` | | Target last name | |
| `--profile-nickname` | | Target nickname | |
| `--profile-birthdate` | | Birthdate (YYYY-MM-DD) | |
| `--profile-partner` | | Partner name | |
| `--profile-partner-birthdate` | | Partner birthdate (YYYY-MM-DD) | |
| `--profile-child` | | Child name | |
| `--profile-pet` | | Pet name | |
| `--profile-keywords` | | Comma-separated keywords | |
| `--profile-numbers` | | Comma-separated special numbers | |
| `--llm-base-url` | | LLM API base URL | env var |
| `--llm-model` | | LLM model name | env var |
| `--tui` | | Launch interactive TUI | false |

---

## Attack Phases (smart mode)

| Phase | What it does |
|-------|-------------|
| 1. Dictionary | Tries every word in the wordlist as-is |
| 2. Dictionary + Rules | Applies hashcat-style mutations (leet, case, append 123, etc.) to each word |
| 3. Profile | Generates candidates from target info -- AI profiler if LLM configured, otherwise local rule-based |
| 4. Profile + Rules | Takes profiled candidates and applies mutations on top |

Stops on first match. If all 4 phases fail, try a larger wordlist (rockyou.txt) or `--rules thorough`.

---

## Creating test hashes

Quick way to generate test hashes for experimenting:

```bash
# MD5
echo -n "password123" | md5

# SHA256
echo -n "password123" | shasum -a 256 | cut -d' ' -f1

# In Python
python3 -c "import hashlib; print(hashlib.md5(b'Johnny1990').hexdigest())"
```

---

## Development

```bash
# Run tests
pytest

# Run tests with coverage
pytest --cov=src --cov-report=term-missing

# Lint
ruff check src/ tests/

# Type check
mypy src/

# Format
black src/ tests/
isort src/ tests/
```

### Project structure

```
src/smartcrack/
  cli.py          -- Typer CLI (crack, identify, smart, version)
  orchestrator.py -- Smart attack phase chaining
  profiler.py     -- LocalProfiler (rules) + AIProfiler (LLM)
  cracker.py      -- Parallel + sequential cracking engines
  hash_id.py      -- Hash type auto-identification
  hashers.py      -- Hash computation and verification
  rules.py        -- Hashcat-compatible mutation rules
  models.py       -- Core dataclasses and enums
  config.py       -- Environment variable loading
  session.py      -- Session save/resume (JSON)
  report.py       -- Report generation (Markdown/JSON)
  wordlist.py     -- Wordlist I/O and streaming
  tui/            -- Textual interactive dashboard
  data/100K.txt   -- Bundled 100K password wordlist
```

---

## Troubleshooting

**AI profiler returns 0 candidates**
- Check that `SMARTCRACK_LLM_API_KEY` is set: `echo $SMARTCRACK_LLM_API_KEY`
- Test the endpoint directly: `curl $SMARTCRACK_LLM_BASE_URL/chat/completions -H "Authorization: Bearer $SMARTCRACK_LLM_API_KEY" -H "Content-Type: application/json" -d '{"model":"llama-8b-baseline","messages":[{"role":"user","content":"hello"}]}'`
- If you get 504 errors, the model may be restarting -- wait 30s and retry
- Try `llama-8b-baseline` instead of `qwen35b-opus` (more reliable, faster)

**"Not found" on a hash you know is in the wordlist**
- Check hash type detection: `smartcrack identify -H "<hash>"`
- Force the type if auto-detect is wrong: `--type md5`
- If using a salt, pass it with `--salt`

**TUI not rendering properly**
- Requires a terminal with 256-color support
- Minimum terminal size ~80x24
- Press `q` to quit cleanly
