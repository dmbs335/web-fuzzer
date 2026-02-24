# web-fuzzer

A grammar-based, coverage-guided web fuzzing framework with built-in differential testing, domain-specific oracles, and persistent execution mode.

Designed for discovering parser differentials, SSRF bypasses, and sanitizer evasions across multiple target implementations.

## Key Features

- **Grammar-Based Input Generation** — Custom DSL for defining input grammars (URI, HTML, JSON, CSP, Cookie, ECMAScript, multipart)
- **Differential Fuzzing** — Compare outputs across multiple target implementations to find behavioral divergences
- **Domain-Specific Oracles** — Crash, SSRF (URL confusion), XSS, mXSS, sanitizer bypass, and response anomaly detection
- **Coverage-Guided Mutation** — AFL-style edge coverage + behavioral divergence tracking (Nezha-inspired)
- **Persistent Execution** — Length-prefixed binary protocol for ~50x speedup over process-per-execution
- **Pluggable Architecture** — Protocol-based interfaces for targets, mutators, schedulers, coverage collectors, and oracles
- **Seed Corpus** — File-based seed loading with curated seed sets for URL and XSS fuzzing

## Quick Start

### Prerequisites

- Python 3.10+
- (Optional) Node.js 18+ — for JavaScript-based targets (DOMPurify, WHATWG URL, etc.)
- (Optional) Java, Go, Rust, PHP, .NET — for language-specific URL parser targets
- (Optional) Redis — for [fuzzer-orchestrator](../fuzzer-orchestrator) integration

### Installation

```bash
cd web-fuzzer
pip install -e .
```

### Basic Usage

```bash
# Generate inputs from a grammar
webfuzzer generate --grammar json --count 10

# Fuzz a single target
webfuzzer fuzz --grammar json --target-cmd "python targets/json_strict.py {input}"

# Differential fuzzing (compare two JSON parsers)
webfuzzer fuzz --grammar json \
  --target-cmd "python targets/json_strict.py {input}" \
  --diff-cmd "python targets/json_json5.py {input}" \
  --oracle crash

# URL parser differential fuzzing (9 parsers, persistent mode)
webfuzzer fuzz --grammar uri \
  --target-cmd "python targets/url_python_urllib.py {input}" \
  --diff-cmd "python targets/url_node_whatwg.js {input}" \
  --diff-cmd "python targets/url_curl.py {input}" \
  --oracle crash,ssrf \
  --mutators grammar,havoc \
  --scheduler entropic \
  --seeds-dir targets/url_seeds \
  --persistent \
  --timeout 300 \
  --output-dir results/url_diff
```

### CLI Commands

| Command | Description |
|---------|-------------|
| `webfuzzer generate` | Generate outputs from a grammar |
| `webfuzzer fuzz` | Run the fuzzing engine |
| `webfuzzer list` | List available grammars and rules |
| `webfuzzer validate` | Validate grammar syntax |

### Fuzz Command Options

| Option | Description |
|--------|-------------|
| `--grammar NAME` | Input grammar (json, uri, html, csp, cookie, ecmascript, multipart) |
| `--target-cmd CMD` | Target command with `{input}` placeholder |
| `--diff-cmd CMD` | Reference target for differential fuzzing (repeatable) |
| `--oracle LIST` | Comma-separated oracles: crash, response, sanitizer, xss, mxss, ssrf |
| `--mutators LIST` | Comma-separated: grammar, havoc, token, splice, dictionary, mxss, structural |
| `--scheduler NAME` | Seed scheduler: random, entropic, ecofuzz, rare-branch |
| `--count N` | Max iterations (0 = unlimited) |
| `--timeout N` | Max time in seconds (0 = unlimited) |
| `--initial-seeds N` | Initial seed corpus size (default: 100) |
| `--seeds-dir DIR` | Load file-based seeds before grammar generation |
| `--persistent` | Enable persistent execution mode (~50x faster) |
| `--dict-file PATH` | Dictionary file for dictionary mutator |
| `--output-dir DIR` | Results output directory |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        FuzzEngine                               │
│                                                                 │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌────────────┐  │
│  │ Grammar  │──>│ Mutators │──>│ Targets  │──>│  Oracles   │  │
│  │ Source   │   │          │   │          │   │            │  │
│  └──────────┘   └──────────┘   └──────────┘   └────────────┘  │
│       │              │              │               │          │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌────────────┐  │
│  │  Corpus  │<──│Schedulers│<──│ Coverage │   │  Findings  │  │
│  │          │   │          │   │Collectors│   │            │  │
│  └──────────┘   └──────────┘   └──────────┘   └────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Core Loop

1. **Seed Phase** — Load file-based seeds (Phase 1), then fill with grammar-generated seeds (Phase 2)
2. **Select** — Scheduler picks a seed and a mutator
3. **Mutate** — Mutator transforms the seed input
4. **Execute** — Run against primary target (and reference targets if differential mode)
5. **Evaluate** — Coverage collector checks for novel behavior; oracles classify findings
6. **Update** — Add interesting inputs to corpus; report findings; feedback to scheduler

---

## Components

### Grammars

Custom DSL with directives, weighted productions, quantifiers, and built-in functions.

```
!root <url>
!max_depth 10

<url> = <scheme> "://" <authority> <path> <query> <fragment>
<scheme> = [weight=5] "http" | [weight=5] "https" | "ftp"
<authority> = <userinfo> <host> <port>
<host> = <int min=1 max=255> "." <int min=0 max=255> "." <int min=0 max=255> "." <int min=0 max=255>
```

**Built-in Grammars:** `uri`, `json`, `html`, `csp`, `cookie`, `ecmascript`, `multipart`

**Built-in Functions:** `<int>`, `<float>`, `<string>`, `<hex>`, `<regex>`, `<choice>`

### Mutators

| Mutator | Strategy |
|---------|----------|
| **grammar** | AST-level subtree replacement, splice, production swap (Nautilus/Superion-style) |
| **havoc** | Byte-level bit flips, insertions, deletions (AFL-style) |
| **token** | Token-aware mutations on identified delimiters |
| **splice** | Cross-seed subtree swapping |
| **dictionary** | Dictionary token insertion from wordlist |
| **mxss** | Mutation XSS-specific context encoding tricks |
| **structural** | Structure-preserving mutations on parsed output |

### Oracles

| Oracle | Detection |
|--------|-----------|
| **crash** | SIGSEGV, SIGABRT, timeouts, nonzero exits |
| **response** | Basic response validation |
| **sanitizer** | Dangerous patterns surviving sanitization (script tags, event handlers, CSS XSS) |
| **xss** | Context-aware XSS detection (script elements, event handlers, dangerous URIs) |
| **mxss** | Mutation XSS via re-parsing divergence |
| **ssrf** | URL confusion attacks — host/scheme/userinfo/port/path confusion across parser pairs |
| **differential** | Auto-enabled with `--diff-cmd`; pluggable strategies (exit code, output, semantic, timing, URL confusion, XSS bypass) |

### Coverage Collectors

| Collector | Method |
|-----------|--------|
| **ResponseCoverage** | Status code + output hash features |
| **EdgeCoverage** | AFL-style 64K edge bitmap |
| **StateCoverage** | State machine transition tracking |
| **DiffCoverage** | Per-pair behavioral divergence signatures (auto-enabled in differential mode) |

### Schedulers

| Scheduler | Algorithm |
|-----------|-----------|
| **random** | Uniform random selection |
| **entropic** | Energy-based scheduling (AFLFast-style) |
| **ecofuzz** | Ecosystem-optimized scheduling |
| **rare-branch** | Prioritizes seeds covering rare branches |

---

## Target Execution Modes

### Process Mode (default)

Spawns a new process per execution. Compatible with any command-line program.

```bash
webfuzzer fuzz --grammar json --target-cmd "python my_parser.py {input}"
```

### Persistent Mode (~50x faster)

Keeps a long-running subprocess alive and communicates via a length-prefixed binary protocol (4-byte big-endian length header on stdin/stdout).

```bash
webfuzzer fuzz --grammar uri --target-cmd "python targets/url_python_urllib.py {input}" --persistent
```

Wrappers for persistent mode:
- **Python** — `targets/persistent_wrapper.py`
- **Node.js** — `targets/persistent_wrapper.js`
- **Java** — Native `--persistent` flag

---

## Available Targets

### URL Parsers

| Target | Language | Implementation |
|--------|----------|----------------|
| `url_python_urllib.py` | Python | `urllib.parse` |
| `url_python_rfc3986.py` | Python | `rfc3986` library |
| `url_node_whatwg.js` | Node.js | WHATWG `URL` |
| `url_node_legacy.js` | Node.js | `url.parse()` |
| `url_curl.py` | Python/C | libcurl |
| `url_go_neturl/` | Go | `net/url` |
| `url_java_uri/` | Java | `java.net.URI` |
| `url_java_url/` | Java | `java.net.URL` |
| `url_rust_url/` | Rust | `url` crate |
| `url_php_parse_url.php` | PHP | `parse_url()` |
| `url_dotnet_uri/` | C# | `System.Uri` |

### HTML Sanitizers

| Target | Language | Implementation |
|--------|----------|----------------|
| `sanitizer_dompurify.js` | Node.js | DOMPurify |
| `sanitizer_sanitize_html.js` | Node.js | sanitize-html |
| `sanitizer_jsxss.js` | Node.js | xss.js |
| `sanitizer_bleach.py` | Python | Bleach |
| `sanitizer_nh3.py` | Python | nh3 |

### JSON Parsers

| Target | Language | Implementation |
|--------|----------|----------------|
| `json_strict.py` | Python | `json` (strict) |
| `json_json5.py` | Python | JSON5 |
| `json_crockford.py` | Python | Crockford reference |
| `json_jsmn.py` | Python/C | JSMN |
| `json_lenient.py` | Python | Lenient parser |

---

## Seed Corpus

File-based seeds are loaded before grammar-generated seeds via `--seeds-dir`.

| Directory | Contents |
|-----------|----------|
| `targets/url_seeds/` | 40 curated URLs — backslash confusion, hex/octal IP, IPv6, null bytes, encoding tricks |
| `targets/xss_seeds/` | 40 XSS payloads — namespace confusion, foster parenting, adoption agency, mXSS chains |
| `targets/mxss_seeds/` | 115 mutation XSS seeds — CVE reproductions, depth attacks, CDATA injection, config misuse |

---

## Output Format

```
output_dir/
├── report.json              # Session statistics
├── findings/
│   ├── 0000_low_crash/
│   │   ├── info.json        # Title, severity, fingerprint, metadata
│   │   └── input            # Triggering input
│   ├── 0001_high_differential/
│   │   ├── info.json
│   │   └── input
│   └── ...
└── corpus/
    ├── id_000000            # Seed input
    ├── id_000000.meta       # Seed metadata (depth, energy, coverage)
    └── ...
```

---

## Orchestrator Integration

web-fuzzer integrates with [fuzzer-orchestrator](../fuzzer-orchestrator) for web-based session management, real-time monitoring, and collaborative finding triage.

When `FUZZER_REDIS_URL` is set, the engine publishes real-time events (stats, findings, coverage, corpus, status) via Redis Pub/Sub.

```bash
# Run with Redis integration
FUZZER_REDIS_URL=redis://localhost:6379/0 FUZZER_SESSION_ID=1 \
  webfuzzer fuzz --grammar uri --target-cmd "..." --timeout 300
```

---

## Project Structure

```
web-fuzzer/
├── webfuzzer/
│   ├── cli.py                          # CLI entry point
│   ├── core/                           # Grammar IR, parser, generator, builtins
│   │   ├── grammar.py                  # Symbol, Production, Rule, Grammar
│   │   ├── parser.py                   # .grammar DSL parser
│   │   ├── generator.py                # Grammar → string generation
│   │   ├── builtins.py                 # Built-in functions (int, string, hex, regex, ...)
│   │   └── registry.py                 # Grammar registry
│   ├── fuzzer/
│   │   ├── engine.py                   # Main fuzzing loop (FuzzEngine)
│   │   ├── corpus.py                   # Seed corpus + coverage map
│   │   ├── protocols.py                # Protocol interfaces
│   │   ├── stats.py                    # Statistics tracking
│   │   ├── grammar_source.py           # Grammar-based seed generation
│   │   ├── redis_publisher.py          # Redis Pub/Sub integration
│   │   ├── targets/                    # ProcessTarget, PersistentTarget
│   │   ├── mutators/                   # 7 mutation strategies
│   │   ├── oracles/                    # 8 oracle types + composite
│   │   ├── coverage/                   # 4 coverage collectors
│   │   ├── schedulers/                 # 6 scheduling algorithms
│   │   └── dedup/                      # Fingerprint-based deduplication
│   ├── grammars/                       # Built-in .grammar files
│   └── native/                         # Rust speedups (PyO3)
├── targets/                            # Target scripts and seeds
│   ├── url_seeds/                      # Curated URL seed corpus
│   ├── xss_seeds/                      # XSS seed corpus
│   ├── mxss_seeds/                     # mXSS seed corpus
│   ├── persistent_wrapper.py           # Python persistent mode wrapper
│   └── persistent_wrapper.js           # Node.js persistent mode wrapper
├── tests/                              # Unit tests
├── docs/                               # Research reports and findings
├── poc/                                # Proof-of-concept demonstrations
├── scripts/                            # Utility scripts
├── tools/                              # Analysis tools
└── pyproject.toml                      # Project metadata
```
