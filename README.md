# web-fuzzer

A grammar-based, coverage-guided web fuzzing framework with differential testing, domain-specific oracles, persistent execution, and advanced state-space exploration techniques.

Designed for discovering parser differentials, SSRF bypasses, and sanitizer evasions across multiple target implementations.

## Key Features

- **Grammar-Based Input Generation** — Custom DSL for defining input grammars (URI, HTML, JSON, CSP, Cookie, ECMAScript, multipart)
- **Differential Fuzzing** — Compare outputs across multiple target implementations to find behavioral divergences
- **Domain-Specific Oracles** — Crash, SSRF (URL confusion), XSS, mXSS, sanitizer bypass, and response anomaly detection
- **Coverage-Guided Mutation** — AFL-style edge coverage + behavioral divergence tracking (Nezha-inspired)
- **Persistent Execution** — Length-prefixed binary protocol for ~50x speedup over process-per-execution
- **Pluggable Architecture** — Protocol-based interfaces for targets, mutators, schedulers, coverage collectors, and oracles
- **Seed Corpus** — File-based seed loading with curated seed sets for URL and XSS fuzzing
- **MCTS Grammar Derivation** — UCB1-guided grammar production selection with reward backpropagation
- **MAP-Elites Quality-Diversity** — Behavior-archive scheduler exploring parser disagreement frontiers
- **Contextual Bandit Mutator Selection** — LinUCB learns which mutator works best for each seed type
- **CEGAR Adaptive Coverage** — Auto-tunes differential coverage abstraction level based on corpus growth
- **Combinatorial Testing** — Pairwise covering arrays for systematic URL component combination coverage

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

# URL parser differential fuzzing with all features
webfuzzer fuzz --grammar uri --rule uri \
  --target-cmd "python targets/url_python_urllib.py {input}" \
  --diff-cmd "node targets/url_node_whatwg.js {input}" \
  --diff-cmd "targets/url_go_net_url/url_go_net_url.exe {input}" \
  --oracle crash,ssrf \
  --mutators grammar,havoc,token,splice \
  --scheduler map-elites \
  --mutator-scheduler linucb --linucb-alpha 1.5 \
  --mcts --mcts-exploration 1.41 \
  --adaptive-coverage --adaptive-level 1 \
  --seeds-dir targets/url_seeds \
  --persistent \
  --timeout 3600 \
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
| `--scheduler NAME` | Seed scheduler: random, entropic, ecofuzz, rare-branch, map-elites |
| `--mutator-scheduler NAME` | Mutator scheduler: random, mopt, darwin, linucb |
| `--linucb-alpha FLOAT` | LinUCB exploration parameter (default: 1.0) |
| `--mcts` | Enable MCTS-guided grammar derivation |
| `--mcts-exploration FLOAT` | UCB1 exploration weight (default: 1.41) |
| `--adaptive-coverage` | Enable CEGAR adaptive coverage refinement |
| `--adaptive-level INT` | Initial refinement level 0-4 (default: 1) |
| `--adaptive-upper-pct FLOAT` | Corpus % threshold for coarsening (default: 5.0) |
| `--adaptive-check-interval INT` | Iterations between adaptation checks (default: 5000) |
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
│       │              │                                         │
│  ┌──────────┐   ┌──────────┐                                   │
│  │ MCTS     │   │ MAP-Elite│                                   │
│  │ UCBTable │   │ Archive  │                                   │
│  └──────────┘   └──────────┘                                   │
└─────────────────────────────────────────────────────────────────┘
```

### Core Loop

1. **Seed Phase** — Load file-based seeds (Phase 1), then fill with grammar-generated seeds (Phase 2); MCTS feedback on each seed
2. **Select** — Seed scheduler picks a seed (Entropic / MAP-Elites composite); mutator scheduler picks a mutator (LinUCB / MOPT / random)
3. **Mutate** — Mutator transforms the seed input; grammar mutator uses UCB1-guided production selection
4. **Execute** — Run against primary target (and reference targets if differential mode)
5. **Evaluate** — Coverage collector checks for novel behavior; oracles classify findings; CEGAR monitors corpus growth
6. **Update** — Add interesting inputs to corpus; report findings; backpropagate rewards to MCTS and LinUCB

---

## State-Space Exploration Techniques

web-fuzzer applies five CS state-space exploration techniques to improve fuzzing coverage and efficiency:

### 1. MCTS Grammar Derivation

Grammar derivation is a sequential decision problem — each rule expansion is a choice point. MCTS (Monte Carlo Tree Search) learns which production alternatives lead to inputs that discover new coverage or findings.

- **UCB1 selection**: Balances exploitation (high-reward productions) vs exploration (untried productions)
- **Backpropagation**: Rewards (new coverage = 1.0, finding = 5.0) propagate to all productions in the derivation path
- **Shared table**: UCBTable is shared between GrammarInputSource and GrammarMutator, so learned preferences transfer
- Enable with `--mcts` and tune exploration weight with `--mcts-exploration`

### 2. MAP-Elites Quality-Diversity Scheduling

Maintains a behavior archive indexed by (finding_category, reference_parser_index). Each cell holds the "best" seed — the one with the richest coverage.

- **Frontier exploration**: Preferentially selects seeds from cells adjacent to empty cells in the grid
- **16 categories x 5 ref indices** = 80-cell archive (SSRF host confusion, open redirect, scheme confusion, etc.)
- Composed with EntropicScheduler via CompositeScheduler (30% MAP-Elites, 70% Entropic by default)
- Enable with `--scheduler map-elites`

### 3. LinUCB Contextual Bandit (Mutator Scheduling)

Context-aware mutator selection — learns which mutator works best for which kind of seed. Context features are extracted from the seed (AST depth, energy, finding count, rule diversity, mutation chain depth, etc.).

- **8-dimensional context**: tree_depth, has_findings, rule_diversity, exec_count, energy, age, chain_depth, bias
- **Pure Python**: No numpy dependency; 8x8 matrix operations with Sherman-Morrison incremental inverse
- **Online learning**: Updates after every execution, adapts to changing corpus characteristics
- Enable with `--mutator-scheduler linucb` and tune with `--linucb-alpha`

### 4. CEGAR Adaptive Coverage

Auto-tunes the abstraction level of differential coverage features based on corpus growth rate, inspired by CEGAR (Counterexample-Guided Abstraction Refinement).

Five refinement levels (coarsest to finest):

| Level | Features |
|-------|----------|
| L0 | exit_vec + div_bucket{0,1+} |
| L1 | + per-pair cdiff hash (default) |
| L2 | + per-component individual bits |
| L3 | + actual differing value hashes |
| L4 | + status_vec + error_divergence |

- **Coarsens** when corpus grows too fast (corpus% > threshold) — reduces over-splitting
- **Refines** when coverage stagnates — discovers finer-grained differentials
- **Lossless rebuild**: Stores raw features per seed, re-hashes at new level without re-execution
- Enable with `--adaptive-coverage` and configure with `--adaptive-level`, `--adaptive-upper-pct`, `--adaptive-check-interval`

### 5. Combinatorial Testing (Pairwise Covering Arrays)

Guarantees that all pairs of URL component mutations are tested at least once, using the IPOG algorithm.

Generate combinatorial seed corpus:

```bash
python scripts/generate_combinatorial_seeds.py \
  --output-dir targets/url_seeds_comb \
  --strength 2
```

7 URL dimensions (51 total values):
- **scheme** (8): http, https, file, javascript, data, gopher, case_varied, tab_injected
- **userinfo** (7): none, simple, double_at, backslash_at, encoded_at, colon_backslash, host_like
- **host** (10): domain, ipv4, hex_ip, octal_ip, decimal_ip, ipv6_loopback, ipv6_mapped, bracket_confusion, localhost, wildcard_dns
- **port** (7): none, standard, high, overflow, leading_zero, negative, non_numeric
- **path** (7): simple, traversal, encoded_traversal, overlong_utf8, semicolon_param, backslash, null_byte
- **query** (6): none, simple, encoded, double_question, semicolon_delimited, hpp_duplicate
- **fragment** (6): none, simple, at_authority, double_hash, query_like, authority_like

Expected ~300-400 seeds for pairwise (2-way) coverage.

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
| **grammar** | AST-level subtree replacement, splice, production swap (Nautilus/Superion-style); UCB1-guided with `--mcts` |
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
| **AdaptiveDiffCoverage** | CEGAR-wrapped DiffCoverage with automatic level management |

### Seed Schedulers

| Scheduler | Algorithm |
|-----------|-----------|
| **random** | Uniform random selection |
| **entropic** | Energy-based scheduling (AFLFast-style) |
| **ecofuzz** | Ecosystem-optimized scheduling |
| **rare-branch** | Prioritizes seeds covering rare branches |
| **map-elites** | Composite scheduler: 70% Entropic + 30% MAP-Elites quality-diversity |

### Mutator Schedulers

| Scheduler | Algorithm |
|-----------|-----------|
| **random** | Uniform random selection |
| **mopt** | PSO-based mutator optimization |
| **darwin** | Evolutionary strategy mutator selection |
| **linucb** | LinUCB contextual bandit — context-aware selection based on seed features |

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
| `targets/url_seeds/` | 154 curated URLs — backslash confusion, hex/octal IP, IPv6, null bytes, encoding tricks |
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
│   │   ├── grammar_source.py           # Grammar-based seed generation + MCTS feedback
│   │   ├── mcts.py                     # UCBTable — MCTS grammar production selection
│   │   ├── redis_publisher.py          # Redis Pub/Sub integration
│   │   ├── targets/                    # ProcessTarget, PersistentTarget
│   │   ├── mutators/                   # 7 mutation strategies
│   │   ├── oracles/                    # 8 oracle types + composite
│   │   ├── coverage/                   # Coverage collectors + CEGAR adaptive
│   │   │   ├── diff_coverage.py        # DiffCoverageCollector (Nezha-inspired)
│   │   │   ├── adaptive_coverage.py    # AdaptiveDiffCoverage (CEGAR)
│   │   │   └── feature_store.py        # Raw feature store for level transitions
│   │   ├── schedulers/                 # Scheduling algorithms
│   │   │   ├── map_elites.py           # MAP-Elites quality-diversity
│   │   │   ├── composite.py           # CompositeScheduler (primary + secondary)
│   │   │   └── linucb_scheduler.py     # LinUCB contextual bandit
│   │   └── dedup/                      # Fingerprint-based deduplication
│   ├── combinatorial/                  # Combinatorial testing
│   │   └── covering_array.py           # IPOG covering array generator
│   ├── grammars/                       # Built-in .grammar files
│   └── native/                         # Rust speedups (PyO3)
├── targets/                            # Target scripts and seeds
│   ├── url_seeds/                      # Curated URL seed corpus
│   ├── xss_seeds/                      # XSS seed corpus
│   ├── mxss_seeds/                     # mXSS seed corpus
│   ├── persistent_wrapper.py           # Python persistent mode wrapper
│   └── persistent_wrapper.js           # Node.js persistent mode wrapper
├── scripts/
│   └── generate_combinatorial_seeds.py # Pairwise URL seed generator
├── tests/                              # Unit tests
├── docs/                               # Research reports and findings
├── poc/                                # Proof-of-concept demonstrations
├── tools/                              # Analysis tools
└── pyproject.toml                      # Project metadata
```

---

## References

- **Nautilus** — Aschermann et al., "NAUTILUS: Fishing for Deep Bugs with Grammars", NDSS 2019
- **Nezha** — Petsios et al., "NEZHA: Efficient Domain-Independent Differential Testing", IEEE S&P 2017
- **MAP-Elites** — Mouret & Clune, "Illuminating search spaces by mapping elites", IEEE TEC 2015
- **LinUCB** — Li et al., "A Contextual-Bandit Approach to Personalized News Article Recommendation", WWW 2010
- **IPOG** — Lei & Tai, "In-parameter-order: a test generation strategy for pairwise testing", IEEE HASE 1998
- **CEGAR** — Clarke et al., "Counterexample-guided abstraction refinement", CAV 2000
- **MOPT** — Lyu et al., "MOPT: Optimized Mutation Scheduling for Fuzzers", USENIX Security 2019
- **Entropic** — Böhme et al., "Boosting Fuzzer Efficiency", ESEC/FSE 2020
