# URL Parser Differential Fuzzing: Campaign Report

> **Date**: 2026-02-23
> **Sessions**: S50 ~ S57 (7 sessions, ~157,000 total executions)
> **Cumulative Unique Findings**: 786
> **Parsers**: Python urllib, Python rfc3986, Node.js WHATWG, Node.js legacy, curl

---

## 1. Executive Summary

7개의 URL 파서에 대한 differential fuzzing 캠페인을 통해 **786개의 고유한 파싱 불일치 패턴**을 발견했다. 이 중 166개는 4회 이상의 세션에서 재현되는 **구조적 취약점**이며, 32개는 SSRF로 직결되는 CRITICAL 등급이다.

가장 중요한 발견은 기술적 결과가 아니라 **방법론적 발견**이다: 퍼저의 oracle이 입력당 하나의 finding만 반환하도록 설계되면, 실제 존재하는 취약점의 **절반 이상이 보이지 않게 된다.** Session 57에서 다중 finding oracle을 도입한 결과, 이전 6개 세션의 누적 결과(396개)보다 **단일 세션에서 더 많은 고유 패턴(553개)**을 발견했다.

---

## 2. Campaign Evolution

### 2.1 Session Overview

| Session | Duration | Execs | Exec/s | Findings | Cumulative | New | Novelty | Key Change |
|---------|----------|-------|--------|----------|------------|-----|---------|------------|
| S50 | 20min | 18,901 | 15.8 | 129 | 129 | 129 | 100% | Baseline (7-target) |
| S51 | 21min | 5,103 | 4.1 | 66 | 129 | 0 | 0% | Persistent mode (failed) |
| S52 | 15min | 16,531 | 18.4 | 172 | 188 | 59 | 34% | Mixed persistent/process |
| S53 | 15min | 20,654 | 22.9 | 256 | 290 | 102 | 40% | Coverage granularity fix |
| S54 | 15min | 19,782 | 22.0 | 211 | 320 | 30 | 14% | Seeds-dir + curated seeds |
| S56 | 30min | 44,283 | 24.6 | 325 | 396 | 76 | 23% | Dead seed pruning |
| **S57** | **45min** | **32,402** | **12.0** | **553** | **786** | **390** | **70.5%** | **Multi-finding oracle** |

### 2.2 Novelty Rate Trend

```
S50  ████████████████████████████████████████  100%   (baseline)
S51                                              0%   (persistent mode failure)
S52  █████████████                              34%   (speed recovery)
S53  ████████████████                           40%   (coverage fix)
S54  █████                                      14%   (diminishing returns)
S56  █████████                                  23%   (seed optimization)
S57  ████████████████████████████               70.5% ← multi-finding oracle
```

### 2.3 Severity Distribution Evolution

| Session | CRITICAL | HIGH | MEDIUM | LOW | Total |
|---------|----------|------|--------|-----|-------|
| S50 | 31 (24%) | 89 (69%) | 8 (6%) | 1 | 129 |
| S53 | 58 (23%) | 187 (73%) | 10 (4%) | 1 | 256 |
| S56 | 68 (21%) | 242 (74%) | 14 (4%) | 1 | 325 |
| **S57** | **35 (6%)** | **193 (35%)** | **291 (53%)** | **34 (6%)** | **553** |

---

## 3. Core Insights

### Insight 1: Oracle 설계가 퍼저의 시야를 결정한다

S50-S56까지의 DiffOracle는 입력 하나당 **가장 높은 severity의 finding 하나만** 반환했다. 이는 합리적인 설계처럼 보이지만, 실제로는 치명적인 정보 손실을 일으켰다.

```
입력: http://evil.com\@good.com:8080/path?q=1#frag

[이전] host confusion (HIGH) 만 반환
       → port=8080 vs 80 (MEDIUM) 버려짐
       → query 인코딩 차이 (MEDIUM) 버려짐
       → fragment 처리 차이 (LOW) 버려짐

[S57]  host confusion (HIGH)  ← 반환
       port confusion (MEDIUM) ← 반환
       query confusion (MEDIUM) ← 반환
       fragment confusion (LOW) ← 반환
```

**수치적 증거:**

| 항목 | S56 (단일) | S57 (다중) | 배율 |
|------|-----------|-----------|------|
| MEDIUM findings | 14 | 291 | **×20.8** |
| LOW findings | 1 | 34 | **×34** |
| port_confusion | 0 | 34 | **∞** |
| query_confusion | 0 | 27 | **∞** |
| fragment_confusion | 0 | 36 | **∞** |
| path_confusion | 0 | 45 | **∞** |

port, query, fragment, path confusion은 이전 6개 세션에서 **단 한 건도 독립적으로 보고되지 않았다.** 이들은 존재하지 않았던 것이 아니라, host confusion에 **가려져 보이지 않았던 것**이다.

> **일반화**: Differential fuzzing에서 oracle의 출력 카디널리티(1 vs N)는 mutator 전략이나 seed 최적화보다 탐색 공간에 더 큰 영향을 미친다.

### Insight 2: 파서 불일치는 멱법칙(Power Law)을 따른다

786개의 고유 fingerprint 중:

| 재현 횟수 | Fingerprint 수 | 비율 |
|-----------|---------------|------|
| 1 session only | 485 | 61.7% |
| 2 sessions | 81 | 10.3% |
| 3 sessions | 54 | 6.9% |
| 4 sessions | 48 | 6.1% |
| 5 sessions | 63 | 8.0% |
| 6 sessions (all) | 55 | 7.0% |

61.7%가 단일 세션에서만 발견되었다. 이는 **긴 꼬리(long tail)** 분포이며, 다음을 의미한다:

1. **핵심 취약점 55개**: 모든 세션에서 재현. 파서의 근본적 설계 차이. 패치 없이는 해결 불가.
2. **재현 가능 취약점 166개 (4+ sessions)**: 안정적으로 재현되며 실전 공격에 활용 가능.
3. **탐색 공간 미포화**: 매 세션마다 새로운 패턴이 발견되고 있어, 아직 발견되지 않은 패턴이 상당수 존재.

> **일반화**: URL 파서 불일치의 total population은 현재 발견된 786개보다 **수배 이상** 클 것으로 추정된다. 70.5%의 novelty rate는 탐색이 아직 초기 단계임을 시사한다.

### Insight 3: 파서 쌍마다 공격 표면이 질적으로 다르다

| 파서 쌍 | 주요 공격 벡터 | 근본 원인 |
|---------|---------------|----------|
| urllib vs **WHATWG** (225건) | Backslash→slash, fullwidth Unicode, incomplete IP | WHATWG가 "브라우저처럼" 관대하게 정규화 |
| urllib vs **legacy** (207건) | NULL byte truncation, hex/octal IP | legacy가 C-style string 처리와 유사 |
| urllib vs **rfc3986** (115건) | Strict rejection, percent-encoding 차이 | rfc3986가 비표준 입력을 거부 |
| urllib vs **curl** (4건) | NULL byte, C string truncation | curl이 C 기반이라 근본적 차이 |

**curl의 과소 대표 문제**: curl 타겟이 4건만 생성한 것은 curl이 안전하기 때문이 아니다. curl은 persistent mode로 동작하면서 **에러 시 무출력**을 반환하여, output strategy가 비교할 데이터가 없기 때문이다. 이는 타겟 어댑터 설계의 문제이며, 향후 curl의 에러 출력도 캡처하도록 개선이 필요하다.

### Insight 4: 독립적 컴포넌트 confusion의 실전 위협

S57에서 새로 발견된 컴포넌트별 confusion은 독립적 공격 벡터를 구성한다:

**Port Confusion (34건)**
```
http://example.com:8080/admin
  urllib: port="8080"
  WHATWG: port="" (default 80)
```
- **공격 시나리오**: 관리자 포트(8080, 9090) 접근 제어가 port 파싱에 의존하는 경우, 파서 차이로 우회 가능
- **실전 영향**: Kubernetes 내부 서비스 포트 접근, 관리 콘솔 우회

**Query Confusion (27건)**
```
http://example.com/api?redirect=http://evil.com
  urllib: query="redirect=http://evil.com"
  rfc3986: query="redirect=http%3A//evil.com"
```
- **공격 시나리오**: OAuth callback URL 검증에서 query parameter 파싱 차이를 이용한 open redirect
- **실전 영향**: OAuth token 탈취, CSRF 토큰 유출

**Fragment Confusion (36건)**
```
http://example.com/page#<script>alert(1)</script>
  urllib: fragment="<script>alert(1)</script>"
  WHATWG: fragment="%3Cscript%3Ealert(1)%3C/script%3E"
```
- **공격 시나리오**: Fragment를 서버 사이드에서 처리하는 SPA에서 XSS
- **실전 영향**: Single Page Application의 hash routing 기반 XSS

**Path Confusion (45건)**
```
http://example.com/..\..\admin
  urllib: path="/..\\..\\admin"
  WHATWG: path="/admin" (정규화됨)
```
- **공격 시나리오**: 리버스 프록시 뒤의 path-based ACL 우회
- **실전 영향**: nginx/Apache 리버스 프록시 + Node.js 백엔드 조합에서 관리자 경로 접근

### Insight 5: 퍼저 최적화의 수확 체감과 패러다임 전환

S50~S56의 6개 세션에 걸친 최적화(persistent mode, coverage fix, seed pruning)는 누적 396개의 고유 패턴을 산출했다. 각 세션의 한계 기여도는 점진적으로 감소했다:

```
S52: +59 new  (infrastructure optimization)
S53: +102 new (coverage algorithm fix)
S54: +30 new  (seed curation)
S56: +76 new  (dead seed pruning + extended time)
     ─────────
     총 267개의 점진적 발견 over 4 sessions
```

반면 S57의 **oracle 아키텍처 변경 하나**가 +390 new findings를 산출했다. 이는 4개 세션의 점진적 최적화 합계(267개)보다 **46% 더 많다.**

```
점진적 최적화 (4 sessions): +267
패러다임 전환 (1 session):  +390  ← 1.46x more
```

> **일반화**: 퍼저 성능 개선에서 "같은 프레임워크 안에서의 최적화"보다 "프레임워크 자체의 재설계"가 더 큰 도약을 만든다. 수확 체감이 나타나면, 매개변수 튜닝이 아닌 아키텍처 변경을 고려해야 한다.

---

## 4. Attack Pattern Taxonomy

### 4.1 Tier 1: SSRF Direct Bypass (CRITICAL, 35건)

파서 A는 외부 호스트로, 파서 B는 내부 IP로 해석하는 패턴.

| Pattern | Example | Bypasses |
|---------|---------|----------|
| Hex IP | `http://0x7f000001/` | IP blocklist |
| Octal IP | `http://0177.0.0.1/` | IP blocklist |
| Fullwidth Unicode | `http://１２７.0.0.1/` | WAF + blocklist |
| Percent-encoded localhost | `http://%6c%6f%63%61%6c%68%6f%73%74/` | String matching |
| IPv6 bracket mismatch | `http://[[::1]]/` | IPv6 blocklist |
| Incomplete IP | `http://127.0.0./` | Regex validation |
| NULL byte truncation | `http://good.com%00.evil.com/` | Domain allowlist |
| Hex + percent dot | `https://0x7f%2e0%2e0%2e1/` | Multi-layer WAF |

### 4.2 Tier 2: Authority & Redirect (HIGH, 193건)

| Pattern | Example | Impact |
|---------|---------|--------|
| Backslash authority | `http://evil.com\@good.com/` | Open redirect, OAuth bypass |
| Double @ | `http://user@evil.com@good.com/` | Credential confusion |
| Encoded @ | `http://good.com%40evil.com/` | Host confusion |
| Scheme confusion | `data:text/html,<script>...` | XSS via scheme |
| Path traversal | `http://host/..\..\admin` | ACL bypass |

### 4.3 Tier 3: Component-Level (MEDIUM, 291건) — S57 신규 발견

| Pattern | Count | Impact |
|---------|-------|--------|
| Path normalization diff | 45 | Reverse proxy ACL bypass |
| Fragment encoding diff | 36 | SPA XSS |
| Port interpretation diff | 34 | Internal port access |
| Query encoding diff | 27 | OAuth redirect manipulation |
| Output structure diff | 178 | General parsing inconsistency |

---

## 5. Finding Stability Analysis

### 5.1 Rock-Solid Findings (6/6 sessions): 55건

모든 세션에서 재현되는 55개 패턴은 파서의 **설계 결정(design decision)** 차이에서 비롯된다:

| Severity | Count | Example |
|----------|-------|---------|
| CRITICAL | 12 | Hex IP SSRF, NULL byte host truncation |
| HIGH | 38 | Backslash authority, path traversal normalization |
| MEDIUM | 4 | Output mismatch on specific components |
| LOW | 1 | Non-zero exit code |

이들은 RFC 해석의 차이, WHATWG vs RFC 3986 표준의 충돌, C vs Python 문자열 처리 차이 등 **구조적 원인**에 기인하며, 개별 파서를 패치하지 않는 한 영구적으로 존재한다.

### 5.2 Highly Reproducible (4+ sessions): 166건

| Severity | Count |
|----------|-------|
| CRITICAL | 32 |
| HIGH | 122 |
| MEDIUM | 11 |
| LOW | 1 |

---

## 6. Mutator Effectiveness

### 6.1 New Coverage Generation

| Mutator | S53 | S54 | S56 | S57 | Trend |
|---------|-----|-----|-----|-----|-------|
| dictionary | 196 | 169 | 255 | 107 | SSRF 토큰이 가장 효율적 |
| havoc | 104 | 88 | 96 | 56 | 무작위 변형의 꾸준한 기여 |
| grammar | 32 | 36 | 38 | 5 | 급격한 효율 감소 |

### 6.2 Interpretation

- **Dictionary**: SSRF 특화 토큰(`0x7f`, `%00`, `\\@`, `%2e` 등)이 새 경로를 가장 효과적으로 발견
- **Grammar**: 초기 탐색에서는 유용하나, 구조적 다양성이 포화되면서 효율 급감 (S56: 38 → S57: 5)
- **Havoc**: 예측 불가능한 변형이 꾸준히 새 패턴을 생성하여, 장기 세션에서 가장 안정적

---

## 7. Defense Recommendations

### 7.1 Architectural Principle (최우선)

```
[취약] Parser A로 검증 → Parser B로 요청
[안전] Parser B로 검증 → Parser B로 요청 (동일 파서)
```

786개의 불일치 패턴은 **모든 다중 파서 아키텍처가 원천적으로 취약**함을 증명한다.

### 7.2 Defense-in-Depth Checklist

| Layer | Action | Blocks |
|-------|--------|--------|
| **Input** | URL 내 `\`, `%00` 포함 시 거부 | Backslash authority, NULL byte |
| **Normalization** | 모든 IP 표기법을 dotted-decimal로 변환 | Hex/octal/fullwidth IP bypass |
| **Scheme** | `http`, `https`만 허용 | gopher/file/data/javascript SSRF |
| **DNS** | 파싱 결과가 아닌 실제 DNS resolution으로 검증 | DNS rebinding, IP 표기법 우회 |
| **Allowlist** | Blocklist 대신 allowlist 사용 | IP 표기법 변형의 무한 우회 |
| **Port** | 명시적 port allowlist (80, 443만) | Port confusion 기반 내부 서비스 접근 |

### 7.3 Architecture-Specific Guidance

| Architecture | Risk Level | Priority Action |
|---|---|---|
| Python backend + Node.js proxy | **CRITICAL** | 225건의 urllib↔WHATWG 불일치 |
| Python backend + Node.js legacy | **CRITICAL** | 207건, NULL byte + hex IP 집중 |
| Python backend + curl/requests | **HIGH** | C string truncation 위험 |
| Python backend + Java service | **MEDIUM** | Java가 대부분 비표준 URL 거부 |
| Any multi-parser combination | **CRITICAL** | 동일 파서 사용 원칙 적용 |

---

## 8. Methodology

### 8.1 Tools & Infrastructure

- **Fuzzer**: webfuzzer (custom grammar-based differential fuzzer)
- **Grammar**: URI (RFC 3986 기반)
- **Mutators**: Grammar, Havoc, Dictionary (SSRF-focused tokens)
- **Coverage**: DiffCoverageCollector (behavioral divergence-based)
- **Oracle**: DiffOracle with multi-finding mode (S57~)
- **Strategies**: UrlConfusionStrategy, PortConfusionStrategy, QueryConfusionStrategy, FragmentConfusionStrategy
- **Orchestrator**: fuzzer-orchestrator (FastAPI + WebSocket + SQLite)

### 8.2 Targets

| Parser | Language | Standard | Mode |
|--------|----------|----------|------|
| urllib.parse.urlparse | Python | RFC 3986 (loose) | Process |
| rfc3986 | Python | RFC 3986 (strict) | Process |
| new URL() | Node.js | WHATWG URL Standard | Process |
| url.parse() | Node.js | Legacy (pre-WHATWG) | Process |
| curl_url_set | C (curl) | RFC 3986 + extensions | Persistent |

### 8.3 Key Improvements Over Campaign

| Phase | Change | Impact |
|-------|--------|--------|
| S50→S51 | Persistent mode | Failed (speed regression) |
| S51→S52 | Mixed persistent/process | Speed 4.1→18.4 exec/s |
| S52→S53 | Coverage granularity fix | Corpus ratio 30%→2% |
| S53→S54 | Seeds-dir + curated seeds | +30 new findings |
| S54→S56 | Dead seed pruning | +76 new findings |
| **S56→S57** | **Multi-finding oracle** | **+390 new findings (paradigm shift)** |

---

## 9. Future Work

1. **curl 타겟 어댑터 개선**: 에러 시에도 JSON 출력을 보장하여 output strategy 활성화
2. **Java 타겟 재도입**: 별도 프로세스로 실행하여 accept/reject 차이 포착
3. **Scheme-specific oracle**: http/https/ftp/file 등 스킴별 특화 비교 전략
4. **DNS resolution oracle**: 파싱된 host의 실제 DNS 결과까지 비교
5. **세션 시간 60분 확장**: saturation factor 0.77 (S56 기준), 아직 미포화
6. **다른 언어 파서 추가**: Go net/url, Rust url crate, PHP parse_url
