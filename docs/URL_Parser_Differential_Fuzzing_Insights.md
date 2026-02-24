# URL Parser Differential Fuzzing: Security Insights Report

> **Date**: 2026-02-23
> **Sessions Analyzed**: S50 ~ S54 (5 sessions, ~80,000 total executions)
> **Total Unique Findings**: 320 (72 Critical, 232 High, 15 Medium, 1 Low)
> **Parsers Tested**: Python urllib, Python rfc3986, Node.js WHATWG, Node.js legacy, curl, Java URI, Java URL

---

## 1. Executive Summary

7개의 URL 파서를 대상으로 differential fuzzing을 수행한 결과, **320개의 고유한 파싱 불일치 패턴**을 발견했다. 이 중 72개는 SSRF(Server-Side Request Forgery)로 직결되는 **CRITICAL** 등급이다.

핵심 발견: **"파서 A로 URL을 검증하고, 파서 B로 실제 요청을 보내는"** 모든 아키텍처가 취약하다. 파서마다 동일한 URL을 완전히 다르게 해석하며, 이 차이가 곧 보안 취약점이 된다.

---

## 2. Parser Differential Matrix

urllib(primary)와 각 참조 파서 간의 URL 컴포넌트별 불일치 건수:

| Component | vs rfc3986 | vs WHATWG | vs legacy | vs curl | vs java_uri | vs java_url | Total |
|-----------|-----------|----------|----------|--------|------------|------------|-------|
| **host** | 62 | 82 | 38 | 48 | 4 | 5 | **239** |
| **path** | 71 | 73 | 44 | 45 | 5 | 6 | **244** |
| **userinfo** | 42 | 36 | 18 | 28 | 4 | 1 | **129** |
| **port** | 25 | 23 | 13 | 19 | 0 | 2 | **82** |
| **scheme** | 20 | 34 | 1 | 23 | 0 | 0 | **78** |
| **query** | 32 | 32 | 16 | 22 | 2 | 0 | **104** |
| **fragment** | 36 | 38 | 19 | 16 | 0 | 2 | **111** |

### Parser Pair Productivity

| Parser Pair | Findings | Share | Critical Rate |
|-------------|----------|-------|---------------|
| **urllib vs WHATWG** | 100 | 31.3% | 22% |
| **urllib vs rfc3986** | 90 | 28.1% | 24% |
| **urllib vs curl** | 62 | 19.4% | 23% |
| **urllib vs legacy** | 50 | 15.6% | 28% |
| urllib vs java_uri | 8 | 2.5% | 0% |
| urllib vs java_url | 8 | 2.5% | 0% |

**Key Insight**: urllib vs WHATWG가 가장 많은 불일치를 생성하지만, **urllib vs legacy(Node.js url.parse)가 가장 높은 critical rate**(28%)를 보인다. legacy 파서는 hex/octal IP를 자동 정규화하여 SSRF host confusion이 빈번하게 발생한다.

---

## 3. Finding Stability (Cross-Session Recurrence)

| Recurrence | Count | Share | Meaning |
|------------|-------|-------|---------|
| 4/4 sessions | **100** | 31.2% | Rock-solid: 매 세션 재현 |
| 3/4 sessions | 37 | 11.6% | Highly stable |
| 2/4 sessions | 74 | 23.1% | Moderately stable |
| 1 session only | 109 | 34.1% | One-off / mutation-dependent |

**100개의 rock-solid finding**이 모든 세션에서 재현된다. 이들은 파서의 근본적인 설계 차이에서 비롯되며, 패치 없이는 해결되지 않는 구조적 취약점이다.

---

## 4. Top Attack Patterns (핵심 공격 벡터)

### 4.1. Backslash Authority Confusion (`\@`)

```
http://evil.com\@good.com/path
```

- **urllib**: userinfo=`evil.com\`, host=`good.com`
- **WHATWG**: host=`evil.com`, path=`/@good.com/path` (backslash → slash)
- **Impact**: urllib로 검증하면 host=good.com(안전), WHATWG로 요청하면 host=evil.com(공격자)
- **Finding count**: 24+ variants
- **Real-world**: Python 백엔드 + Node.js/브라우저 프록시 아키텍처

### 4.2. Hex/Octal IP Normalization

```
http://0x7f000001/admin
http://0177.0.0.1/admin
http://0x7f.0x0.0.1/admin
```

- **urllib**: host=`0x7f000001` (문자열 그대로 — 차단 목록에 없음)
- **curl/WHATWG/legacy**: host=`127.0.0.1` (정규화된 내부 IP)
- **Impact**: SSRF 차단 목록 완전 우회
- **Finding count**: 20+ variants

### 4.3. NULL Byte Host Truncation

```
http://good.com%00.evil.com/path
file://attacker.com%00@127.0.0.1/
```

- **urllib**: host=`good.com%00.evil.com` (전체 문자열)
- **curl (C-based)**: host=`good.com` (NULL에서 절단)
- **Impact**: C 기반 라이브러리와 Python/JS 간의 근본적 문자열 처리 차이
- **Finding count**: 54 variants (가장 빈번한 패턴)

### 4.4. Fullwidth Unicode Digit IP

```
http://%ef%bc%91%ef%bc%92%ef%bc%97.0.0.1/
```

- `%ef%bc%91%ef%bc%92%ef%bc%97` = Unicode fullwidth "127"
- **urllib**: host=`%ef%bc%91%ef%bc%92%ef%bc%97.0.0.1` (문자열 그대로)
- **WHATWG**: host=`127.0.0.1` (Unicode 정규화 후 IP 인식)
- **Impact**: 가장 깔끔한 SSRF 우회 벡터. WAF 탐지 극히 어려움
- **Real-world**: 프론트엔드 검증 → 브라우저/Node.js fetch 시나리오

### 4.5. Double-Bracket IPv6 Confusion

```
http://[[::1]]/path
```

- **urllib**: host=`[::1` (첫 `]`에서 파싱 종료, 유효하지 않은 호스트)
- **legacy**: host=`[::1]` (올바른 IPv6 루프백)
- **Impact**: IPv6 대괄호 처리의 edge case. 차단 목록에 `[::1`은 없음

### 4.6. Percent-Encoded Dot + Hex IP (이중 우회)

```
https://0x7f%2e0%2e0%2e1/path
```

- **urllib**: host=`0x7f%2e0%2e0%2e1` (디코딩 안 함)
- **WHATWG**: host=`127.0.0.1` (디코딩 + hex 정규화)
- **Impact**: 인코딩 + IP 표기법 이중 우회로 WAF 탐지 극도로 어려움

### 4.7. Incomplete IP Auto-Completion

```
http://127.0.0./path
```

- **urllib**: host=`127.0.0.` (불완전 IP, 외부로 판단)
- **WHATWG**: host=`127.0.0.0` (자동 완성된 내부 IP)
- **Impact**: 마지막 옥텟 생략이라는 단순한 트릭으로 SSRF 우회

### 4.8. Non-HTTP Scheme SSRF (FTP, Gopher, Telnet)

```
gopher://127.0.0.1:6379/_SET%20pwned%20true
ftp://localhost:\@external.com/..
telnet://attacker.net\@127.0.0.1/
```

- **Impact**: 비-HTTP 스킴에서의 파서 차이는 보안 검증에서 자주 간과됨
- **Real-world**: SSRF 필터가 http/https만 검사하는 경우 완전 우회

---

## 5. Architecture-Specific Risk Assessment

### 5.1. Python Backend + Node.js Proxy/Frontend

| Risk | Level | Vector |
|------|-------|--------|
| SSRF via backslash authority | **CRITICAL** | `\@` confusion |
| SSRF via fullwidth digits | **CRITICAL** | Unicode normalization |
| SSRF via incomplete IP | **CRITICAL** | Auto-completion |
| Open redirect | **HIGH** | Host parsing difference |

**가장 위험한 조합.** urllib와 WHATWG가 가장 많은 불일치(100건)를 보인다.

### 5.2. Python Backend + curl/requests

| Risk | Level | Vector |
|------|-------|--------|
| SSRF via hex/octal IP | **CRITICAL** | IP normalization |
| SSRF via NULL byte | **CRITICAL** | C string truncation |
| SSRF via non-HTTP scheme | **HIGH** | Scheme handling diff |

curl은 C 기반이므로 NULL 바이트 절단이 치명적.

### 5.3. Python Backend + Java Microservice

| Risk | Level | Vector |
|------|-------|--------|
| Authority confusion | **HIGH** | `@` encoding diff |
| Scheme rejection diff | **MEDIUM** | Strict vs lenient parsing |

Java 파서는 대부분의 비표준 URL을 거부하므로 공격 표면이 좁다. 단, 허용되는 URL에서의 차이는 여전히 위험.

### 5.4. Multi-Parser Architecture (Any combination)

| Risk | Level | Vector |
|------|-------|--------|
| 모든 위 공격 벡터 | **CRITICAL** | 파서 조합에 따라 다름 |

> **원칙: SSRF 검증은 반드시 최종 요청을 수행하는 동일한 파서로 수행해야 한다.**

---

## 6. Fuzzing Campaign Evolution

| Session | Speed | Corpus% | Unique | Cumulative | New | Novelty% |
|---------|-------|---------|--------|------------|-----|----------|
| S50 | 15.8x | 99.1% | 129 | 129 | 129 | 100% |
| S51 | 4.1x | 2.4% | 67 | 129 | 0 | 0% |
| S52 | 22.0x | 30.4% | 172 | 188 | 59 | 34% |
| S53 | 22.9x | 2.1% | 256 | 290 | 102 | 40% |
| S54 | 22.0x | 2.0% | 211 | 320 | 30 | 14% |

### Key Improvements Over Sessions

1. **S50→S51**: Persistent mode 도입 시도 (속도 문제로 실패)
2. **S51→S52**: Mixed persistent/process mode로 속도 5x 향상
3. **S52→S53**: Coverage 과잉 세분화 수정 → corpus ratio 30%→2%
4. **S53→S54**: 타겟 시드 추가, 컴포넌트별 전략 추가

### Mutator Effectiveness (S53-S54 기준)

| Mutator | New Coverage Edges | Efficiency |
|---------|-------------------|------------|
| **dictionary** | 365 (56%) | **최고 효율** — SSRF 특화 토큰이 새 경로를 효과적으로 발견 |
| **havoc** | 192 (30%) | 무작위 변형이 예상 외 패턴 생성 |
| **grammar** | 68 (10%) | 구조적 다양성은 높지만 coverage 효율 낮음 |

---

## 7. Defense Recommendations

### 7.1. Architectural Defense (가장 중요)

```
[WRONG] Parser A로 검증 → Parser B로 요청
[RIGHT] Parser B로 검증 → Parser B로 요청 (동일 파서 사용)
```

URL 검증과 실제 요청에 **반드시 동일한 파서**를 사용해야 한다. 파서가 다르면 아무리 엄격한 검증도 우회 가능하다.

### 7.2. Input Normalization

1. **IP 주소 정규화**: hex(0x7f), octal(0177), decimal(2130706433), fullwidth 등 모든 표기법을 표준 dotted-decimal로 변환
2. **퍼센트 디코딩**: host 컴포넌트에서 모든 퍼센트 인코딩 디코딩 후 비교
3. **백슬래시 제거**: URL에 `\`가 포함된 경우 거부
4. **NULL 바이트 차단**: `%00`이 포함된 URL 거부

### 7.3. Allowlist vs Blocklist

```
[WRONG] if host not in blocklist: allow
[RIGHT] if host in allowlist: allow
```

- Blocklist는 IP 표기법 변형(hex/octal/decimal/fullwidth/IPv6-mapped 등)으로 무한히 우회 가능
- Allowlist 사용 시에도 정규화 필수

### 7.4. Scheme Restriction

```python
# HTTP/HTTPS만 허용
if parsed.scheme not in ('http', 'https'):
    reject()
```

gopher://, file://, ftp://, telnet:// 등 비-HTTP 스킴은 명시적으로 거부해야 한다.

### 7.5. DNS Resolution Check

```python
# 파싱된 호스트가 아닌, 실제 DNS 결과로 검증
resolved_ip = socket.getaddrinfo(host, port)
if is_internal(resolved_ip):
    reject()
```

DNS rebinding 방어를 위해 파싱 결과가 아닌 실제 DNS resolution 결과를 검증해야 한다.

---

## 8. Methodology

### Tools
- **Fuzzer**: Custom grammar-based differential fuzzer (webfuzzer)
- **Grammar**: URI (RFC 3986 기반)
- **Mutators**: Grammar, Havoc, Dictionary (SSRF-focused tokens)
- **Coverage**: Behavioral divergence-based (DiffCoverageCollector)
- **Oracle**: UrlConfusionStrategy (host > scheme > userinfo > path > port > query > fragment)

### Targets

| Parser | Language | Standard |
|--------|----------|----------|
| urllib.parse.urlparse | Python | RFC 3986 (loose) |
| rfc3986 | Python | RFC 3986 (strict) |
| new URL() | Node.js | WHATWG URL Standard |
| url.parse() | Node.js | Legacy (pre-WHATWG) |
| curl_url_set | C (curl) | RFC 3986 + extensions |
| java.net.URI | Java | RFC 2396 |
| java.net.URL | Java | Protocol-specific |

### Session Configuration
- **Execution mode**: Mixed PersistentTarget (Node.js/Java) + ProcessTarget (Python/curl)
- **Session duration**: 15-30 minutes
- **Initial seeds**: 100-150 (curated SSRF seeds + grammar-generated)
- **Deduplication**: Fingerprint-based (SHA256 of title + metadata hash)

---

## Appendix: Cumulative Finding Categories

| Category | Count | Description |
|----------|-------|-------------|
| path_traversal | 80 | `..` normalization differences enabling directory escape |
| open_redirect | 72 | Different host parsing enabling redirect to attacker domain |
| ssrf_host_confusion | 72 | Internal vs external host interpretation (SSRF bypass) |
| authority_confusion | 65 | `@`, `\`, userinfo boundary differences |
| scheme_confusion | 3 | Protocol interpretation differences |
| other | 28 | Exit code, output, crash differences |
