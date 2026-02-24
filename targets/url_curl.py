"""URL parser target — curl (libcurl).

Parses URLs using libcurl's CURLU API (ctypes) for differential comparison.

libcurl's URL parser is the actual request-side parser for PHP's curl_exec(),
making this the ground truth for what host PHP+curl SSRF would actually
connect to.

Uses ctypes to call libcurl's curl_url_set/curl_url_get directly, avoiding
subprocess overhead (~79,000 exec/s vs ~45 exec/s with curl CLI).

Fallback: if libcurl DLL is not found, falls back to curl CLI subprocess.

References:
  - libcurl URL API: https://curl.se/libcurl/c/liburl.html
  - Orange Tsai, "Confusion Attacks" (BlackHat 2023)
"""

import json
import sys

# ── libcurl ctypes binding ───────────────────────────────────────────
_libcurl = None
_CURLUPART_URL = 0
_CURLUPART_SCHEME = 1
_CURLUPART_USER = 2
_CURLUPART_PASSWORD = 3
_CURLUPART_HOST = 5
_CURLUPART_PORT = 6
_CURLUPART_PATH = 7
_CURLUPART_QUERY = 8
_CURLUPART_FRAGMENT = 9

_DEFAULT_PORTS = {"http": "80", "https": "443", "ftp": "21", "ws": "80", "wss": "443"}

_EMPTY_RESULT = json.dumps({
    "scheme": "", "userinfo": "", "host": "",
    "port": "", "path": "", "query": "", "fragment": "",
}, sort_keys=True, ensure_ascii=True)


def _load_libcurl():
    """Load libcurl DLL and set up ctypes function signatures."""
    global _libcurl
    if _libcurl is not None:
        return _libcurl

    import ctypes
    import pathlib

    # Strategy 1: find libcurl DLL bundled with pycurl/curl-cffi
    site_packages = pathlib.Path(sys.executable).parent / "Lib" / "site-packages"
    # Also check user site-packages
    candidates = list(pathlib.Path(sys.prefix).rglob("libcurl*.dll"))
    try:
        import importlib.util
        for pkg in ("pycurl", "curl_cffi"):
            spec = importlib.util.find_spec(pkg)
            if spec and spec.origin:
                pkg_dir = pathlib.Path(spec.origin).parent
                candidates.extend(pkg_dir.parent.glob("libcurl*.dll"))
    except Exception:
        pass

    # Strategy 2: system libcurl
    for sys_path in [
        pathlib.Path(r"C:\Windows\System32\libcurl.dll"),
        pathlib.Path(r"C:\msys64\mingw64\bin\libcurl.dll"),
        pathlib.Path(r"C:\msys64\usr\bin\libcurl.dll"),
    ]:
        if sys_path.exists():
            candidates.append(sys_path)

    for dll_path in candidates:
        try:
            lib = ctypes.CDLL(str(dll_path))
            # Verify CURLU API exists
            lib.curl_url.restype = ctypes.c_void_p
            lib.curl_url.argtypes = []
            lib.curl_url_set.restype = ctypes.c_int
            lib.curl_url_set.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
            lib.curl_url_get.restype = ctypes.c_int
            lib.curl_url_get.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_char_p), ctypes.c_uint]
            lib.curl_url_cleanup.restype = None
            lib.curl_url_cleanup.argtypes = [ctypes.c_void_p]
            lib.curl_free.restype = None
            lib.curl_free.argtypes = [ctypes.c_void_p]
            _libcurl = lib
            return lib
        except (OSError, AttributeError):
            continue

    return None


def parse_url(data: str) -> tuple[str, int]:
    """Parse URL with libcurl's CURLU API and return (json_str, exit_code).

    Uses ctypes for in-process parsing (no subprocess overhead).
    Falls back to curl CLI if libcurl DLL is unavailable.
    """
    data = data.strip()
    if not data:
        return _EMPTY_RESULT, 1

    lib = _load_libcurl()
    if lib is None:
        return _parse_url_subprocess(data)

    return _parse_url_ctypes(lib, data)


def _parse_url_ctypes(lib, data: str) -> tuple[str, int]:
    """Parse URL using libcurl CURLU API via ctypes."""
    import ctypes

    h = lib.curl_url()
    if not h:
        return _EMPTY_RESULT, 1

    try:
        url_bytes = data.encode("utf-8", errors="replace")
        rc = lib.curl_url_set(h, _CURLUPART_URL, url_bytes, 0)
        if rc != 0:
            # URL is completely unparseable by libcurl
            return _EMPTY_RESULT, 1

        def _get(part: int) -> str:
            ptr = ctypes.c_char_p()
            rc = lib.curl_url_get(h, part, ctypes.byref(ptr), 0)
            if rc == 0 and ptr.value:
                val = ptr.value.decode("utf-8", errors="replace")
                lib.curl_free(ptr)
                return val
            return ""

        scheme = _get(_CURLUPART_SCHEME)
        user = _get(_CURLUPART_USER)
        password = _get(_CURLUPART_PASSWORD)
        host = _get(_CURLUPART_HOST)
        port = _get(_CURLUPART_PORT)
        path = _get(_CURLUPART_PATH)
        query = _get(_CURLUPART_QUERY)
        fragment = _get(_CURLUPART_FRAGMENT)

        # Build userinfo
        userinfo = ""
        if user:
            userinfo = user
            if password:
                userinfo += ":" + password

        # Normalize port
        if port == "0":
            port = ""
        if port == _DEFAULT_PORTS.get(scheme, ""):
            port = ""

        result = {
            "scheme": scheme,
            "userinfo": userinfo,
            "host": host,
            "port": port,
            "path": path,
            "query": query,
            "fragment": fragment,
        }

        json_str = json.dumps(result, sort_keys=True, ensure_ascii=True)
        has_content = any([scheme, host, path, query, fragment, userinfo])
        return json_str, 0 if has_content else 1

    finally:
        lib.curl_url_cleanup(h)


def _parse_url_subprocess(data: str) -> tuple[str, int]:
    """Fallback: parse URL using curl CLI subprocess."""
    import subprocess

    CURL_FORMAT = (
        "%{url.scheme}\t%{url.user}\t%{url.password}\t"
        "%{url.host}\t%{url.port}\t%{url.path}\t"
        "%{url.query}\t%{url.fragment}"
    )

    proc = subprocess.run(
        ["curl", "-s", "--output", "/dev/null", "--connect-timeout", "0.001",
         "-w", CURL_FORMAT, "--", data],
        capture_output=True, timeout=5, stdin=subprocess.DEVNULL,
    )

    output = proc.stdout.decode("utf-8", errors="replace")
    parts = output.split("\t")
    while len(parts) < 8:
        parts.append("")

    scheme, user, password = parts[0].strip(), parts[1].strip(), parts[2].strip()
    host, port = parts[3].strip(), parts[4].strip()
    path, query, fragment = parts[5].strip(), parts[6].strip(), parts[7].strip()

    userinfo = user
    if user and password:
        userinfo += ":" + password

    if port == "0":
        port = ""
    if port == _DEFAULT_PORTS.get(scheme, ""):
        port = ""

    result = {
        "scheme": scheme, "userinfo": userinfo, "host": host,
        "port": port, "path": path, "query": query, "fragment": fragment,
    }
    json_str = json.dumps(result, sort_keys=True, ensure_ascii=True)
    has_content = any([scheme, host, path, query, fragment, userinfo])
    return json_str, 0 if has_content else 1


def main():
    if len(sys.argv) < 2:
        print("Usage: url_curl.py <file>", file=sys.stderr)
        sys.exit(2)

    try:
        with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as f:
            data = f.read()
    except OSError as e:
        print(f"IO error: {e}", file=sys.stderr)
        sys.exit(2)

    try:
        result, exit_code = parse_url(data)
        print(result)
        sys.exit(exit_code)
    except Exception as e:
        print(f"REJECT: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
