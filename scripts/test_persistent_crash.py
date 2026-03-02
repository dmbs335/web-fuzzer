"""Test persistent wrappers with adversarial inputs."""
import struct
import subprocess
import sys
import time

CRASH_INPUTS = [
    b"",  # empty
    b"not xml at all",  # garbage
    b"\x00\x01\x02\xff\xfe",  # binary
    b"<xml>unclosed",  # malformed XML
    b"<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",  # XXE
    b"<" + b"A" * 100000,  # huge tag
    b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"></samlp:Response>',  # minimal valid
]

def test_wrapper(cmd, label):
    proc = subprocess.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, shell=True,
    )

    for i, payload in enumerate(CRASH_INPUTS):
        try:
            header = struct.pack(">I", len(payload))
            proc.stdin.write(header + payload)
            proc.stdin.flush()

            # Try to read response with timeout
            import threading
            result = [None]
            def reader():
                try:
                    h = proc.stdout.read(4)
                    if len(h) < 4:
                        result[0] = "EOF"
                        return
                    rlen = struct.unpack(">I", h)[0]
                    body = proc.stdout.read(rlen)
                    ec_bytes = proc.stdout.read(4)
                    ec = struct.unpack(">I", ec_bytes)[0]
                    result[0] = f"OK(exit={ec}, len={rlen})"
                except Exception as e:
                    result[0] = f"ERR: {e}"

            t = threading.Thread(target=reader)
            t.start()
            t.join(timeout=5)

            if t.is_alive():
                print(f"  [{label}] input {i}: TIMEOUT (5s)")
                proc.kill()
                return False
            elif result[0] and result[0].startswith("OK"):
                print(f"  [{label}] input {i}: {result[0]}")
            else:
                print(f"  [{label}] input {i}: DIED - {result[0]}")
                return False
        except (BrokenPipeError, OSError) as e:
            print(f"  [{label}] input {i}: CRASH - {e}")
            return False

    proc.stdin.close()
    proc.terminate()
    stderr_out = proc.stderr.read().decode(errors="replace")
    if stderr_out.strip():
        print(f"  [{label}] stderr: {stderr_out[:200]}")
    print(f"  [{label}] ALL PASSED")
    return True


if __name__ == "__main__":
    print("=== Persistent wrapper crash testing ===\n")

    wrappers = [
        ("python targets/persistent_wrapper.py targets/saml_signxml_module.py", "signxml"),
        ("python targets/persistent_wrapper.py targets/saml_python3saml_module.py", "python3-saml"),
        ("node targets/persistent_wrapper.js targets/saml_xmlcrypto_module.js", "xml-crypto"),
        ("node targets/persistent_wrapper.js targets/saml_samlify_module.js", "samlify"),
        ("node targets/persistent_wrapper.js targets/saml_nodesaml_module.js", "node-saml"),
        ("C:/Ruby32-x64/bin/ruby.exe targets/persistent_wrapper.rb targets/saml_rubysaml_module.rb", "ruby-saml"),
        ("C:/Users/dmbs3/AppData/Local/Microsoft/WinGet/Packages/PHP.PHP.8.3_Microsoft.Winget.Source_8wekyb3d8bbwe/php.exe targets/persistent_wrapper.php targets/saml_phpsaml_module.php", "php-saml"),
    ]

    for cmd, label in wrappers:
        test_wrapper(cmd, label)
        print()
