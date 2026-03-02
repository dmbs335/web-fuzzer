"""Quick test for persistent wrapper protocol."""
import struct
import subprocess
import sys
import time

def test_persistent(cmd, label, input_file, n=10):
    """Send n requests to a persistent wrapper and measure throughput."""
    with open(input_file, "rb") as f:
        payload = f.read()

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True,
    )

    start = time.perf_counter()
    for i in range(n):
        # Send request
        header = struct.pack(">I", len(payload))
        proc.stdin.write(header + payload)
        proc.stdin.flush()

        # Read response header
        resp_header = proc.stdout.read(4)
        if len(resp_header) < 4:
            print(f"  [{label}] EOF at iteration {i}")
            break
        resp_len = struct.unpack(">I", resp_header)[0]

        # Read response body + exit code
        resp_body = proc.stdout.read(resp_len)
        exit_code_bytes = proc.stdout.read(4)
        exit_code = struct.unpack(">I", exit_code_bytes)[0]

        if i == 0:
            output = resp_body.decode("utf-8", errors="replace")
            print(f"  [{label}] first response (exit={exit_code}): {output[:120]}...")

    elapsed = time.perf_counter() - start
    proc.stdin.close()
    proc.terminate()

    avg_ms = (elapsed / n) * 1000
    print(f"  [{label}] {n} requests in {elapsed:.3f}s = {avg_ms:.1f}ms/exec")
    return avg_ms


if __name__ == "__main__":
    seed = "targets/saml_seeds/valid_response_01.xml"
    n = 20

    print(f"=== Persistent mode benchmark ({n} iterations each) ===\n")

    # Python targets
    test_persistent(
        "python targets/persistent_wrapper.py targets/saml_signxml_module.py",
        "signxml", seed, n
    )
    print()
    test_persistent(
        "python targets/persistent_wrapper.py targets/saml_python3saml_module.py",
        "python3-saml", seed, n
    )
    print()

    # Node.js targets
    test_persistent(
        "node targets/persistent_wrapper.js targets/saml_xmlcrypto_module.js",
        "xml-crypto", seed, n
    )
    print()
    test_persistent(
        "node targets/persistent_wrapper.js targets/saml_samlify_module.js",
        "samlify", seed, n
    )
    print()
    test_persistent(
        "node targets/persistent_wrapper.js targets/saml_nodesaml_module.js",
        "node-saml", seed, n
    )
    print()

    # Ruby
    test_persistent(
        "C:/Ruby32-x64/bin/ruby.exe targets/persistent_wrapper.rb targets/saml_rubysaml_module.rb",
        "ruby-saml", seed, n
    )
    print()

    # PHP
    php_exe = "C:/Users/dmbs3/AppData/Local/Microsoft/WinGet/Packages/PHP.PHP.8.3_Microsoft.Winget.Source_8wekyb3d8bbwe/php.exe"
    test_persistent(
        f"{php_exe} targets/persistent_wrapper.php targets/saml_phpsaml_module.php",
        "php-saml", seed, n
    )
