#!/usr/bin/env python3
"""Check a CuttleOS node's HTTPS endpoint with independent real-world TLS clients.

    python tools/https_check.py --port 18443                    # run.bat's forward
    python tools/https_check.py --port 18501 --save-cert n1.pem # a Triad/fleet node
    python tools/https_check.py --port 18443 --expect-sha256 <hex64 from the serial log>

1. Fetch the node's certificate (trust on first use) and print its SHA-256.
   With --expect-sha256 (the `HTTPS UP ... cert_sha256=` serial line), the
   fetched certificate must match it.
2. Python `ssl` (OpenSSL): TLS 1.3, certificate pinned with CA verification
   and hostname checks for `localhost` and `127.0.0.1`, then GET /healthz.
   Also: the same client without the pin must refuse the connection.
3. OpenSSL `s_client`: both cipher suites, both key-exchange groups, full
   verification against the pinned certificate; TLS 1.2 and an unoffered
   suite must be refused.
4. curl (Schannel on Windows): GET /healthz over TLS 1.3 against the pin.

Prints one line per check; exits non-zero if any check fails.
"""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile

GIT_TOOLS = pathlib.Path("C:/Program Files/Git/mingw64/bin")
REQUEST = "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"

results: list[tuple[bool, str]] = []


def check(ok: bool, label: str, detail: str = "") -> bool:
    results.append((ok, label))
    print(f"{'ok  ' if ok else 'FAIL'} {label}{(' - ' + detail) if detail else ''}")
    return ok


def find_tool(name: str, override: str | None) -> str | None:
    if override:
        return override
    found = shutil.which(name)
    if found:
        return found
    candidate = GIT_TOOLS / f"{name}.exe"
    return str(candidate) if candidate.exists() else None


def fetch_certificate(host: str, port: int) -> str:
    return ssl.get_server_certificate((host, port), timeout=10)


def python_ssl(host: str, port: int, cafile: str | None, server_name: str, path: str) -> tuple[str, str, str]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    if cafile:
        ctx.load_verify_locations(cafile=cafile)
    else:
        ctx.load_default_certs()
    with socket.create_connection((host, port), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname=server_name) as tls:
            tls.sendall(REQUEST.format(path=path, host=server_name).encode())
            body = b""
            while True:
                try:
                    chunk = tls.recv(4096)
                except (ssl.SSLEOFError, ConnectionResetError):
                    break
                if not chunk:
                    break
                body += chunk
                if b"\r\n\r\n" in body and _complete(body):
                    break
            return tls.version() or "", tls.cipher()[0], body.decode(errors="replace")


def _complete(resp: bytes) -> bool:
    head, _, body = resp.partition(b"\r\n\r\n")
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            return len(body) >= int(line.split(b":", 1)[1])
    return False


def s_client(openssl: str, host: str, port: int, cafile: str, path: str, extra: list[str]) -> subprocess.CompletedProcess:
    # `-ign_eof` keeps reading after the request is sent until the server ends
    # the session, which it does after answering `Connection: close`.
    cmd = [
        openssl, "s_client", "-connect", f"{host}:{port}", "-servername", "localhost",
        "-CAfile", cafile, "-verify_return_error", "-verify_hostname", "localhost",
        "-brief", "-ign_eof", *extra,
    ]
    # Bytes, not text mode: on Windows text mode would turn the request's
    # CRLFs into CR CR LF and the HTTP head would never complete.
    request = REQUEST.format(path=path, host="localhost").encode()
    try:
        r = subprocess.run(cmd, input=request, capture_output=True, timeout=30)
        return subprocess.CompletedProcess(
            cmd, r.returncode, r.stdout.decode(errors="replace"), r.stderr.decode(errors="replace")
        )
    except subprocess.TimeoutExpired as exc:
        partial = ((exc.stdout or b"") + (exc.stderr or b"")).decode(errors="replace")
        return subprocess.CompletedProcess(cmd, 124, partial + "\n(timed out: server did not end the session)", "")


def is_tls_handshake_refusal(r: subprocess.CompletedProcess) -> bool:
    """Return True only when `s_client` failed with an explicit TLS alert or
    handshake refusal, never on a timeout (returncode 124)."""
    out = (r.stdout + r.stderr).lower()
    if r.returncode in (0, 124) or "timed out" in out or "cuttle-status" in out:
        return False
    return any(
        marker in out
        for marker in ("alert", "handshake failure", "protocol version", "no protocols available")
    )


def run_self_test() -> int:
    timeout_res = subprocess.CompletedProcess(
        ["openssl"], 124, "(timed out: server did not end the session)", ""
    )
    assert not is_tls_handshake_refusal(timeout_res), "timeout must not count as TLS refusal"
    ok_res = subprocess.CompletedProcess(["openssl"], 0, "CUTTLE-STATUS", "")
    assert not is_tls_handshake_refusal(ok_res), "200 OK must not count as TLS refusal"
    conn_refused = subprocess.CompletedProcess(["openssl"], 1, "", "connect:errno=111")
    assert not is_tls_handshake_refusal(conn_refused), "TCP error without TLS alert must not count as handshake alert"
    alert_res = subprocess.CompletedProcess(
        ["openssl"], 1, "", "SSL alert number 70: tlsv1 alert protocol version"
    )
    assert is_tls_handshake_refusal(alert_res), "TLS protocol version alert must be accepted"
    hs_fail_res = subprocess.CompletedProcess(
        ["openssl"], 1, "", "sslv3 alert handshake failure"
    )
    assert is_tls_handshake_refusal(hs_fail_res), "TLS handshake failure alert must be accepted"
    print("https_check self-test OK")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, help="target HTTPS port")
    ap.add_argument("--path", default="/healthz")
    ap.add_argument("--expect-sha256", help="certificate SHA-256 from the node's serial console")
    ap.add_argument("--save-cert", help="write the fetched PEM certificate here")
    ap.add_argument("--openssl", help="openssl executable (default: PATH, then Git for Windows)")
    ap.add_argument("--curl", help="curl executable (default: PATH)")
    ap.add_argument("--self-test", action="store_true", help="run unit self-tests")
    args = ap.parse_args()
    if args.self_test:
        return run_self_test()
    if not args.port:
        ap.error("--port is required unless --self-test is passed")
    host, port, path = args.host, args.port, args.path

    # 1. Certificate, trust on first use.
    try:
        pem = fetch_certificate(host, port)
    except OSError as exc:
        check(False, "fetch certificate", str(exc))
        return 1
    sha = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()
    check(True, "fetch certificate", f"sha256={sha}")
    if args.expect_sha256:
        check(sha == args.expect_sha256.lower(), "certificate matches serial-console fingerprint")
    workdir = pathlib.Path(tempfile.mkdtemp(prefix="cuttle_https_"))
    try:
        cafile = pathlib.Path(args.save_cert) if args.save_cert else workdir / "node.pem"
        cafile.write_text(pem, encoding="ascii")

        # 2. Python ssl.
        for name in ("localhost", "127.0.0.1"):
            try:
                version, cipher, resp = python_ssl(host, port, str(cafile), name, path)
                check(
                    version == "TLSv1.3" and resp.startswith("HTTP/1.1 200") and "CUTTLE-STATUS" in resp,
                    f"python ssl ({ssl.OPENSSL_VERSION}) pinned, name={name}",
                    f"{version} {cipher} -> {resp.splitlines()[0] if resp else '(empty)'}",
                )
            except (OSError, ssl.SSLError) as exc:
                check(False, f"python ssl pinned, name={name}", str(exc))
        try:
            python_ssl(host, port, None, "localhost", path)
            check(False, "python ssl without the pin is refused", "connection was accepted")
        except ssl.SSLCertVerificationError as exc:
            check(True, "python ssl without the pin is refused", exc.verify_message)
        except (OSError, ssl.SSLError) as exc:
            check(False, "python ssl without the pin is refused", f"unexpected error: {exc}")

        # 3. OpenSSL s_client.
        openssl = find_tool("openssl", args.openssl)
        if not openssl:
            check(False, "openssl s_client", "openssl not found (pass --openssl)")
        else:
            ver = subprocess.run([openssl, "version"], capture_output=True, text=True).stdout.strip()
            for suite in ("TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256"):
                for group in ("X25519", "P-256"):
                    r = s_client(openssl, host, port, str(cafile), path, ["-tls1_3", "-ciphersuites", suite, "-groups", group])
                    out = r.stdout + r.stderr
                    ok = (
                        r.returncode == 0
                        and "Verification: OK" in out
                        and "Protocol version: TLSv1.3" in out
                        and f"Ciphersuite: {suite}" in out
                        and "CUTTLE-STATUS" in out
                    )
                    check(ok, f"openssl s_client ({ver}) {suite} {group}", "" if ok else out.strip()[-300:])
            r = s_client(openssl, host, port, str(cafile), path, ["-tls1_2"])
            check(is_tls_handshake_refusal(r), "openssl TLS 1.2 is refused with handshake alert")
            r = s_client(openssl, host, port, str(cafile), path, ["-tls1_3", "-ciphersuites", "TLS_AES_256_GCM_SHA384"])
            check(is_tls_handshake_refusal(r), "openssl unoffered suite (AES-256-GCM) is refused with handshake alert")

        # 4. curl.
        curl = find_tool("curl", args.curl)
        if not curl:
            check(False, "curl", "curl not found (pass --curl)")
        else:
            ver = subprocess.run([curl, "--version"], capture_output=True, text=True).stdout.splitlines()[0]
            cmd = [
                curl, "--silent", "--show-error", "--tlsv1.3", "--cacert", str(cafile),
                "--resolve", f"localhost:{port}:{host}", f"https://localhost:{port}{path}",
            ]
            if "Schannel" in ver:
                # Self-signed: there is no CRL/OCSP to consult. Chain and name checks stay on.
                cmd.insert(1, "--ssl-no-revoke")
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            check(
                r.returncode == 0 and "CUTTLE-STATUS" in r.stdout,
                f"curl ({' '.join(ver.split()[:2])}, {'Schannel' if 'Schannel' in ver else 'OpenSSL'})",
                (r.stdout.strip() or r.stderr.strip())[:200],
            )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    failed = [label for ok, label in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
