"""
AdaptiveQKE TLS Server
=======================
OQS-OpenSSL TLS 1.3 server used by the experiment.

  * start_tls_server() -- launches `openssl s_server` restricted to
    TLS 1.3 and the three hybrid groups under evaluation. `-quiet`
    suppresses per-connection output; `-no_ticket` forces a full
    handshake on every trial.

  * start_rtt_probe_server() -- plain TCP sink for the client's RTT
    probe: accepts a connection, drains incoming bytes, closes. One
    thread per connection.

Run standalone (`python3 tls_server.py`) for manual testing;
experiment.py imports both functions and adds readiness polling,
health checks, and restarts on top.
"""

import os
import signal
import subprocess
import socket
import sys
import threading
from pathlib import Path


TLS_PORT       = 4433
RTT_PROBE_PORT = 9000

BASE_DIR  = Path(__file__).resolve().parent
CERT_FILE = BASE_DIR / "certs" / "server.crt"
KEY_FILE  = BASE_DIR / "certs" / "server.key"

SUPPORTED_GROUPS = "x25519_mlkem512:X25519MLKEM768:SecP384r1MLKEM1024"
SSLKEYLOGFILE    = "/tmp/adaptiveqke_sslkeylog.txt"
OPENSSL_CONF     = str(BASE_DIR.parent / "config" / "openssl-oqs.cnf")


def validate_files():
    if not CERT_FILE.exists():
        raise FileNotFoundError(
            f"Certificate not found: {CERT_FILE}\n"
            f"Run ./generate_certs.sh to create it."
        )
    if not KEY_FILE.exists():
        raise FileNotFoundError(
            f"Private key not found: {KEY_FILE}\n"
            f"Run ./generate_certs.sh to create it."
        )


def start_rtt_probe_server(host: str = "127.0.0.1",
                           port: int = RTT_PROBE_PORT,
                           ready_event: threading.Event | None = None):
    """
    TCP sink for the RTT probe.

    ready_event: set once listening, or immediately on a bind failure,
    so a blocked caller doesn't hang. Used by experiment.py from a
    background thread.
    """
    def _handle(conn: socket.socket):
        try:
            while True:
                data = conn.recv(65536)
                if not data:
                    break
        except Exception:
            pass
        finally:
            try: conn.close()
            except Exception: pass

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((host, port))
    except OSError as e:
        print(f"[server] FATAL: cannot bind RTT probe server to {host}:{port} — {e}")
        print(f"[server] Kill any leftover process: sudo fuser -k {port}/tcp")
        if ready_event is not None:
            ready_event.set()
        return
    srv.listen(20)

    print(f"[server] RTT probe server listening on {host}:{port}")
    if ready_event is not None:
        ready_event.set()

    while True:
        try:
            conn, _ = srv.accept()
        except Exception:
            break
        threading.Thread(target=_handle, args=(conn,), daemon=True).start()


def start_tls_server(stdout=None, stderr=None):
    """
    Launch the OQS-OpenSSL s_server subprocess and return its Popen.

    stdout/stderr pass straight to subprocess.Popen: None (inherit) for
    standalone use, or DEVNULL from experiment.py to keep multi-trial
    logs clean.
    """
    validate_files()

    env = os.environ.copy()
    env["SSLKEYLOGFILE"] = SSLKEYLOGFILE
    env["OPENSSL_CONF"]  = OPENSSL_CONF

    cmd = [
        "openssl", "s_server",
        "-accept",   str(TLS_PORT),
        "-cert",     str(CERT_FILE),
        "-key",      str(KEY_FILE),
        "-tls1_3",
        "-groups",   SUPPORTED_GROUPS,
        "-provider", "oqsprovider",
        "-provider", "default",
        "-quiet",
        "-no_ticket",
    ]

    print("[server] Starting OQS-OpenSSL TLS 1.3 server")
    print(f"[server] TLS port:        {TLS_PORT}")
    print(f"[server] Certificate:     {CERT_FILE}")
    print(f"[server] Key:             {KEY_FILE}")
    print(f"[server] Supported groups: {SUPPORTED_GROUPS}")
    print(f"[server] SSLKEYLOGFILE:   {SSLKEYLOGFILE}")

    return subprocess.Popen(cmd, env=env, stdout=stdout, stderr=stderr)


if __name__ == "__main__":
    threading.Thread(target=start_rtt_probe_server, daemon=True).start()

    tls_server = None
    try:
        tls_server = start_tls_server()
        tls_server.wait()
    except KeyboardInterrupt:
        print("\n[server] Stopping...")
        if tls_server is not None:
            try:
                tls_server.send_signal(signal.SIGINT)
                tls_server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                tls_server.kill()
        sys.exit(0)
