"""
AdaptiveQKE TLS Client
=======================
Runs one TLS 1.3 handshake against the OQS-OpenSSL server and times it
by parsing OpenSSL's state transitions on stderr, from ClientHello-sent
to client-side Finished-written -- excluding subprocess startup, library
loading, and connection teardown. Byte counting and CPU sampling are
handled separately by metrics.py.
"""

import os
import re
import select
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import Optional


SSLKEYLOGFILE = "/tmp/adaptiveqke_sslkeylog.txt"

# OpenSSL -state prints lines like "SSL_connect:SSLv3/TLS write client
# hello". The latency window runs from the first "write client hello"
# to the last SSL_connect: line (handshake complete).
_RE_CLIENT_HELLO     = re.compile(r"write client hello", re.IGNORECASE)
_RE_STATE_TRANSITION = re.compile(r"^SSL_connect:", re.IGNORECASE)


@dataclass
class HandshakeResult:
    selected_group:        str
    success:               bool
    handshake_latency_ms:  Optional[float]
    error:                 Optional[str] = None


def _read_stream(stream, sink: list, name: str) -> None:
    """Read a text stream line-by-line, timestamping each line."""
    try:
        for line in iter(stream.readline, ''):
            t = time.perf_counter()
            sink.append((t, name, line.rstrip()))
    except Exception:
        pass


def run_handshake(selected_group: str,
                  server_ip: str = "127.0.0.1",
                  port: int = 4433,
                  timeout: float = 15.0,
                  proxy_signal=None,
                  on_complete_marker: Optional[str] = None,
                  wait_for_ack: bool = False) -> dict:
    """
    Execute one TLS 1.3 handshake and return measurement results
    (a dict, HandshakeResult.__dict__).

    server_ip/port: with ByteCountingProxy, pass the proxy's listen_port
    here, not the real TLS server port.

    proxy_signal: optional callable invoked the instant the handshake
    completes, before the TLS shutdown is sent.

    on_complete_marker: optional string printed to stdout the instant
    the handshake completes, for signalling across a subprocess boundary.

    wait_for_ack: if True (with on_complete_marker set), block on stdin
    for one line, or a 10s timeout, before sending the TLS shutdown.
    """
    env = os.environ.copy()
    env["SSLKEYLOGFILE"] = SSLKEYLOGFILE

    cmd = [
        "stdbuf", "-eL",         # line-buffer stderr so SSL_connect: lines
                                  # arrive individually, not in one burst
        "openssl", "s_client",
        "-connect",  f"{server_ip}:{port}",
        "-groups",   selected_group,
        "-tls1_3",
        "-no_ticket",
        "-state",                # print SSL_connect: transitions to stderr
        "-verify_return_error",
    ]

    events: list[tuple[float, str, str]] = []

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=env,
        )
    except FileNotFoundError as e:
        return HandshakeResult(
            selected_group=selected_group,
            success=False,
            handshake_latency_ms=None,
            error=f"openssl not found: {e}",
        ).__dict__

    stdout_thread = threading.Thread(
        target=_read_stream, args=(proc.stdout, events, "out"), daemon=True,
    )
    stderr_thread = threading.Thread(
        target=_read_stream, args=(proc.stderr, events, "err"), daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()

    # OpenSSL prints "---" on stdout right after SSL_connect() returns
    # successfully, before any application data would be sent. Wait for
    # it, then send Q.
    handshake_done = False
    handshake_t    = None
    error_message  = None
    deadline       = time.perf_counter() + timeout

    while time.perf_counter() < deadline:
        if any(line.strip() == "---" for (_, src, line) in events if src == "out"):
            handshake_t    = time.perf_counter()
            handshake_done = True
            break
        if proc.poll() is not None:
            error_message = "openssl exited before handshake completed"
            break
        time.sleep(0.005)

    # Signal the proxy now, before any close_notify can flow.
    if handshake_done:
        if proxy_signal is not None:
            try:
                proxy_signal()
            except Exception:
                pass
        if on_complete_marker is not None:
            try:
                sys.stdout.write(on_complete_marker + "\n")
                sys.stdout.flush()
            except Exception:
                pass
            if wait_for_ack:
                try:
                    ready, _, _ = select.select([sys.stdin], [], [], 10.0)
                    if ready:
                        sys.stdin.readline()
                except Exception:
                    pass

    # Tell openssl to disconnect cleanly
    try:
        if proc.poll() is None:
            proc.stdin.write("Q\n")
            proc.stdin.flush()
    except (BrokenPipeError, OSError):
        pass

    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass

    stdout_thread.join(timeout=1)
    stderr_thread.join(timeout=1)

    # Parse timing markers
    t_clienthello: Optional[float] = None
    t_finished:    Optional[float] = None
    last_state_t:  Optional[float] = None

    for (t, src, line) in events:
        if src != "err":
            continue
        if _RE_STATE_TRANSITION.search(line):
            last_state_t = t
            if t_clienthello is None and _RE_CLIENT_HELLO.search(line):
                t_clienthello = t

    # End-of-handshake time: the last state transition before "---",
    # falling back to the "---" timestamp itself.
    if last_state_t is not None and handshake_t is not None:
        if t_clienthello is not None and last_state_t < t_clienthello:
            t_finished = handshake_t
        else:
            t_finished = last_state_t
    elif handshake_t is not None:
        t_finished = handshake_t

    handshake_latency_ms: Optional[float] = None
    if t_clienthello is not None and t_finished is not None:
        handshake_latency_ms = round((t_finished - t_clienthello) * 1000, 3)

    stdout_text = "\n".join(line for (_, src, line) in events if src == "out")

    is_tls13     = ("TLSv1.3" in stdout_text) or ("TLS_AES" in stdout_text)
    is_connected = "CONNECTED" in stdout_text
    success = bool(handshake_done and is_connected and is_tls13)

    return HandshakeResult(
        selected_group       = selected_group,
        success              = success,
        handshake_latency_ms = handshake_latency_ms,
        error                = error_message,
    ).__dict__
