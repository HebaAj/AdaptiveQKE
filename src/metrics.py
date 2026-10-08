"""
AdaptiveQKE Metrics
====================
ByteCountingProxy measures handshake size and wire_latency_ms from
outside any cgroup, so client-side cgroup throttling (which can corrupt
tls_client.py's handshake_latency_ms) can't affect it. See the class
docstring below.
"""

import socket
import threading
import time
from typing import Optional


# ---------------------------------------------------------------------------
# Tuning constants
# ---------------------------------------------------------------------------

PROXY_RECV_BUFSIZE = 65536
PROXY_BACKLOG      = 1


# ===========================================================================
# Handshake size measurement
# ===========================================================================

class ByteCountingProxy:
    """
    A one-shot TCP relay that sits between the TLS client and the TLS
    server, counts every byte that flows in each direction, and exposes
    a checkpoint so the experiment can snapshot the byte count at the
    exact moment the handshake completes (before any close_notify or
    application data).

    Architecture:

        TLS client  ──TCP──►  proxy ──TCP──►  TLS server
                              (counts)

    Why a proxy instead of tshark on loopback:

      • tshark requires a startup race window in which the BPF filter
        is not yet attached but the pcap header has already been
        written — on loopback, the entire handshake can finish inside
        that window, producing zero-byte captures.

      • A user-space TCP relay observes every byte directly. No race,
        no decryption needed, no SSLKEYLOGFILE plumbing.
    """

    def __init__(self,
                 upstream_host: str = '127.0.0.1',
                 upstream_port: int = 4433):
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port

        # Live counters (updated by forwarding threads)
        self._c2s_bytes = 0
        self._s2c_bytes = 0
        self._counter_lock = threading.Lock()

        # Snapshot taken when mark_handshake_done() is called
        self._snapshot: Optional[tuple[int, int]] = None

        # Wire-level timing (see wire_latency_ms property). Updated inside
        # _forward() under _counter_lock, alongside the byte counters.
        self._first_c2s_chunk_time: Optional[float] = None  # ClientHello leaving the client
        self._last_chunk_time:      Optional[float] = None  # most recent relayed chunk, either direction
        self._marked_last_time:     Optional[float] = None  # _last_chunk_time snapshot at mark_handshake_done()

        # State
        self._listen_sock: Optional[socket.socket]   = None
        self._client_sock: Optional[socket.socket]   = None
        self._upstream_sock: Optional[socket.socket] = None
        self._listen_port: Optional[int]             = None

        self._accept_thread: Optional[threading.Thread] = None
        self._c2s_thread:    Optional[threading.Thread] = None
        self._s2c_thread:    Optional[threading.Thread] = None

        self._closed_event = threading.Event()

    # -- public API ----------------------------------------------------------

    def start(self, listen_port: int = 0) -> None:
        """Bind a listening socket (ephemeral port by default) and begin
        accepting one inbound connection in a background thread."""
        self._listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listen_sock.bind(('127.0.0.1', listen_port))
        self._listen_sock.listen(PROXY_BACKLOG)
        self._listen_port = self._listen_sock.getsockname()[1]

        self._accept_thread = threading.Thread(
            target=self._accept_one,
            daemon=True,
        )
        self._accept_thread.start()

    @property
    def listen_port(self) -> int:
        if self._listen_port is None:
            raise RuntimeError("Proxy not started")
        return self._listen_port

    def mark_handshake_done(self) -> None:
        """Snapshot the current byte counters. Call this the moment the
        client signals that the TLS handshake has completed."""
        with self._counter_lock:
            self._snapshot = (self._c2s_bytes, self._s2c_bytes)
            self._marked_last_time = self._last_chunk_time

    def wait_quiescent_and_mark(self,
                                idle_s: float,
                                timeout_s: float = 3.0,
                                poll_s: float = 0.005) -> bool:
        """
        Block until the wire is silent for idle_s seconds, then mark
        (marks anyway if timeout_s expires first; return value says
        whether quiescence was genuine).

        Silence only counts from when this call begins, not before --
        otherwise a throttled client could mark before its final bytes
        arrive. Caller must keep the client blocked until marked.
        """
        t_poll_start = time.perf_counter()
        deadline = t_poll_start + timeout_s
        while True:
            now = time.perf_counter()
            with self._counter_lock:
                last = self._last_chunk_time
            quiet_since = t_poll_start if last is None else max(last, t_poll_start)
            if now - quiet_since >= idle_s:
                self.mark_handshake_done()
                return True
            if now >= deadline:
                self.mark_handshake_done()
                return False
            time.sleep(poll_s)

    def wait_closed(self, timeout: float = 15.0) -> bool:
        """Block until both forwarding threads have finished."""
        return self._closed_event.wait(timeout)

    @property
    def handshake_breakdown(self) -> dict:
        """c2s/s2c/total wire bytes at the mark. All -1 if never marked."""
        if self._snapshot is None:
            return {"c2s": -1, "s2c": -1, "total": -1}
        return {
            "c2s":   self._snapshot[0],
            "s2c":   self._snapshot[1],
            "total": self._snapshot[0] + self._snapshot[1],
        }

    @property
    def wire_latency_ms(self) -> Optional[float]:
        """
        Time from the first client->server byte to the last relayed byte
        at the mark, in ms. Unlike handshake_latency_ms, this proxy is
        never cgroup-throttled, so it isn't corrupted by CFS stalls in
        the client process.

        Accurate only if marked via wait_quiescent_and_mark() -- an
        immediate mark_handshake_done() may catch the wire before the
        client's Finished record has actually arrived.

        None if no mark was set, or no client->server byte was observed.
        """
        if self._marked_last_time is None or self._first_c2s_chunk_time is None:
            return None
        return round((self._marked_last_time - self._first_c2s_chunk_time) * 1000.0, 3)

    def stop(self) -> None:
        """Force-close all sockets and threads. Safe to call multiple times."""
        for s in (self._client_sock, self._upstream_sock, self._listen_sock):
            try:
                if s is not None:
                    s.close()
            except Exception:
                pass
        self._closed_event.set()

    # -- internals -----------------------------------------------------------

    def _accept_one(self) -> None:
        try:
            client_sock, _ = self._listen_sock.accept()
        except OSError:
            self._closed_event.set()
            return

        self._client_sock = client_sock

        # TCP_NODELAY on both legs: without it, Nagle can hold small final
        # records (the ~80B Finished flight) waiting for a netem-delayed
        # ACK, adding lag before the proxy relays them.
        try:
            client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

        # Open upstream connection to the real TLS server
        try:
            upstream_sock = socket.create_connection(
                (self.upstream_host, self.upstream_port),
                timeout=10,
            )
            upstream_sock.settimeout(None)   # keep connect timeout, remove recv timeout
            try:
                upstream_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
        except Exception:
            try: client_sock.close()
            except Exception: pass
            self._closed_event.set()
            return

        self._upstream_sock = upstream_sock

        # Spawn two forwarding threads, one per direction
        self._c2s_thread = threading.Thread(
            target=self._forward,
            args=(client_sock, upstream_sock, 'c2s'),
            daemon=True,
        )
        self._s2c_thread = threading.Thread(
            target=self._forward,
            args=(upstream_sock, client_sock, 's2c'),
            daemon=True,
        )
        self._c2s_thread.start()
        self._s2c_thread.start()

        # Wait for both to finish
        self._c2s_thread.join()
        self._s2c_thread.join()

        # Final cleanup
        try: client_sock.close()
        except Exception: pass
        try: upstream_sock.close()
        except Exception: pass

        self._closed_event.set()

    def _forward(self, src: socket.socket, dst: socket.socket, direction: str) -> None:
        while True:
            try:
                data = src.recv(PROXY_RECV_BUFSIZE)
            except (OSError, ConnectionError):
                break
            if not data:
                break
            # Timestamp BEFORE sendall too, same reasoning as the byte
            # counters: mark_handshake_done() must never race ahead of a
            # chunk that's still in flight when it reads the timestamps.
            t = time.perf_counter()
            with self._counter_lock:
                if direction == 'c2s':
                    self._c2s_bytes += len(data)
                    if self._first_c2s_chunk_time is None:
                        self._first_c2s_chunk_time = t
                else:
                    self._s2c_bytes += len(data)
                self._last_chunk_time = t
            try:
                dst.sendall(data)
            except (OSError, ConnectionError):
                break
        # Signal EOF to the other half
        try:
            dst.shutdown(socket.SHUT_WR)
        except Exception:
            pass
