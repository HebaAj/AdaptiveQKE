"""
AdaptiveQKE Context Probe
==========================
Measures rtt_ms, cpu_share_pct, and mem_limit_mb — the raw inputs
policy_engine.select_group() classifies into a hybrid group.
"""

import queue
import socket
import threading
import time

from tls_server import RTT_PROBE_PORT


RTT_ROUNDS      = 3
RTT_TIMEOUT     = 2.0


# ===========================================================================
# RTT (round-trip time)
# ===========================================================================

def tcp_ping(server_ip: str = "127.0.0.1", *, port: int,
             rounds: int = RTT_ROUNDS) -> float:
    """
    Estimate RTT via TCP three-way handshake time. Rounds are launched
    concurrently and the FIRST SUCCESSFUL one to return is used. Because
    the rounds start together, the first to complete is also the minimum
    sample -- the estimate is the same propagation floor as before, but
    the probe now also *costs* that minimum instead of blocking until
    the slowest round finishes. A round whose SYN is lost can no longer
    hold the probe open for the full RTT_TIMEOUT.

    Only a successful round may return early. A refused connection
    completes almost instantly, and returning it would read a broken
    path as a very low RTT -- i.e. as the best possible network. Failed
    rounds therefore record RTT_TIMEOUT and are skipped; if every round
    fails, the probe reads as high RTT so that a broken path degrades
    toward the conservative candidate rather than the strongest one.
    """
    results: queue.Queue = queue.Queue()

    def _one_round():
        start = time.perf_counter()
        try:
            sock = socket.create_connection((server_ip, port), timeout=RTT_TIMEOUT)
            sock.close()
            results.put((True, (time.perf_counter() - start) * 1000.0))
        except Exception:
            results.put((False, 1000.0 * RTT_TIMEOUT))

    # Daemon threads: a straggler must not keep the process alive after
    # a faster round has already answered.
    for _ in range(rounds):
        threading.Thread(target=_one_round, daemon=True).start()

    for _ in range(rounds):
        try:
            ok, sample_ms = results.get(timeout=RTT_TIMEOUT + 0.5)
        except queue.Empty:
            break
        if ok:
            return round(sample_ms, 3)

    return round(1000.0 * RTT_TIMEOUT, 3)


# ===========================================================================
# cgroup v2 limit reading
# ===========================================================================

def _read_cgroup_own_path() -> str | None:
    """This process's cgroup v2 path (after "0::" in /proc/self/cgroup), or None."""
    try:
        with open("/proc/self/cgroup", "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("0::"):
                    return line[len("0::"):]
    except Exception:
        pass
    return None


def _read_cgroup_file(cgroup_path: str, filename: str) -> str | None:
    """Read one file under /sys/fs/cgroup/<cgroup_path>/. None on any failure."""
    try:
        with open(f"/sys/fs/cgroup{cgroup_path}/{filename}", "r") as f:
            return f.read().strip()
    except Exception:
        return None


def _parse_cpu_max(raw: str | None) -> float | None:
    """
    Parse cgroup v2 cpu.max ("max" or "QUOTA PERIOD") into a core fraction.
    inf = unlimited, None = missing/unparsable (not the same thing).
    """
    if raw is None:
        return None
    parts = raw.split()
    if not parts:
        return None
    if parts[0] == "max":
        return float("inf")
    if len(parts) != 2:
        return None
    try:
        quota, period = float(parts[0]), float(parts[1])
        return quota / period if period > 0 else None
    except ValueError:
        return None


def _parse_memory_max(raw: str | None) -> float | None:
    """
    Parse cgroup v2 memory.max ("max" or a byte count) into MB.
    inf = unlimited, None = missing/unparsable (not the same thing).
    """
    if raw is None:
        return None
    raw = raw.strip()
    if raw == "max":
        return float("inf")
    try:
        return float(raw) / (1024 * 1024)
    except ValueError:
        return None


def read_raw_cgroup_limits() -> tuple[float | None, float | None]:
    """
    Return (cpu_share_pct, mem_limit_mb) from this process's own cgroup v2
    limits, unclassified. cpu_share_pct is 0-100; both are None if
    unlimited or unreadable.
    """
    cgroup_path = _read_cgroup_own_path()
    if cgroup_path is None:
        return None, None

    cpu_frac = _parse_cpu_max(_read_cgroup_file(cgroup_path, "cpu.max"))
    mem_mb   = _parse_memory_max(_read_cgroup_file(cgroup_path, "memory.max"))

    cpu_share_pct = None if cpu_frac in (None, float("inf")) else cpu_frac * 100.0
    mem_limit_mb  = None if mem_mb in (None, float("inf")) else mem_mb
    return cpu_share_pct, mem_limit_mb


# ===========================================================================
# Public entry point
# ===========================================================================

def collect_context(server_ip: str = "127.0.0.1") -> dict:
    """
    Probe rtt_ms, cpu_share_pct, and mem_limit_mb — ready to pass straight
    to policy_engine.select_group().
    """
    cpu_share_pct, mem_limit_mb = read_raw_cgroup_limits()
    return {
        # Probed against RTT_PROBE_PORT, not the real TLS server port: a
        # bare TCP connect there never sends a ClientHello, which blocks
        # s_server and starves subsequent handshakes.
        "rtt_ms":         tcp_ping(server_ip, port=RTT_PROBE_PORT),
        "cpu_share_pct":  cpu_share_pct,
        "mem_limit_mb":   mem_limit_mb,
    }
