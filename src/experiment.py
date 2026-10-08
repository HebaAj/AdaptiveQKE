"""
AdaptiveQKE Experiment Orchestrator
=====================================
Runs the full evaluation: 3 device profiles × 3 network profiles ×
4 configurations × 50 trials = 1,800 handshake measurements.

Network/device profile enforcement is in profile_enforcement.py, CSV
output in results.py; this file owns server lifecycle, per-trial
execution, and orchestration.

Records both handshake_latency_ms (client-side, corruptible by CFS
throttling) and wire_latency_ms (proxy-measured, authoritative under
throttling -- see metrics.py), plus classified_profile/classified_network
next to enforced_profile/network_profile for comparison (see
policy_engine.py). Results saved to ../results/results_YYYYMMDD_HHMMSS.csv.
"""

import argparse
import json
import os
import random
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from policy_engine import select_group, classify_device, GROUP_512, GROUP_768, GROUP_1024
from tls_client import run_handshake
from context_probe import collect_context
from tls_server import (
    start_tls_server, start_rtt_probe_server,
    TLS_PORT, RTT_PROBE_PORT, OPENSSL_CONF,
)
import metrics

from profile_enforcement import (
    apply_network_profile, clear_network_profile, ensure_bbr,
    CGROUP_NAME, setup_cgroup, teardown_cgroup,
)
from results import (
    RESULTS_FILE, CRYPTO_LATENCY_FILE,
    init_csv, append_row,
    init_crypto_latency_csv, append_crypto_latency_row,
)

# Ensures OPENSSL_CONF is set in THIS process's environment too, not just
# inside the generated runner scripts (which set it themselves for their
# cgexec'd child) -- covers direct run_handshake() calls made in this
# process, e.g. _start_tls_server_process()'s readiness check.
os.environ["OPENSSL_CONF"] = OPENSSL_CONF


# ---------------------------------------------------------------------------
# Experiment configuration
# ---------------------------------------------------------------------------

TRIALS    = 50
SERVER_IP = "127.0.0.1"
SEED      = 20260719   # seeds the per-condition trial-order shuffle

DEVICE_PROFILES = [
    {"name": "High-performance", "cpu_quota": None,  "mem_limit": None},
    {"name": "Mid-range",        "cpu_quota": 25000, "mem_limit": 128 },
    {"name": "Constrained",      "cpu_quota": 10000, "mem_limit": 32  },
]

NETWORK_PROFILES = [
    {"name": "Low-latency",  "delay_ms": 10, "rate_mbit": 100, "loss_pct": 0.0},
    {"name": "Moderate",     "delay_ms": 35, "rate_mbit": 15,  "loss_pct": 0.5},
    {"name": "High-latency", "delay_ms": 60, "rate_mbit": 3,   "loss_pct": 2.0},
]

CONFIGURATIONS = [
    {"name": "Adaptive",    "group": None},
    {"name": "Static-512",  "group": GROUP_512},
    {"name": "Static-768",  "group": GROUP_768},
    {"name": "Static-1024", "group": GROUP_1024},
]


# ---------------------------------------------------------------------------
# Servers
# ---------------------------------------------------------------------------

def _start_tls_server_process():
    """Spawn the TLS server process and wait until it accepts connections
    and completes a real handshake -- a fixed sleep was not reliable
    under system load."""
    tls_proc = start_tls_server(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    deadline = time.time() + 45.0
    while time.time() < deadline:
        if tls_proc.poll() is not None:
            raise RuntimeError(
                f"TLS server exited immediately (code {tls_proc.returncode})."
            )
        try:
            s = socket.create_connection((SERVER_IP, TLS_PORT), timeout=0.5)
            s.close()
        except OSError:
            time.sleep(0.1)
            continue
        result = run_handshake(GROUP_512)
        if result.get("success"):
            return tls_proc
        time.sleep(0.1)

    tls_proc.kill()
    raise RuntimeError(
        f"TLS server (pid={tls_proc.pid}) never accepted on :{TLS_PORT}."
    )


def start_servers():
    rtt_ready = threading.Event()
    threading.Thread(
        target=start_rtt_probe_server,
        kwargs=dict(host=SERVER_IP, port=RTT_PROBE_PORT, ready_event=rtt_ready),
        daemon=True,
    ).start()
    if not rtt_ready.wait(timeout=3.0):
        raise RuntimeError(f"RTT probe server on :{RTT_PROBE_PORT} never became ready")

    tls_proc = _start_tls_server_process()

    try:
        s = socket.create_connection((SERVER_IP, RTT_PROBE_PORT), timeout=2.0)
        s.close()
    except OSError as e:
        tls_proc.kill()
        raise RuntimeError(
            f"RTT probe on :{RTT_PROBE_PORT} not reachable after starting — {e}"
        )

    print(f"[server] TLS server up (pid={tls_proc.pid})")
    print(f"[server] RTT probe up on :{RTT_PROBE_PORT}")
    return tls_proc


def _terminate(proc, term_timeout: float = 5.0, kill_timeout: float = 2.0):
    """SIGTERM, then SIGKILL if it doesn't exit in time. No-op if already exited."""
    if not proc or proc.poll() is not None:
        return
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=term_timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        try: proc.wait(timeout=kill_timeout)
        except subprocess.TimeoutExpired: pass


def restart_tls_server(tls_proc):
    """Kill the current TLS server and start a fresh one. Returns the new process."""
    _terminate(tls_proc)
    new_proc = _start_tls_server_process()
    print(f"[server] TLS server restarted (pid={new_proc.pid})")
    return new_proc


def stop_servers(tls_proc):
    _terminate(tls_proc)
    print("[server] TLS server stopped")


def _server_ok(tls_proc) -> bool:
    """Return True iff the TLS server process is alive and its TCP port is reachable."""
    if tls_proc.poll() is not None:
        return False
    try:
        s = socket.create_connection((SERVER_IP, TLS_PORT), timeout=2.0)
        s.close()
        return True
    except OSError:
        return False


def _ensure_healthy(tls_proc, context: str = ""):
    """Restart the TLS server if it's not currently reachable."""
    if _server_ok(tls_proc):
        return tls_proc
    if context:
        print(f"[server] proactive restart before {context}")
    return restart_tls_server(tls_proc)


# ---------------------------------------------------------------------------
# Per-trial execution
# ---------------------------------------------------------------------------

def _runner_script(selected_group: str, proxy_port: int) -> str:
    """
    Generate a self-contained script that runs one handshake through the
    proxy, for cgexec'd cgroup-constrained trials. Prints "HSCOMPLETE" on
    completion, blocks on stdin for "MARKED" or a 10s timeout (see
    run_one_trial()), then prints one JSON result line.

    CPU time is resource.getrusage() deltas around run_handshake(), so
    it's unaffected by cgroup scheduling. cpu_share_pct/mem_limit_mb are
    read here (inside the enforced cgroup) before that measurement
    window starts.
    """
    return f"""
import json, os, resource, sys
os.environ["OPENSSL_CONF"] = {OPENSSL_CONF!r}
sys.path.insert(0, {str(BASE_DIR)!r})
from tls_client import run_handshake
from context_probe import read_raw_cgroup_limits

cpu_share_pct, mem_limit_mb = read_raw_cgroup_limits()

r0_self     = resource.getrusage(resource.RUSAGE_SELF)
r0_children = resource.getrusage(resource.RUSAGE_CHILDREN)

result = run_handshake(
    selected_group     = {selected_group!r},
    server_ip          = "127.0.0.1",
    port               = {proxy_port},
    on_complete_marker = "HSCOMPLETE",
    wait_for_ack       = True,
)

r1_self     = resource.getrusage(resource.RUSAGE_SELF)
r1_children = resource.getrusage(resource.RUSAGE_CHILDREN)

cpu_time_ms = round(
    ((r1_self.ru_utime     - r0_self.ru_utime) +
     (r1_self.ru_stime     - r0_self.ru_stime) +
     (r1_children.ru_utime - r0_children.ru_utime) +
     (r1_children.ru_stime - r0_children.ru_stime)) * 1000,
    3,
)

result["cpu_time_ms"] = cpu_time_ms
result["cpu_share_pct"] = cpu_share_pct
result["mem_limit_mb"] = mem_limit_mb
sys.stdout.write(json.dumps(result) + "\\n")
sys.stdout.flush()
"""


def run_one_trial(dev_profile: dict, selected_group: str,
                  pin_cpu: int | None = None,
                  net_delay_ms: float = 0.0,
                  timeout: float = 20.0) -> dict:
    """
    Execute a single trial under the given device profile. Returns a dict
    with handshake_latency_ms, cpu_time_ms, handshake_size_bytes, success,
    etc. Creates a fresh byte-counting proxy between the client subprocess
    and the real TLS server.

    pin_cpu: pin the client to one CPU core via taskset (crypto phases).
    net_delay_ms: the network profile's one-way delay, 0.0 on plain
    loopback; sizes the quiescence wait below.
    timeout: seconds to wait for the runner subprocess (raise for slower
    startup, e.g. a heavily-throttled cgroup).
    """
    proxy = metrics.ByteCountingProxy(
        upstream_host = "127.0.0.1",
        upstream_port = TLS_PORT,
    )
    proxy.start()
    proxy_port = proxy.listen_port

    handshake_result: dict = {}

    try:
        runner_code = _runner_script(selected_group, proxy_port)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as tmp:
            tmp.write(runner_code)
            tmp_path = tmp.name

        json_line: str = ""
        try:
            cmd = [sys.executable, tmp_path]
            if pin_cpu is not None:
                cmd = ["taskset", "-c", str(pin_cpu)] + cmd
            if dev_profile["cpu_quota"] is not None:
                cmd = ["sudo", "cgexec", "-g", f"cpu,memory:{CGROUP_NAME}"] + cmd
            proc = subprocess.Popen(
                cmd,
                stdin  = subprocess.PIPE,
                stdout = subprocess.PIPE,
                stderr = subprocess.PIPE,
                text   = True,
                bufsize = 1,
            )

            # HSCOMPLETE -> wait for wire quiescence (so a delayed/
            # throttled final record isn't missed), snapshot the proxy,
            # then ack via stdin ("MARKED") so the runner sends its TLS
            # shutdown. idle_s: 0.40s floor absorbs a TCP min-RTO
            # retransmit; 4x one-way delay covers propagation.
            marked = False
            try:
                for line in iter(proc.stdout.readline, ""):
                    line = line.rstrip()
                    if line == "HSCOMPLETE" and not marked:
                        idle_s = max(0.40, 4 * (net_delay_ms / 1000.0))
                        proxy.wait_quiescent_and_mark(idle_s=idle_s)
                        marked = True
                        try:
                            proc.stdin.write("MARKED\n")
                            proc.stdin.flush()
                        except (BrokenPipeError, OSError):
                            pass
                        continue
                    if line.startswith("{") and line.endswith("}"):
                        json_line = line
            except Exception:
                pass

            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                try: proc.wait(timeout=2)
                except subprocess.TimeoutExpired: pass

            # Surface cgexec/sudo/Python errors when no JSON was produced.
            if not json_line:
                try:
                    _err = proc.stderr.read(500)
                    if _err:
                        print(f"  [runner-err] {_err.strip()!r}", flush=True)
                except Exception:
                    pass

            # Defensive: marker was somehow missed (process died early) --
            # snap the proxy now so we still get a number.
            if not marked:
                proxy.mark_handshake_done()
        finally:
            try: os.unlink(tmp_path)
            except Exception: pass

        try:
            handshake_result = json.loads(json_line) if json_line else {}
        except Exception:
            handshake_result = {}
        if not handshake_result:
            handshake_result = {
                "selected_group":       selected_group,
                "success":              False,
                "handshake_latency_ms": None,
                "error":                "runner produced no JSON output",
            }
    finally:
        proxy.wait_closed(timeout=10)
        proxy.stop()

    breakdown = proxy.handshake_breakdown

    return {
        "handshake_latency_ms": handshake_result.get("handshake_latency_ms"),
        "wire_latency_ms":      proxy.wire_latency_ms,
        "success":              handshake_result.get("success", False),
        "cpu_time_ms":          handshake_result.get("cpu_time_ms", 0.0),
        "cpu_share_pct":        handshake_result.get("cpu_share_pct"),
        "mem_limit_mb":         handshake_result.get("mem_limit_mb"),
        "handshake_size_bytes": breakdown["total"],
        "handshake_c2s_bytes":  breakdown["c2s"],
        "handshake_s2c_bytes":  breakdown["s2c"],
        "error":                handshake_result.get("error"),
    }


def _choose_group(dev: dict, cfg: dict):
    """
    Pick the group for one trial. Static configs force cfg["group"]
    directly. Adaptive configs probe the network and pass the enforced
    profile's mem_limit_mb through select_group().

    Returns (selected_group, probed_rtt_ms, classified_network,
    probe_cost_ms, policy_cost_ms). The cost fields are None for static
    configs, since no probing or policy evaluation happens.
    """
    if cfg["group"] is not None:
        return cfg["group"], None, None, None, None

    t0 = time.perf_counter_ns()
    ctx = collect_context(server_ip=SERVER_IP)
    t1 = time.perf_counter_ns()
    probe_cost_ms = round((t1 - t0) / 1_000_000.0, 4)

    probed_rtt = ctx["rtt_ms"]

    t2 = time.perf_counter_ns()
    selection = select_group({
        "rtt_ms":        probed_rtt,
        "cpu_share_pct": None if dev["cpu_quota"] is None else dev["cpu_quota"] / 1000.0,
        "mem_limit_mb":  dev["mem_limit"],
    })
    t3 = time.perf_counter_ns()
    policy_cost_ms = round((t3 - t2) / 1_000_000.0, 4)

    return selection.group, probed_rtt, selection.network_candidate, probe_cost_ms, policy_cost_ms


def _build_exec_order(seed: int = SEED) -> list[tuple[dict, int]]:
    """
    Build the (config, trial) execution order for one (device, network)
    condition: all 4 configs x TRIALS, interleaved so that any systematic
    drift over a condition's run (thermal, cgroup warm-up, etc.) doesn't
    confound one config more than another.
    """
    order = [(cfg, trial) for cfg in CONFIGURATIONS for trial in range(1, TRIALS + 1)]
    random.Random(seed).shuffle(order)
    return order


def _build_crypto_exec_order(groups: list[str],
                             seed: int = SEED) -> list[tuple[str, int]]:
    """
    Build the (group, trial) execution order for the crypto-latency
    phase: all groups x TRIALS, interleaved with the same fixed seed as
    the main loop. Running each group as a contiguous block confounds
    group with time -- any drift over the phase (thermal, scheduler,
    cgroup warm-up) is attributed entirely to whichever group happened
    to be running while it occurred. Interleaving removes the confound;
    exec_order is recorded so drift can afterwards be tested for
    directly rather than assumed absent.
    """
    order = [(grp, trial) for grp in groups for trial in range(1, TRIALS + 1)]
    random.Random(seed).shuffle(order)
    return order


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run_experiment():
    init_csv()
    orig_cc = ensure_bbr()
    tls_proc = start_servers()

    try:
        total = len(DEVICE_PROFILES) * len(NETWORK_PROFILES)
        cond_n = 0

        for dev in DEVICE_PROFILES:
            setup_cgroup(dev)

            for net in NETWORK_PROFILES:
                apply_network_profile(net)
                time.sleep(1)

                cond_n += 1
                exec_order = _build_exec_order()
                print(f"\n[experiment] Condition {cond_n}/{total}: "
                      f"device={dev['name']} | network={net['name']} "
                      f"({len(CONFIGURATIONS)} configs x {TRIALS} trials, "
                      f"interleaved, seed={SEED})")

                for pos, (cfg, trial) in enumerate(exec_order):
                    tls_proc = _ensure_healthy(
                        tls_proc,
                        f"{dev['name']}/{net['name']}/{cfg['name']} trial {trial}",
                    )

                    selected_group, probed_rtt, classified_network, \
                        probe_cost_ms, policy_cost_ms = _choose_group(dev, cfg)

                    t = run_one_trial(dev, selected_group,
                                       net_delay_ms=net["delay_ms"])

                    if not t["success"]:
                        print(f"  [server] {cfg['name']} trial {trial} failed — "
                              f"restarting TLS server")
                        tls_proc = restart_tls_server(tls_proc)

                    # Uses this trial's actually-measured values, not
                    # the pre-trial estimate _choose_group() used.
                    classified_profile = classify_device(
                        t.get("cpu_share_pct"), t.get("mem_limit_mb")
                    )
                    append_row({
                        "enforced_profile":     dev["name"],
                        "classified_profile":   classified_profile,
                        "cpu_share_pct":        t.get("cpu_share_pct"),
                        "mem_limit_mb":         t.get("mem_limit_mb"),
                        "network_profile":      net["name"],
                        "classified_network":   classified_network,
                        "probed_rtt_ms":        probed_rtt,
                        "probe_cost_ms":        probe_cost_ms,
                        "policy_cost_ms":       policy_cost_ms,
                        "config":               cfg["name"],
                        "trial":                trial,
                        "exec_order":           pos,
                        "requested_group":      selected_group,
                        "success":              t["success"],
                        "handshake_latency_ms": t["handshake_latency_ms"],
                        "wire_latency_ms":      t["wire_latency_ms"],
                        "cpu_time_ms":          t["cpu_time_ms"],
                        "handshake_size_bytes": t["handshake_size_bytes"],
                        "handshake_c2s_bytes":  t["handshake_c2s_bytes"],
                        "handshake_s2c_bytes":  t["handshake_s2c_bytes"],
                    })

                    if (pos + 1) % 10 == 0:
                        probe_info = (
                            f"rtt={probed_rtt}ms | "
                            if probed_rtt is not None else ""
                        )
                        print(f"  [{pos + 1}/{len(exec_order)}] "
                              f"config={cfg['name']} trial={trial}/{TRIALS} — "
                              f"{probe_info}"
                              f"group={selected_group} | "
                              f"latency={t['handshake_latency_ms']}ms | "
                              f"size={t['handshake_size_bytes']}B | "
                              f"cpu={t['cpu_time_ms']}ms | "
                              f"ok={t['success']}")

            teardown_cgroup(dev)

        clear_network_profile()
        print(f"\n[experiment] Done. Results: {RESULTS_FILE}")

    finally:
        clear_network_profile()
        stop_servers(tls_proc)
        subprocess.run(["sudo", "cgdelete", "-g", f"cpu,memory:{CGROUP_NAME}"],
                       capture_output=True)
        subprocess.run(
            ["sudo", "sysctl", "-w", f"net.ipv4.tcp_congestion_control={orig_cc}"],
            capture_output=True,
        )
        print(f"[bbr] restored congestion control = {orig_cc}")


# ---------------------------------------------------------------------------
# Near-zero-network handshake latency (crypto-dominated)
# ---------------------------------------------------------------------------

def run_crypto_latency_phase():
    """
    Near-zero-network (plain loopback, no tc-netem) TLS handshake latency
    per device profile × group -- with no delay or rate limit, latency is
    dominated by cryptographic cost and OS/scheduling overhead.

    Per (device, group): 5 warm-up trials discarded, then TRIALS measured,
    pinned to CPU 0 via taskset -c 0. Raw rows go to CRYPTO_LATENCY_FILE.
    """
    print("\n" + "=" * 64)
    print("[crypto-latency] Near-zero-network handshake latency")
    print("=" * 64)

    # Guarantee no stale qdisc leaks in or out of this phase
    clear_network_profile()
    time.sleep(0.5)

    tls_proc = start_servers()
    init_crypto_latency_csv()

    GROUPS = [GROUP_512, GROUP_768, GROUP_1024]
    WARMUP = 5
    success_count: dict[tuple[str, str], int] = {}

    try:
        for dev in DEVICE_PROFILES:
            setup_cgroup(dev)

            # Warm up every group before any measurement, so that no group
            # is measured while the cgroup and page cache are still cold.
            for grp in GROUPS:
                success_count[(dev["name"], grp)] = 0
                print(f"[crypto-latency] {dev['name']} x {grp}: {WARMUP} warm-up")
                for _ in range(WARMUP):
                    tls_proc = _ensure_healthy(tls_proc)
                    run_one_trial(dev, grp, pin_cpu=0)

            exec_order = _build_crypto_exec_order(GROUPS)
            print(f"\n[crypto-latency] {dev['name']}: "
                  f"{len(GROUPS)} groups x {TRIALS} trials, "
                  f"interleaved, seed={SEED}, taskset -c 0")

            for pos, (grp, trial) in enumerate(exec_order):
                key = (dev["name"], grp)
                tls_proc = _ensure_healthy(tls_proc)
                t = run_one_trial(dev, grp, pin_cpu=0)

                append_crypto_latency_row({
                    "device_profile":       dev["name"],
                    "group":                grp,
                    "trial":                trial,
                    "exec_order":           pos,
                    "handshake_latency_ms": t["handshake_latency_ms"],
                    "wire_latency_ms":      t["wire_latency_ms"],
                    "handshake_size_bytes": t["handshake_size_bytes"],
                    "success":              t["success"],
                })

                if t["success"]:
                    success_count[key] += 1
                else:
                    tls_proc = restart_tls_server(tls_proc)

            for grp in GROUPS:
                print(f"  -> {grp}: "
                      f"{success_count[(dev['name'], grp)]}/{TRIALS} successful")

            teardown_cgroup(dev)

        print(f"\n[crypto-latency] Written: {CRYPTO_LATENCY_FILE}")

    finally:
        stop_servers(tls_proc)
        clear_network_profile()  # ensure loopback stays clean after this phase


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    _ap = argparse.ArgumentParser(
        description="AdaptiveQKE experiment + near-zero-network crypto latency",
    )
    _ap.add_argument(
        "--crypto-only", action="store_true",
        help="Skip the 1800-trial main loop; run only the near-zero-network "
             "latency phase.",
    )
    _args = _ap.parse_args()

    if _args.crypto_only:
        run_crypto_latency_phase()
    else:
        run_experiment()
        run_crypto_latency_phase()
