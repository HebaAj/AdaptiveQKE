"""
AdaptiveQKE Results
=====================
Writes results.csv and crypto_latency.csv as the experiment runs. Both
are the actual deliverable -- write-only from this project's own code;
nothing here reads them back in.
"""

import csv
from datetime import datetime
from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

_RUN_TS             = datetime.now().strftime('%Y%m%d_%H%M%S')
RESULTS_FILE        = RESULTS_DIR / f"results_{_RUN_TS}.csv"
CRYPTO_LATENCY_FILE = RESULTS_DIR / f"crypto_latency_{_RUN_TS}.csv"

CSV_COLUMNS = [
    "enforced_profile",
    "classified_profile",
    "cpu_share_pct",
    "mem_limit_mb",
    "network_profile",
    "classified_network",
    "probed_rtt_ms",
    "probe_cost_ms",
    "policy_cost_ms",
    "config",
    "trial",
    "exec_order",
    "requested_group",
    "success",
    "handshake_latency_ms",
    "wire_latency_ms",
    "cpu_time_ms",
    "handshake_size_bytes",
    "handshake_c2s_bytes",
    "handshake_s2c_bytes",
]

CRYPTO_LATENCY_COLUMNS = [
    "device_profile", "group", "trial", "exec_order",
    "handshake_latency_ms", "wire_latency_ms", "handshake_size_bytes", "success",
]


def init_csv():
    if not RESULTS_FILE.exists():
        with open(RESULTS_FILE, "w", newline="") as f:
            csv.DictWriter(f, fieldnames=CSV_COLUMNS).writeheader()
        print(f"[results] Results file: {RESULTS_FILE}")


def append_row(row: dict):
    with open(RESULTS_FILE, "a", newline="") as f:
        csv.DictWriter(f, fieldnames=CSV_COLUMNS).writerow(row)


def init_crypto_latency_csv():
    with open(CRYPTO_LATENCY_FILE, "w", newline="") as f:
        csv.DictWriter(f, fieldnames=CRYPTO_LATENCY_COLUMNS).writeheader()


def append_crypto_latency_row(row: dict):
    with open(CRYPTO_LATENCY_FILE, "a", newline="") as f:
        csv.DictWriter(f, fieldnames=CRYPTO_LATENCY_COLUMNS).writerow(row)
