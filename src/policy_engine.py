"""
AdaptiveQKE Policy Engine
==========================
The thesis's two-stage selection logic (Tables 3.2-3.4, Algorithm 1).

Stage 1 — network_candidate(): network-driven candidate determination
    RTT > 100 ms  → x25519_mlkem512
    RTT <  50 ms  → SecP384r1MLKEM1024
    otherwise     → X25519MLKEM768

Stage 2 — device_validation(): device-aware feasibility validation
    High-performance → keep candidate
    Mid-range        → cap at X25519MLKEM768
    Constrained      → always x25519_mlkem512

    Device tier is classified primarily from CPU share: on constrained
    devices the dominant ML-KEM handshake cost is computation (polynomial
    multiplication + hashing), not memory. Memory is a feasibility floor
    (can the algorithm fit at all), not the performance driver -- either
    signal can still push the tier down if it is the tighter bottleneck.

select_group() runs both stages; see its docstring for the input shape.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


# ---------------------------------------------------------------------------
# Hybrid group names (must match what OQS-OpenSSL accepts via -groups)
# ---------------------------------------------------------------------------

GROUP_512  = "x25519_mlkem512"
GROUP_768  = "X25519MLKEM768"
GROUP_1024 = "SecP384r1MLKEM1024"

ALLOWED_GROUPS = {GROUP_512, GROUP_768, GROUP_1024}

# ---------------------------------------------------------------------------
# Thresholds (Table 3.4)
# ---------------------------------------------------------------------------

T_LO = 50.0       # milliseconds
T_HI = 100.0      # milliseconds

def network_candidate(rtt_ms: float) -> str:
    if rtt_ms > T_HI:
        return GROUP_512
    if rtt_ms < T_LO:
        return GROUP_1024
    return GROUP_768

# ---------------------------------------------------------------------------
# Device-tier classification thresholds (Table 3.4)
# ---------------------------------------------------------------------------

CPU_SHARE_CONSTRAINED_PCT = 15.0   # cpu_share_pct below this -> "Constrained"
CPU_SHARE_MID_PCT         = 60.0   # cpu_share_pct below this -> "Mid-range"

MEM_LIMIT_CONSTRAINED_MB  = 64.0   # mem_limit_mb below this  -> "Constrained"
MEM_LIMIT_MID_MB          = 256.0  # mem_limit_mb below this  -> "Mid-range"

def classify_device(cpu_share_pct: float | None, mem_limit_mb: float | None) -> str:
    """
    Classify a device tier from CPU share and memory limit. CPU is the
    primary classifier -- on constrained devices the dominant ML-KEM
    handshake cost is computation (polynomial multiplication + hashing),
    not memory. Memory is a feasibility floor (can the algorithm fit at
    all), not the performance driver. Either signal can push to a more
    restrictive tier: whichever bottleneck is tighter wins.

    cpu_share_pct: CPU share in percent (0-100), or None if unrestricted/unknown.
    mem_limit_mb: memory limit in MB, or None if unrestricted/unknown.
    (None, None) classifies as "High-performance".
    """
    if (mem_limit_mb is not None and mem_limit_mb < MEM_LIMIT_CONSTRAINED_MB) or \
       (cpu_share_pct is not None and cpu_share_pct < CPU_SHARE_CONSTRAINED_PCT):
        return "Constrained"
    if (mem_limit_mb is not None and mem_limit_mb < MEM_LIMIT_MID_MB) or \
       (cpu_share_pct is not None and cpu_share_pct < CPU_SHARE_MID_PCT):
        return "Mid-range"
    return "High-performance"

def device_validation(candidate: str, cpu_share_pct: float | None, mem_limit_mb: float | None) -> str:
    """
    Cap a network candidate group to what the device tier
    (classify_device()) can feasibly run.
    """
    if candidate not in ALLOWED_GROUPS:
        raise ValueError(f"Unsupported candidate group: {candidate}")

    tier = classify_device(cpu_share_pct, mem_limit_mb)

    if tier == "Mid-range":
        return GROUP_768 if candidate == GROUP_1024 else candidate
    if tier == "Constrained":
        return GROUP_512
    return candidate


@dataclass
class Selection:
    group: str               # final group, after device capping
    network_candidate: str   # Stage 1's group, before device capping


def select_group(context_dict: Mapping[str, Any]) -> Selection:
    """
    Run both stages over a context mapping of rtt_ms, cpu_share_pct, and
    mem_limit_mb. Returns both the final group and Stage 1's network-only
    candidate, so callers that want to record what the network alone
    would have picked don't need to call network_candidate() again
    themselves.
    """
    if not isinstance(context_dict, Mapping):
        raise TypeError("context_dict must be a mapping/dictionary")

    required = {"rtt_ms", "cpu_share_pct", "mem_limit_mb"}
    missing = required - context_dict.keys()
    if missing:
        raise KeyError(f"Missing context field(s): {', '.join(sorted(missing))}")

    candidate = network_candidate(
        rtt_ms = context_dict["rtt_ms"],
    )
    group = device_validation(
        candidate     = candidate,
        cpu_share_pct = context_dict["cpu_share_pct"],
        mem_limit_mb  = context_dict["mem_limit_mb"],
    )
    return Selection(group=group, network_candidate=candidate)
