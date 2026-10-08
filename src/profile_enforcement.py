"""
AdaptiveQKE Profile Enforcement
==================================
Applies and tears down the network and device profiles the experiment
tests against: tc-netem delay/rate/loss on the loopback interface, and
cgroup v2 CPU/memory limits emulating constrained device tiers.
"""

import subprocess

LOOPBACK_IF   = "lo"
CGROUP_NAME   = "adaptiveqke"

# setup_cgroup() scales cpu_quota onto a much shorter CFS period than the
# cgroup v2 default. Under a 100ms period, exhausting the quota mid-
# handshake freezes the process for the full period-quota gap (75-90ms)
# until refill, producing a bimodal latency tail. A 10ms period preserves
# the same CPU fraction but caps that stall at ~7-9ms, small enough to
# stop dominating handshake latency.
CFS_PERIOD_US = 10_000  # 10ms (cgroup v2 default is 100_000 = 100ms)

# Rate limiting uses netem's own `rate` option rather than a layered tbf
# qdisc. tc-tbf(8) states that TBF shapes with ideal minimal burstiness
# only up to about 1 Mbit/s; above that "data is on average dequeued at
# the configured rate but may be sent much faster at millisecond
# timescales". Every profile here runs at 3 Mbit/s or more, and a TLS
# handshake is precisely a millisecond-timescale event, so TBF cannot
# reproduce per-packet serialisation at the scale being measured -- and
# no choice of `burst` fixes that, because the cause is timer
# granularity rather than bucket depth.
#
# tc-netem(8) describes `rate` as delaying "packets based on packet size
# and is a replacement for TBF". That is the correct model for a link
# whose cost depends on how many bytes are sent: total added delay is
# the sum over packets of size/rate, which is what a real serial link
# imposes. It also removes the token bucket entirely, so there is no
# burst parameter left to choose.
#
# netem's own limits still apply: kernel clock granularity prevents
# perfect shaping and shows up as artificial packet compression. At
# 3 Mbit a 1500 B packet costs 4 ms, far above that granularity; at
# 100 Mbit it costs 0.12 ms, near it -- but serialisation is negligible
# at 100 Mbit anyway, so the inaccuracy sits where it does not matter.


# ---------------------------------------------------------------------------
# Network profiles
# ---------------------------------------------------------------------------

def apply_network_profile(profile: dict):
    # netem is applied once to the shared `lo` interface, but BOTH
    # loopback legs of a trial (client->proxy AND proxy->server) traverse
    # `lo` and each pay the delay independently -- so a handshake's
    # effective RTT is ~2x profile['delay_ms'], not 1x, uniformly across
    # every device/config combination (the print below already reflects
    # this via `2*profile['delay_ms']`).
    iface = LOOPBACK_IF
    subprocess.run(["sudo", "ip", "link", "set", iface, "mtu", "1500"], check=True)
    subprocess.run(["sudo", "tc", "qdisc", "del", "dev", iface, "root"],
                   capture_output=True)

    netem_cmd = [
        "sudo", "tc", "qdisc", "add",
        "dev", iface, "root", "handle", "1:",
        "netem",
        "delay", f"{profile['delay_ms']}ms",
    ]
    if profile.get("loss_pct", 0) > 0:
        netem_cmd += ["loss", f"{profile['loss_pct']}%"]
    # `rate` must come last: tc-netem(8) lists RATE as the final option
    # group. One qdisc now carries delay, loss and rate together, so
    # there is no parent/child chain and no token bucket.
    netem_cmd += ["rate", f"{profile['rate_mbit']}mbit"]
    subprocess.run(netem_cmd, check=True)

    print(f"[tc-netem] {profile['name']}: "
          f"delay={profile['delay_ms']}ms (RTT≈{2*profile['delay_ms']}ms), "
          f"rate={profile['rate_mbit']}Mbit (netem, per-packet), "
          f"loss={profile.get('loss_pct', 0)}%")


def clear_network_profile():
    subprocess.run(["sudo", "tc", "qdisc", "del", "dev", LOOPBACK_IF, "root"],
                   capture_output=True)
    subprocess.run(["sudo", "ip", "link", "set", LOOPBACK_IF, "mtu", "65536"],
                   capture_output=True)


def ensure_bbr() -> str:
    """Switch the kernel to BBR congestion control.

    Returns the original cc name so the caller can restore it on exit.
    Does NOT touch the lo qdisc — default_qdisc only affects interfaces that
    have no explicit qdisc set, so the netem qdisc on lo is unaffected.
    """
    orig = subprocess.run(
        ["sysctl", "-n", "net.ipv4.tcp_congestion_control"],
        capture_output=True, text=True,
    ).stdout.strip()

    subprocess.run(["sudo", "modprobe", "tcp_bbr"], capture_output=True)

    subprocess.run(
        ["sudo", "sysctl", "-w", "net.ipv4.tcp_congestion_control=bbr"],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["sudo", "sysctl", "-w", "net.core.default_qdisc=fq"],
        check=True, capture_output=True,
    )

    active = subprocess.run(
        ["sysctl", "-n", "net.ipv4.tcp_congestion_control"],
        capture_output=True, text=True,
    ).stdout.strip()

    if active != "bbr":
        raise RuntimeError(
            f"BBR could not be enabled: net.ipv4.tcp_congestion_control is "
            f"'{active}' after attempting to set it. "
            f"Check that the tcp_bbr module is available: modinfo tcp_bbr"
        )

    print(f"[bbr] congestion control = bbr  (was: {orig})")
    return orig


# ---------------------------------------------------------------------------
# Device profiles
# ---------------------------------------------------------------------------

def _cpu_fraction(cpu_quota: int | None) -> float | None:
    """cpu_quota is in DEVICE_PROFILES units (100_000 = 100% of one core)."""
    return None if cpu_quota is None else cpu_quota / 100_000


def setup_cgroup(profile: dict):
    if profile["cpu_quota"] is None:
        return
    # Ensure the cpu controller is listed in subtree_control -- otherwise
    # cpu.max in a child cgroup is silently ignored on systems where the
    # root slice doesn't advertise it by default. Idempotent.
    #
    # Uses `sudo tee <path>` rather than `sudo sh -c "echo ... > file"`:
    # sudoers NOPASSWD rules match the literal command, and a fixed `tee`
    # invocation is an exact match -- `sh -c "..."` is both fragile to
    # whitelist and, if whitelisted, grants a passwordless root shell.
    subprocess.run(
        ["sudo", "tee", "/sys/fs/cgroup/cgroup.subtree_control"],
        input="+cpu\n", text=True, capture_output=True,
        # non-fatal: already-set or cgroup-v1 systems
    )
    subprocess.run(["sudo", "cgcreate", "-g", f"cpu,memory:{CGROUP_NAME}"], check=True)

    cpu_fraction  = _cpu_fraction(profile["cpu_quota"])
    scaled_quota  = round(cpu_fraction * CFS_PERIOD_US)
    subprocess.run(["sudo", "cgset", "-r",
                    f"cpu.max={scaled_quota} {CFS_PERIOD_US}",
                    CGROUP_NAME], check=True)
    mem_bytes = profile["mem_limit"] * 1024 * 1024
    subprocess.run(["sudo", "cgset", "-r",
                    f"memory.max={mem_bytes}",
                    CGROUP_NAME], check=True)
    print(f"[cgroups] {profile['name']}: "
          f"cpu={scaled_quota}/{CFS_PERIOD_US} ({cpu_fraction:.0%}), "
          f"mem={profile['mem_limit']}MB")


def teardown_cgroup(profile: dict):
    if profile["cpu_quota"] is None:
        return
    subprocess.run(["sudo", "cgdelete", "-g", f"cpu,memory:{CGROUP_NAME}"],
                   capture_output=True)
