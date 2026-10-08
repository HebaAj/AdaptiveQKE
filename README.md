# AdaptiveQKE

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.23244638.svg)](https://doi.org/10.5281/zenodo.23244638)

**Context-Aware Hybrid Key Exchange for TLS Channels**

AdaptiveQKE is a graduation research project that tests whether a TLS 1.3 client can choose its hybrid post-quantum key-exchange group for each connection, from measured network delay and device resource limits, instead of using one fixed group everywhere. The choice is made on the client before the handshake, and the TLS 1.3 handshake itself is not modified.

This repository contains the Python testbed, the recorded measurements, and checksums that tie both to the thesis.

## Results at a glance

Measured on an emulated testbed: 3 device profiles x 3 network profiles x 4 configurations x 50 trials = 1,800 handshakes.

- **Selection:** the policy chose the group its rules prescribe in 450 of 450 adaptive trials.
- **Against the strongest fixed group (SecP384r1MLKEM1024):** lower median wire latency in 8 of 9 conditions (12.8% lower on average, up to 36.1% on the Constrained device over a low-latency link), 16.5% less CPU time on average, and 26.2% fewer handshake bytes on average. In the ninth condition (unrestricted device, low-latency link) the policy picks that same group, so the two behave alike.
- **After selection:** no detectable difference in wire latency from a fixed configuration using the same group. All nine confidence intervals span zero, which is not a proof of equivalence.
- **Cost:** the RTT probe adds a one-time delay on the first connection of about 22 ms, 72 ms and 122 ms on the low-latency, moderate and high-latency profiles. Evaluating the policy itself takes about 0.03 ms.
- Adaptive does not beat the lighter fixed groups everywhere. It trades latency against security level on purpose.

These are results from a controlled testbed and do not establish production suitability. See [Limitations](#limitations).

## How it works

The policy uses round-trip time (RTT), CPU share and memory limit in two stages.

**Stage 1: RTT selects a candidate group**

| Measured RTT | Candidate group |
| --- | --- |
| below 50 ms | `SecP384r1MLKEM1024` |
| 50 to 100 ms (inclusive) | `X25519MLKEM768` |
| above 100 ms | `x25519_mlkem512` |

**Stage 2: the device tier caps the candidate.** The tier comes from CPU share and memory limit, and the more restrictive of the two wins.

| Tier | Rule | Effect |
| --- | --- | --- |
| High-performance | CPU share 60% or more and memory 256 MB or more (or unrestricted) | candidate kept |
| Mid-range | CPU share below 60% or memory below 256 MB | capped at `X25519MLKEM768` |
| Constrained | CPU share below 15% or memory below 64 MB | always `x25519_mlkem512` |

| Hybrid group | Identifier in the code | NIST level | Handshake size (measured) |
| --- | --- | :---: | ---: |
| X25519 + ML-KEM-512 | `x25519_mlkem512` | 1 | 3,176 B |
| X25519 + ML-KEM-768 | `X25519MLKEM768` | 3 | 3,892 B |
| secp384r1 + ML-KEM-1024 | `SecP384r1MLKEM1024` | 5 | 4,886 B |

`x25519_mlkem512` uses a private-use code point from the Open Quantum Safe provider and has no assigned standard identifier. All thresholds are fixed prototype parameters, defined in [`src/policy_engine.py`](src/policy_engine.py).

## Evaluation setup

Four configurations are compared in every condition: **Adaptive**, **Static-512**, **Static-768** and **Static-1024**. Trial order within a condition is shuffled with a fixed seed (20260719).

| Device profile | CPU | Memory |
| --- | --- | --- |
| High-performance | unrestricted | unrestricted |
| Mid-range | 25% of one core | 128 MB |
| Constrained | 10% of one core | 32 MB |

Device limits are applied with Linux cgroup v2 (10 ms CFS period).

| Network profile | One-way delay | Rate | Packet loss |
| --- | --- | --- | --- |
| Low-latency | 10 ms | 100 Mbit/s | 0% |
| Moderate | 35 ms | 15 Mbit/s | 0.5% |
| High-latency | 60 ms | 3 Mbit/s | 2% |

Network conditions are emulated with `tc-netem` on the loopback interface (MTU forced to 1500, BBR congestion control). Rate and loss are experimental conditions, not policy inputs. The RTT probe measures roughly twice the configured one-way delay (about 21, 71 and 121 ms).

| Component | Version used for the recorded data |
| --- | --- |
| OS / kernel | Ubuntu 22.04, Linux 6.8.0-124-generic |
| OpenSSL | 3.4.1 |
| OQS provider / liboqs | 0.9.0 / 0.13.0 |
| Python | 3.10.12 (standard library only) |
| Host | VMware VM, Intel Core i5-1035G1, 2 vCPUs |

## Repository contents

```
AdaptiveQKE/
├── src/         implementation (see below)
├── config/      openssl-oqs.cnf, the OpenSSL provider configuration
├── results/     recorded datasets
├── docs/        the thesis (PDF)
├── SHA256SUMS   checksums of src/ and results/ files, as listed in thesis Table A.2
├── CITATION.cff
└── LICENSE
```

| Module in `src/` | Purpose |
| --- | --- |
| `policy_engine.py` | Two-stage group selection |
| `context_probe.py` | RTT probe and cgroup limit reading |
| `tls_client.py`, `tls_server.py` | OpenSSL handshake client and the testbed server |
| `profile_enforcement.py` | Apply cgroup and `tc-netem` profiles, set congestion control |
| `metrics.py` | Byte-counting relay: handshake size and wire latency |
| `experiment.py` | Orchestrate the full evaluation and the crypto-only phase |
| `results.py` | Write timestamped result CSV files |
| `generate_certs.sh` | Generate a self-signed RSA-2048 test certificate |

## Data

| File | Rows | Scope |
| --- | ---: | --- |
| [`results/results.csv`](results/results.csv) | 1,800 | Main evaluation: 3 device x 3 network x 4 configurations x 50 trials |
| [`results/crypto_latency.csv`](results/crypto_latency.csv) | 450 | Near-zero-network latency: 3 device x 3 groups x 50 trials, client pinned to one CPU, 5 discarded warm-up trials per pair |

Every trial in both files succeeded. No rows were removed.

**Columns of `results.csv`**

| Column | Meaning |
| --- | --- |
| `enforced_profile` | Device profile that was applied |
| `classified_profile` | Tier the policy derived from the measured cgroup limits (equals `enforced_profile` in all rows) |
| `cpu_share_pct`, `mem_limit_mb` | Measured limits. Empty means unrestricted |
| `network_profile` | `tc-netem` profile that was applied |
| `classified_network` | Stage 1 candidate group (despite the name). Adaptive rows only |
| `probed_rtt_ms`, `probe_cost_ms`, `policy_cost_ms` | RTT probe result, time spent probing, time spent evaluating the policy. Adaptive rows only |
| `config` | `Adaptive`, `Static-512`, `Static-768` or `Static-1024` |
| `trial`, `exec_order` | Trial number (1-50) and position in the shuffled run order of the condition |
| `requested_group` | Group passed to the TLS client |
| `success` | Handshake completed as TLS 1.3 |
| `handshake_latency_ms` | Client-side time from ClientHello to handshake completion. Can be distorted by CPU throttling |
| `wire_latency_ms` | Time at the byte-counting relay from the first client byte to the last relayed byte. Not affected by client throttling, so preferred for comparisons |
| `cpu_time_ms` | Client CPU time (user + system, process and children) |
| `handshake_size_bytes`, `handshake_c2s_bytes`, `handshake_s2c_bytes` | Bytes at the relay: total, client to server, server to client |

`crypto_latency.csv` has `device_profile`, `group`, `trial`, `exec_order`, `handshake_latency_ms`, `wire_latency_ms`, `handshake_size_bytes` and `success`.

Notes:
- The CSV files use Windows (CRLF) line endings, and `.gitattributes` keeps them byte-identical.
- In 3 of the 500 `SecP384r1MLKEM1024` trials the relay recorded 4,850 or 4,879 bytes instead of 4,886. They are kept unfiltered.

## Verify the files

```bash
sha256sum -c SHA256SUMS
```

Every line should report `OK`. The hashes are the ones listed in the thesis (Table A.2) for the implementation and the two datasets.

## Running the experiment

**Status:** the recorded data was produced on the original VM. This procedure has not yet been re-run from this repository layout, and a verified setup guide is planned.

Requirements: Linux with cgroup v2 and `sudo`, OpenSSL 3 built with the OQS provider and liboqs (versions above), Python 3.10 or later, `tc` (iproute2), cgroup-tools (`cgcreate`, `cgset`, `cgexec`), `taskset`, `stdbuf` and the `tcp_bbr` kernel module.

```bash
cd src
./generate_certs.sh               # creates src/certs/server.crt and server.key (git-ignored)
sudo -v
python3 experiment.py             # full run: 1,800 + 450 handshakes
python3 experiment.py --crypto-only
```

The code reads `config/openssl-oqs.cnf` from the repository root and writes new timestamped CSV files to `results/` (git-ignored, separate from the published files). The client verifies the server certificate, so the self-signed certificate must be trusted by the OpenSSL installation in use, for example by pointing `SSL_CERT_FILE` at `src/certs/server.crt`.

**The harness changes host settings:** it applies a `tc-netem` qdisc and MTU to the loopback interface, switches TCP congestion control to BBR (restored on exit), sets the default qdisc to `fq` (not restored) and creates a cgroup. Run it only in a dedicated test VM.

## Limitations

- The network and devices are emulated on a single host, not measured on real links or hardware. Absolute latencies are inflated because the relay makes the shaped path be crossed several times, so compare configurations rather than reading the milliseconds as production values.
- The policy thresholds were chosen to match the tested profiles, so 100% selection accuracy shows the rules are implemented correctly, not that the thresholds generalize.
- The test certificate is RSA, so this evaluates hybrid **key exchange**, not post-quantum authentication.
- A planned security-level floor and ceiling (to resist a manipulated RTT forcing a weaker group) was designed but not implemented. No downgrade-resistance claim is made.
- The first connection pays the RTT probe cost. It pays off only if the choice is reused across connections.
- No formal security analysis was performed.

## Authors

Graduation project for the B.Sc. in Cybersecurity Engineering, University College of Applied Sciences (UCAS), Gaza.

**Authors**
- Heba Ajjour — project lead and lead developer; maintainer of this repository
- Weaam Abdalaal
- Hala Nasrallah
- Farah Rajab

**Supervisor:** Eng. Hadi El-Nabris

**Contact:** Heba Ajjour, hajjour27@gmail.com

The full thesis is available in [`docs/AdaptiveQKE-thesis.pdf`](docs/AdaptiveQKE-thesis.pdf).

## Citation and license

Citation details are in [`CITATION.cff`](CITATION.cff) (GitHub shows a "Cite this repository" button). The archived release is on Zenodo: [10.5281/zenodo.23244638](https://doi.org/10.5281/zenodo.23244638).

The code is released under the [MIT License](LICENSE), copyright Heba Ajjour and co-authors. The recorded datasets in `results/` are released under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
