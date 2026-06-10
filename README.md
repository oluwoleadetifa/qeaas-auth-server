# QEaaS: QRNG-Backed Entropy Distribution and Benchmarking

QEaaS is a QRNG-backed entropy distribution and benchmarking framework for evaluating entropy as a measurable trust resource.

This repository supports Paper 1 of a larger dissertation on trust as a systems resource. The codebase implements an authenticated Quantum Entropy-as-a-Service prototype with device enrollment, post-quantum-style device credentials, canonical request signing, nonce-based replay protection, and sustained-load benchmarking for IoT-style client workloads.

The current prototype is a workstation-hosted QRNG entropy service. This reflects the hardware reality of the available QRNG PCIe card, which depends on legacy Linux kernel and driver compatibility. The deployment model is a workstation-hosted QRNG service node supporting an authenticated QEaaS service, rather than an enterprise server hardware deployment.

The primary validation environment for Paper 1 is the Ubuntu 18 / Linux kernel 4 QRNG workstation. See [docs/build_setup.md](docs/build_setup.md) for build dependencies, QRNG device checks, and OpenSSL/libcrypto troubleshooting.

## Project Overview

The project evaluates how authenticated remote entropy distribution behaves under different entropy-serving designs. The service exposes a protected HTTP API that allows enrolled devices to request entropy, while a benchmark client simulates many IoT-style devices issuing signed requests under configurable load.

The central research question is whether entropy can be treated as a systems resource whose trust properties and performance costs can be measured, compared, and engineered.

## Research Motivation

Randomness is a foundational trust dependency for cryptographic systems. QRNG hardware can provide high-quality physical entropy, but serving QRNG output directly to many clients may introduce throughput, latency, and synchronization constraints.

This project studies the trade-off between physical entropy quality and service scalability by comparing direct QRNG delivery against hybrid QRNG-CSPRNG designs. The goal is not merely to build an entropy API, but to quantify how different entropy-serving architectures affect trust, performance, and deployability.

## Current Paper Scope

Paper 1 focuses on QEaaS: an authenticated, QRNG-backed entropy distribution framework and benchmark methodology.

The paper compares three configurations:

- Config 1: Direct QRNG
- Config 2: Hybrid QRNG-CSPRNG
- Config 3: Parallel Hybrid QRNG-CSPRNG

The current implementation includes all three runtime entropy modes. Full publication-grade validation across the recommended benchmark matrix, especially on the target Ubuntu 18 workstation-hosted QRNG service node, is still in progress.

## System Architecture

The repository is organized around three main components:

- `auth_server`: authenticated QEaaS service. It handles enrollment, verifies request signatures, enforces nonce replay protection, fetches or generates entropy according to the selected entropy mode, encrypts entropy responses, and signs response transcripts.
- `client_iot`: IoT-style client support library. It generates device credentials, enrolls devices, signs entropy requests, verifies server response signatures, and decrypts returned entropy.
- `benchmark_client`: benchmarking CLI. It performs bulk enrollment, persists device credentials in `users.jsonl`, reconstructs signing contexts, generates concurrent signed entropy requests, and writes benchmark summaries.

The QRNG is accessed through a local QRNG service node. In direct mode, the authenticated service requests QRNG bytes for each entropy request. In hybrid modes, QRNG output is used as seed material for ChaCha20-based CSPRNG state.

## IoT Client CLI

The `client_iot` crate provides a small standalone client for edge-client feasibility checks and development without requiring benchmark-client machinery. It uses the same enrollment, request signing, response verification, and decrypt path as the library code.

Client credentials are stored under `client_iot/device_state/`. This directory contains generated private device credentials and is ignored by Git. Do not commit files from this directory.

Default client settings:

- Device ID: `iot-device-mac`.
- Server URL: `QEAAAS_SERVER_URL`, then `AUTH_BASE`, then `http://127.0.0.1:3000`.
- Request size: `32` bytes.

Development-only dry runs validate CLI parsing and state-directory creation without calling the network:

```sh
cd client_iot
cargo run -- --help
cargo run -- enroll --dry-run
cargo run -- request --n 32 --dry-run
cargo run -- re-enroll --dry-run
```

Live client commands:

```sh
cd client_iot
QEAAAS_SERVER_URL=http://127.0.0.1:3000 cargo run -- enroll
QEAAAS_SERVER_URL=http://127.0.0.1:3000 cargo run -- request --n 32
QEAAAS_SERVER_URL=http://127.0.0.1:3000 cargo run -- re-enroll
```

Optional flags:

- `--server <URL>` overrides the server URL for one command.
- `--device-id <ID>` selects a device-state file.
- `--n <BYTES>` selects request size for `request`.
- `--dry-run` avoids network calls for `enroll`, `request`, and `re-enroll`.

## Entropy Serving Configurations

### Config 1: Direct QRNG

`ENTROPY_MODE=direct_qrng`

Entropy is served directly from the QRNG device interface through the QRNG service node for each request. This configuration measures the cost of direct physical entropy serving under authenticated client load.

This is the baseline for comparing quality-preserving simplicity against service scalability.

### Config 2: Hybrid QRNG-CSPRNG

`ENTROPY_MODE=hybrid_csprng`

QRNG entropy seeds a ChaCha20-based CSPRNG. Client-facing entropy is generated from the CSPRNG, and the CSPRNG is periodically reseeded from QRNG-derived entropy.

Implemented settings:

- `HYBRID_QRNG_SEED_SIZE`: QRNG seed bytes fetched for the CSPRNG. Default: `32`.
- `HYBRID_RESEED_AFTER_BYTES`: byte threshold for reseeding. Default: `1048576`.

The purpose of this configuration is to decouple entropy quality from serving scalability. It tests whether QRNG-backed seeding can preserve a meaningful trust relationship while avoiding per-request QRNG I/O.

### Config 3: Parallel Hybrid QRNG-CSPRNG

`ENTROPY_MODE=parallel_hybrid`

`ENTROPY_MODE=hybrid_pool` is accepted as an alias, but `parallel_hybrid` is the preferred name for documentation and experiments.

This mode uses a pool of independently seeded ChaCha20 CSPRNG shards. Each shard is seeded from QRNG-derived entropy, with shard-specific derivation so shards do not accidentally share identical CSPRNG seeds. Requests are distributed across shards, currently using low-contention shard selection.

Implemented setting:

- `HYBRID_POOL_SIZE`: number of independent CSPRNG shards. Default: `8`.

Older `QEaaS_*`, `QEAAS_*`, and `QEAAAS_*` variable names are still accepted for compatibility with earlier experiments, but the commands in this README use the canonical names above.

This configuration tests whether entropy-source synchronization is the dominant serving bottleneck. It is intended to reduce contention from a single shared RNG state while preserving QRNG-backed reseeding behavior.

## Security Properties

The authenticated QEaaS service currently implements the following security properties:

- Device enrollment: devices submit public KEM and signature keys before requesting entropy.
- Request signing: clients sign each entropy request using their device signing credential.
- Parameter binding: `device_id`, requested entropy length `n`, and `nonce` are bound into the signed request transcript.
- Canonical request message:

```text
device_id || 0x00 || n(u64 LE) || 0x00 || nonce
```

- Nonce-based replay protection: accepted nonces are tracked per device for a replay window.
- Invalid signature handling: invalid signatures return `HTTP 401`.
- Unregistered device handling: unknown devices return `HTTP 401`.
- Replay detection: repeated valid signed requests return `HTTP 409`.
- Fresh valid requests: enrolled devices with valid signatures and unused nonces receive `HTTP 200`.

The authentication and signing flow is intentionally shared across all entropy modes. The selected entropy mode must not alter the canonical request transcript, request verification order, nonce replay semantics, or response cryptographic structure.

## Benchmarking Infrastructure

The Rust benchmark client supports:

- Bulk enrollment of simulated devices.
- Persistent device credential storage in `users.jsonl`.
- Reconstruction of signing contexts for load tests.
- Multi-device simulation.
- Concurrent request generation using `tokio`.
- Payload-size variation through the request size parameter `n`.
- Concurrency variation through the `--concurrency` flag.
- Sustained-duration load tests through the `--duration` flag.
- CSV, JSONL, and Markdown benchmark summaries.

Example enrollment:

```sh
cargo run --release -- enroll \
  --base-url http://127.0.0.1:3000 \
  --count 100 \
  --out users.jsonl
```

Example load test:

```sh
cargo run --release -- loadtest \
  --base-url http://127.0.0.1:3000 \
  --users users.jsonl \
  --entropy-mode direct_qrng \
  --n 1024 \
  --concurrency 10 \
  --duration 30 \
  --label direct_qrng \
  --csv-out results.csv \
  --jsonl-out results.jsonl \
  --md-out results.md
```

When restarting the auth server, re-enroll devices or use a fresh users file for that run, because enrolled device state is currently in memory.

## Metrics Collected

The benchmark client currently reports:

- Configuration label.
- Timestamp.
- Git commit when available.
- Base URL.
- Entropy mode.
- Payload size.
- Concurrency.
- Duration.
- Total requests.
- Successful responses.
- Failure count.
- Error breakdown for `401`, `409`, and other failures.
- Throughput in requests per second.
- Mean latency.
- P50 latency.
- P95 latency.
- P99 latency.
- Max latency.

Planned or in-progress reporting additions:

- Server-side entropy wait summaries in benchmark output.

Server-side observability includes entropy mode, request size, request latency, reseed counters, reseed failures, QRNG seed size, and Config 3 pool/shard-related fields where available.

Optional per-request stage timing can be enabled with:

```sh
ENABLE_STAGE_TIMING=1 ENTROPY_MODE=parallel_hybrid cargo run --release
```

When enabled, the authenticated service writes structured JSONL timing records to stdout, including at least signature verification time, entropy acquisition/generation time, total request time, payload size, entropy mode, device ID, and status code.

## Recommended Benchmark Matrix

For Paper 1, use a consistent benchmark matrix across all entropy configurations:

- Payload sizes: `32`, `256`, `1024`, `4096` bytes.
- Concurrency levels: `1`, `5`, `10`, `25`, and optionally `50`.
- Duration: `30` seconds minimum for exploratory runs.
- Duration: `60` seconds for final publication runs.
- Configurations: `direct_qrng`, `hybrid_csprng`, `parallel_hybrid`.

Each run should use release builds and a stable QRNG service node. Avoid enrolling devices during load testing.

Example auth server commands:

```sh
ENTROPY_MODE=direct_qrng cargo run --release
```

```sh
ENTROPY_MODE=hybrid_csprng \
HYBRID_RESEED_AFTER_BYTES=1048576 \
cargo run --release
```

```sh
ENTROPY_MODE=parallel_hybrid \
HYBRID_POOL_SIZE=8 \
HYBRID_RESEED_AFTER_BYTES=1048576 \
cargo run --release
```

Matrix runner:

```sh
cd benchmark_client
cargo run --release -- matrix \
  --base-url http://127.0.0.1:3000 \
  --entropy-mode direct_qrng \
  --users users.jsonl \
  --payloads 32,256,1024,4096 \
  --concurrency-levels 1,5,10,25 \
  --duration 30 \
  --label direct_qrng \
  --csv-out ../results/qeaas_matrix.csv \
  --jsonl-out ../results/qeaas_matrix.jsonl \
  --md-out ../results/qeaas_matrix.md
```

Equivalent script:

```sh
ENTROPY_MODE=direct_qrng scripts/run_matrix.sh
```

## Security Validation Matrix

The security validation matrix should be run for each entropy-serving configuration:

| Test | Expected Result |
|---|---|
| Unregistered device requests entropy | `HTTP 401` |
| Enrolled device sends valid fresh request | `HTTP 200` |
| Enrolled device sends invalid signature | `HTTP 401` |
| Signed request modified after signing | `HTTP 401` |
| Valid signed request replayed with same nonce | `HTTP 409` |
| Fresh nonce after replay failure | `HTTP 200` |
| Payload size changed without resigning | `HTTP 401` |

These tests validate the shared security path. They should not depend on whether entropy is served by direct QRNG, single CSPRNG state, or sharded CSPRNG state.

Run the validation subcommand:

```sh
cd benchmark_client
cargo run --release -- security-check \
  --base-url http://127.0.0.1:3000
```

Or use the repository wrapper script:

```sh
BASE_URL=http://127.0.0.1:3000 scripts/security_validate.sh
```

## Optional Edge-Client Feasibility Validation

An optional validation step is to run physically separate clients against the workstation-hosted QRNG service over a local network.

This is not intended to be a large-scale IoT latency benchmark. The goal is narrower: verify that edge-style clients can enroll, authenticate, request entropy, receive valid responses, and trigger replay protection from separate machines or network locations.

This supports edge-client feasibility validation without overclaiming broad IoT deployment performance.

See [docs/edge-client-lan.md](docs/edge-client-lan.md) for private-LAN setup notes.

## Reproducibility Notes

- Run benchmarks with `cargo run --release`.
- Validate builds on the Ubuntu 18 / Linux kernel 4 QRNG workstation before collecting publication results.
- Keep the QRNG service node configuration stable across runs.
- Use the same benchmark matrix for each entropy mode.
- Re-enroll devices after restarting the auth server unless enrollment persistence has been added.
- Use fresh `users.jsonl` files when comparing independent server runs to avoid stale duplicate device credentials.
- Record `ENTROPY_MODE`, `HYBRID_QRNG_SEED_SIZE`, `HYBRID_RESEED_AFTER_BYTES`, and `HYBRID_POOL_SIZE` with each result set.
- Do not change the canonical signing message between configurations.
- Do not enroll devices during sustained load tests.

## Pre-Push Checklist

- Run `cargo fmt`.
- Run `cargo clippy -- -D warnings`.
- Run `cargo test` where native dependencies are available.
- Verify no private keys, generated `users.jsonl`, or `users_*.jsonl` files are staged.
- Verify no local `.env` files are staged.
- Verify no local machine paths were committed.
- Verify benchmark result files are intentionally included or ignored.
- Verify QRNG workstation-specific notes still point to Ubuntu 18 / Linux kernel 4 as the primary validation target.

## Next Implementation Tasks

Implemented:

- Authenticated enrollment.
- Canonical request signing.
- Nonce-based replay protection.
- Direct QRNG entropy mode.
- Hybrid ChaCha20 CSPRNG entropy mode.
- Parallel hybrid sharded ChaCha20 CSPRNG mode.
- CSV, JSONL, and Markdown benchmark summaries.
- Benchmark matrix subcommand.
- Security validation subcommand.

In progress:

- Full Ubuntu 18 validation on the workstation-hosted QRNG service node.
- Complete benchmark matrix for Config 1, Config 2, and Config 3.
- Server-side bottleneck instrumentation for PQ verification, KEM encapsulation, AEAD encryption, base64 processing, nonce-cache synchronization, and request logging overhead.
- Benchmark output extensions for entropy wait summaries.

Planned:

- Enrollment persistence or explicit benchmark workflow safeguards for server restarts.
- Comparative plots for throughput, latency, and error behavior across configurations.
- Optional edge-client feasibility validation over a local network.

## Dissertation Alignment

This repository supports the first paper in a three-paper dissertation structure:

- Paper 1: QEaaS. QRNG-backed entropy distribution and benchmarking, treating entropy as a measurable trust resource.
- Paper 2: QTPM. Quantum-informed or QRNG-backed trusted platform mechanisms for key generation and platform trust services.
- Paper 3: Zero-Trust Orchestration. System-level orchestration of trust decisions across devices, services, and infrastructure.

Paper 1 establishes the empirical foundation: how a trusted entropy resource can be authenticated, distributed, benchmarked, and compared across serving architectures.
