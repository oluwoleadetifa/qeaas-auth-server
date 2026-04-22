# QEaaS: Entropy Distribution Service Benchmarking Framework

This repository contains the client, benchmarking infrastructure, and experimental setup for evaluating a Quantum Entropy-as-a-Service (QEaaS) system.

The system provides authenticated access to entropy sourced from a Quantum Random Number Generator (QRNG), with cryptographic protections against replay and tampering.

---

#  Current Status

## Completed

### 1. Hardened QRNG Entropy Service
- Device enrollment enforced
- Cryptographic request signing implemented
- Nonce-based replay protection added
- Replay attacks return `HTTP 409`
- Invalid signatures return `HTTP 401`

### 2. Security Validation
The following properties have been experimentally verified:

- **Authentication Enforcement**
  - Unregistered devices rejected (`401`)

- **Parameter Binding**
  - `device_id`, `n`, and `nonce` are cryptographically bound
  - Any modification results in `401`

- **Replay Protection**
  - Identical requests rejected (`409`)
  - Nonce reuse detected
  - Fresh requests continue to succeed (`200`)

### 3. Benchmarking Infrastructure (In Progress)
A Rust-based benchmarking client has been implemented with:

- Multi-device simulation
- Per-request nonce generation
- Correct canonical message signing:
msg = device_id || 0x00 || n(u64 LE) || 0x00 || nonce

- Concurrent request generation using `tokio`
- Metrics collection:
- throughput (req/s)
- latency (mean, p95, p99)
- error breakdown (401, 409, other)

---

#  System Architecture

## Components

### 1. Auth Server
- Handles device enrollment
- Verifies request signatures
- Enforces nonce replay protection
- Serves entropy from QRNG

---

### 2. `client_iot`
Responsible for:
- Generating PQ key material (`DevicePq`)
- Performing device enrollment
- Signing entropy requests

Key distinction:
- `DevicePq` → cryptographic operations
- `IotClient` → HTTP communication

---

### 3. `benchmark_client`
Responsible for:
- Bulk device enrollment
- Persisting device credentials (`users.jsonl`)
- Reconstructing device signing context
- Running sustained-load performance tests

---

#  File Structure
benchmark_client/

├── enroll.rs # Bulk device enrollment

├── loadtest.rs # Load testing engine

├── message.rs # Canonical message + signing logic

├── storage.rs # users.jsonl read/write

├── models.rs # Shared structs

└── main.rs # CLI entry point


---

# Device Lifecycle

## 1. Enrollment Phase

Each device:
- Generates PQ keypair (`DevicePq`)
- Sends:
  - `device_id`
  - `kem_pk_b64`
  - `sig_pk_b64`
- Server registers device

Credentials are saved locally:

```json
{
  "device_id": "iot-device-0001",
  "kem_pk_b64": "...",
  "sig_pk_b64": "...",
  "sig_sk_b64": "..."
}```

Stored in:
```
users.jsonl
```
## 2. Request Phase

Each entropy request includes:
{
  "device_id": "...",
  "n": 32,
  "nonce_b64": "...",
  "signature_b64": "..."
}
Signature is computed over:
device_id || 0x00 || n(u64 LE) || 0x00 || nonce

## Usage
1. Enroll Devices
cargo run --release -- enroll \
  --base-url http://127.0.0.1:3000 \
  --count 100 \
  --out users.jsonl
2. Run Load Test
cargo run --release -- loadtest \
  --base-url http://127.0.0.1:3000 \
  --users users.jsonl \
  --concurrency 10 \
  --duration 30
### Metrics Collected
Total requests
Successful responses (200)
Failures:
401 → invalid signature
409 → replay detected
Throughput (req/s)
Latency:
mean
p95
p99

## Current Limitations
Only direct QRNG system tested (no buffering/CSPRNG yet)
Device key reconstruction requires DevicePq::set_sig_sk()
No TTL-based replay expiration implemented yet
Benchmark assumes correct signing implementation

## Next Steps
- 1. Performance Evaluation (Immediate)
Run sustained-load tests on hardened QRNG system
Measure:
throughput vs concurrency
latency distribution
saturation point
- 2. Hybrid QRNG + CSPRNG Model
Introduce entropy buffering
Use QRNG as seed source
Evaluate:
throughput improvement
latency stabilization
security trade-offs
- 3. Comparative Analysis (Paper Core)

Compare:

System	Expected Outcome
Direct QRNG	Low throughput, high latency
Hybrid Model	High throughput, stable latency
- 4. Extended Security Features
TTL-based nonce expiration
Enhanced replay semantics
Optional client-side verification
- 5. QTPM Integration (Future Work)
Use QEaaS as entropy backend
Implement TPM-like interface in Rust
Evaluate secure key generation pipelines
 Research Contribution

This work demonstrates:

Secure remote entropy distribution using QRNG
Practical replay-resistant authentication
Scalability limitations of direct QRNG access
Performance gains from hybrid entropy architectures
Experimental Goal

To show that:

A direct QRNG-backed entropy service, while secure, does not scale under load, and must be augmented with a CSPRNG-based architecture to achieve practical performance.
### Notes
Always run benchmarks in --release mode
Do not enroll devices during load testing
Ensure nonce uniqueness per request
Verify signature correctness before scaling tests
👨‍🔬 Author Notes

This project is part of ongoing research into secure entropy distribution, post-quantum cryptography, and trusted execution environments.
