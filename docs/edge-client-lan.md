# QEaaS Local LAN / Edge-Client Notes

These notes support optional edge-client feasibility validation. They are not a large-scale IoT latency benchmark. The goal is to verify that a physically separate client can enroll, authenticate, request entropy, and trigger replay protection over a private LAN.

## Start the QRNG Service Node

Run the QRNG service on the workstation that has access to the QRNG device interface.

```sh
cd qrng_server
cargo run --release
```

## Bind the Authenticated QEaaS Service to the LAN

On the workstation-hosted QEaaS service node:

```sh
cd auth_server
AUTH_ADDR=0.0.0.0:3000 \
ENTROPY_MODE=direct_qrng \
cargo run --release
```

For hybrid modes:

```sh
AUTH_ADDR=0.0.0.0:3000 \
ENTROPY_MODE=hybrid_csprng \
HYBRID_RESEED_AFTER_BYTES=1048576 \
cargo run --release
```

```sh
AUTH_ADDR=0.0.0.0:3000 \
ENTROPY_MODE=parallel_hybrid \
HYBRID_POOL_SIZE=8 \
HYBRID_RESEED_AFTER_BYTES=1048576 \
cargo run --release
```

## Find the Workstation IP Address

On Linux:

```sh
hostname -I
```

On macOS:

```sh
ipconfig getifaddr en0
```

Use the private LAN address, for example `192.168.1.25`.

## Test from Another Device

From the remote client:

```sh
curl http://192.168.1.25:3000/health
```

Expected response:

```text
ok
```

## Run Enrollment from a Remote Client

From the repository checkout on the remote client:

```sh
cd benchmark_client
cargo run --release -- enroll \
  --base-url http://192.168.1.25:3000 \
  --count 10 \
  --out users-lan.jsonl
```

## Run Signed Requests from a Remote Client

```sh
cargo run --release -- loadtest \
  --base-url http://192.168.1.25:3000 \
  --entropy-mode direct_qrng \
  --users users-lan.jsonl \
  --n 32 \
  --concurrency 1 \
  --duration 30 \
  --label lan-smoke \
  --csv-out lan-results.csv \
  --jsonl-out lan-results.jsonl
```

## Replay Validation

Run the security validation subcommand against the workstation-hosted service:

```sh
cargo run --release -- security-check \
  --base-url http://192.168.1.25:3000
```

This checks enrollment, signed requests, invalid signatures, replay detection, malformed base64 handling, and oversized request handling.
