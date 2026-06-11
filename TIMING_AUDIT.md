# QEaaS Timing Instrumentation Audit

This audit maps the current timing metrics in `auth_server`, `client_iot`, and `benchmark_client` to the operations they actually measure. No protocol logic changes are implied here.

## 1. Current Timing Map

### Benchmark Client Metrics

#### `mean_latency_us`, `p50_latency_us`, `p95_latency_us`, `p99_latency_us`, `max_latency_us`

- File/function: `benchmark_client/src/loadtest.rs`, `worker_loop`.
- Start point: immediately after `build_signed_request(...)` succeeds, just before `http_client.post(...).json(&req).send().await`.
- Stop point: immediately after `send().await` returns.
- Included operations:
  - Reqwest request construction after the timer starts.
  - JSON request serialization performed by `.json(&req)` after the timer starts.
  - Connection acquisition/reuse inside reqwest.
  - HTTP request transmission.
  - Network round trip to the server.
  - Server-side processing until the HTTP response is available to reqwest.
  - Response header receipt and enough response handling for `send().await` to return.
- Excluded operations:
  - User/context loading from `users.jsonl`.
  - `DevicePq` reconstruction before the load loop.
  - Nonce generation.
  - Canonical message construction.
  - Client-side Dilithium signing.
  - Response body read via `resp.text().await`, because this occurs after `elapsed` is recorded.
  - Response JSON deserialization.
  - Client-side Kyber decapsulation.
  - Client-side AEAD decryption.
  - Client-side server-signature verification.
  - Entropy SHA-256 computation.
  - Benchmark summary stdout printing.
- Name accuracy: partially accurate. It is an HTTP request-send latency, not usable entropy latency.
- Safe for paper: safe only if described as `client_http_send_latency_us` or `client_observed_response_latency_us`, with the caveat that response body consumption and client decrypt/verify are excluded.
- Recommended better name: `client_http_response_available_us`.

### Benchmark Client Throughput

#### `throughput_req_s`

- File/function: `benchmark_client/src/loadtest.rs`, `summarize`.
- Start point: implicit fixed configured duration, from `deadline = Instant::now() + duration`.
- Stop point: task loops stop after the shared deadline.
- Included operations:
  - Repeated request signing before each timed HTTP request.
  - HTTP request execution.
  - Response status classification.
  - Response body discard via `resp.text().await`.
  - Per-request latency vector mutex insertion.
  - Tokio scheduling overhead.
- Excluded operations:
  - User enrollment.
  - Signing context reconstruction before workers start.
  - Report writing after workers finish.
- Name accuracy: mostly accurate for successful HTTP 200 responses per configured second.
- Safe for paper: yes, as successful authenticated entropy responses per second, but note that the benchmark client does not decrypt or verify returned entropy in the load-test path.
- Recommended better name: keep `throughput_req_s`, define as `successful_http_200_responses_per_second`.

### Server Stage-Timing JSONL Metrics

Stage timing is enabled by `ENABLE_STAGE_TIMING=1` or compatibility aliases. Records are emitted from `auth_server/src/api.rs` by `log_stage_timing(...)` with `println!("{line}")`.

#### `total_us`

- File/function: `auth_server/src/api.rs`, `request_entropy` and `log_stage_timing`.
- Start point: first line inside the Axum handler body, after Axum has already matched the route and deserialized the JSON extractor into `EntropyRequest`.
- Stop point: when `log_stage_timing(...)` is called. For successful requests this is just before returning `(StatusCode::OK, Json(resp)).into_response()`.
- Included operations:
  - Max-size check.
  - Device lookup.
  - Base64 decode of nonce and request signature.
  - Canonical request message construction.
  - Dilithium verification.
  - Nonce-cache lookup/insertion.
  - Entropy acquisition/generation.
  - Kyber encapsulation.
  - HKDF key derivation.
  - AEAD nonce derivation.
  - AAD construction.
  - AEAD encryption.
  - Response transcript construction.
  - Response signing.
  - Base64 encoding of response fields into the response struct.
  - Entropy stats tracing setup before the final timing log.
- Excluded operations:
  - TCP accept, HTTP parsing, Axum routing, and JSON extractor deserialization before handler entry.
  - Final Axum `IntoResponse` conversion after the timing log.
  - Actual response JSON serialization by Axum after the timing log.
  - Kernel/network send back to the client.
  - Client-side work.
  - The stdout cost of the timing `println!` itself.
- Name accuracy: mostly accurate as server handler elapsed time, but not full server HTTP processing.
- Safe for paper: yes if named and described as `server_handler_us`.
- Recommended better name: `server_handler_us`.

#### `parse_us`

- File/function: `auth_server/src/api.rs`, `request_entropy`.
- Start point: before base64 decoding `nonce_b64`.
- Stop point: after base64 decoding both `nonce_b64` and `signature_b64`, or at the decode error path.
- Included operations:
  - Base64 decode of request nonce.
  - Base64 decode of request signature.
- Excluded operations:
  - HTTP parsing.
  - JSON body deserialization into `EntropyRequest`.
  - Canonical message construction.
- Name accuracy: misleading if interpreted as full request parsing.
- Safe for paper: use only as request base64 decode time.
- Recommended better name: `server_request_b64_decode_us`.

#### `device_lookup_us`

- File/function: `auth_server/src/api.rs`, `request_entropy`.
- Start point: before acquiring `state.devices.read().await`.
- Stop point: after `devices.get(...).cloned()` and read-lock release.
- Included operations:
  - Waiting for the devices `RwLock` read lock.
  - HashMap lookup.
  - Clone of `DeviceKeys`, including KEM and signature public key byte vectors.
- Excluded operations:
  - Enrollment write-lock activity except as contention seen while waiting.
- Name accuracy: mostly accurate, but includes lock wait and clone.
- Safe for paper: yes as `server_device_lookup_us`, with lock-wait caveat.
- Recommended better name: keep `server_device_lookup_us`.

#### `signature_verify_us`

- File/function: `auth_server/src/api.rs`, `request_entropy`.
- Start point: after canonical request message construction, immediately before `verify_with_client_pk_bytes(...)`.
- Stop point: after the verification call returns.
- Included operations:
  - Device signature public-key conversion/validation inside PQ wrapper, if performed there.
  - Dilithium verification over the canonical message.
- Excluded operations:
  - Base64 decode of the request signature.
  - Canonical request message construction.
  - Nonce replay check.
- Name accuracy: accurate enough for server-side Dilithium verification.
- Safe for paper: yes.
- Recommended better name: `server_verify_us`.

#### `nonce_check_us`

- File/function: `auth_server/src/api.rs`, `request_entropy`; `auth_server/src/state.rs`, `NonceCache::check_and_insert`.
- Start point: before `check_and_insert(...).await`.
- Stop point: after it returns.
- Included operations:
  - Waiting for nonce cache write lock.
  - Per-device HashMap entry lookup/creation.
  - Replay lookup.
  - TTL/cap cleanup when cap is reached.
  - Nonce insertion for fresh requests.
- Excluded operations:
  - Signature verification.
  - Periodic cleanup task, except when lock contention affects this call.
- Name accuracy: accurate, but it is lookup plus insertion plus possible cleanup.
- Safe for paper: yes.
- Recommended better name: `server_nonce_check_insert_us`.

#### `entropy_us`

- File/function: `auth_server/src/api.rs`, `request_entropy`; `auth_server/src/entropy.rs`, `EntropySource::bytes_with_stats`.
- Start point: immediately before `state.entropy.bytes_with_stats(req.n).await`.
- Stop point: after entropy bytes and stats are returned, or after entropy error.
- Included operations by mode:
  - `direct_qrng`: HTTP GET to QRNG service endpoint, network/loopback latency, QRNG server response JSON deserialization, hex decode, length checks.
  - `hybrid_csprng`: reseed threshold check, possible QRNG seed fetch, single global CSPRNG mutex acquisition, ChaCha20 output generation, stats update.
  - `parallel_hybrid`: round-robin shard selection, possible per-shard reseed fetch, per-shard mutex wait, ChaCha20 output generation, atomic stats updates.
- Excluded operations:
  - Kyber encapsulation.
  - HKDF.
  - AEAD encryption.
  - Response signing.
- Name accuracy: accurate as end-to-end server entropy provider time, not as pure QRNG hardware time.
- Safe for paper: yes if defined as `server_entropy_provider_us`.
- Recommended better name: `server_entropy_provider_us`.

#### `encapsulation_us`

- File/function: `auth_server/src/api.rs`, `request_entropy`.
- Start point: immediately before `encapsulate_to_client_kem_pk_bytes(...)`.
- Stop point: after Kyber encapsulation returns.
- Included operations:
  - Client KEM public-key reconstruction/validation inside PQ wrapper, if performed there.
  - Kyber encapsulation.
- Excluded operations:
  - HKDF key derivation.
  - AEAD encryption.
- Name accuracy: accurate enough.
- Safe for paper: yes.
- Recommended better name: `server_kem_us`.

#### `encryption_us`

- File/function: `auth_server/src/api.rs`, `request_entropy`.
- Start point: before HKDF key derivation.
- Stop point: after AEAD encryption.
- Included operations:
  - HKDF from Kyber shared secret and client nonce.
  - AEAD nonce derivation.
  - AAD construction.
  - AEAD encryption.
- Excluded operations:
  - Kyber encapsulation.
  - Response transcript construction.
  - Response signing.
- Name accuracy: slightly broad. It is not AEAD encryption only.
- Safe for paper: safe if described as `server_key_derivation_and_encrypt_us`.
- Recommended better name: split into `server_hkdf_us` and `server_encrypt_us`; otherwise rename to `server_encrypt_pipeline_us`.

#### `response_sign_us`

- File/function: `auth_server/src/api.rs`, `request_entropy`.
- Start point: after response transcript construction, immediately before `state.pq.sign(&resp_tbs)`.
- Stop point: after signing returns.
- Included operations:
  - Server-side Dilithium signing of response transcript.
- Excluded operations:
  - Response transcript construction.
  - Base64 encoding.
  - JSON serialization.
- Name accuracy: accurate.
- Safe for paper: yes.
- Recommended better name: `server_response_sign_us`.

#### `serialize_us`

- File/function: `auth_server/src/api.rs`, `request_entropy`.
- Start point: immediately before constructing `EntropyResponse`.
- Stop point: immediately after the response struct is built.
- Included operations:
  - Moving/copying response fields into `EntropyResponse`.
  - Base64 encoding of KEM ciphertext, AEAD nonce, entropy ciphertext, and server signature.
- Excluded operations:
  - Actual JSON serialization by Axum.
  - HTTP response write.
- Name accuracy: misleading if interpreted as full serialization.
- Safe for paper: use only as response base64/build time.
- Recommended better name: `server_response_build_b64_us`.

### Server Entropy Stats Logging

#### `request_latency_us`

- File/function: `auth_server/src/api.rs`, tracing `info!("entropy request served")`.
- Start point: handler entry.
- Stop point: at the tracing call before final stage timing and before returning the response.
- Included operations:
  - Same successful-path handler work as `total_us`, except it stops slightly before final stage timing logging.
- Excluded operations:
  - Axum JSON response serialization and network send.
  - Stage timing `println!`.
- Name accuracy: too broad if read as client request latency.
- Safe for paper: use as server handler latency only.
- Recommended better name: `server_handler_latency_us`.

#### `lock_wait_us` / `entropy_wait_us`

- File/function: `auth_server/src/entropy.rs`, `EntropySource::bytes_with_stats`, parallel hybrid branch.
- Start point: immediately before `shard.state.lock().await`.
- Stop point: immediately after the shard mutex is acquired.
- Included operations:
  - Wait to acquire the selected shard mutex.
- Excluded operations:
  - Round-robin shard selection.
  - Reseed threshold check.
  - QRNG seed fetch during reseed.
  - ChaCha20 output generation.
  - Atomic stats updates.
  - Any global server request work outside entropy provider.
- Name accuracy: `lock_wait_us` is accurate; `entropy_wait_us` is ambiguous.
- Safe for paper: yes as CSPRNG shard mutex wait time for Config 3 only.
- Recommended better name: `server_entropy_shard_lock_wait_us`.

#### `total_entropy_wait_us`

- File/function: `auth_server/src/entropy.rs`, parallel hybrid branch.
- Start point: initialized at server startup.
- Stop point: incremented after each successful parallel-hybrid shard lock acquisition.
- Included operations:
  - Cumulative sum of per-request shard mutex wait times in Config 3.
- Excluded operations:
  - Direct QRNG and single hybrid modes, currently reported as zero.
  - Entropy generation time.
  - Reseed fetch time.
- Name accuracy: too broad; this is cumulative shard lock wait, not total entropy wait.
- Safe for paper: safe only for average Config 3 shard mutex contention if divided by a matching request count.
- Recommended better name: `total_entropy_shard_lock_wait_us`.

### Standalone IoT Client Path

The standalone `client_iot` command does decrypt the entropy response. In `client_iot/src/client.rs`, `request_entropy`:

- Generates nonce.
- Builds the canonical signing message.
- Signs the request.
- Sends HTTP JSON.
- Deserializes JSON response.
- Decodes response base64 fields.
- Kyber-decapsulates the server KEM ciphertext.
- Derives the AEAD key.
- Builds AAD.
- Decrypts entropy.
- Verifies the server signature over the ciphertext transcript.
- Returns plaintext entropy to `client_iot/src/main.rs`, which computes `SHA256(entropy)` for display.

There are currently no fine-grained timers in `client_iot`.

## 2. Direct Answers to the Timing Questions

1. Current benchmark total request latency includes client HTTP send through `send().await` completion. Server `total_us` includes server handler work from handler entry to timing log.
2. Benchmark latency does not include client-side signing. The standalone client path performs signing but does not time it.
3. Benchmark latency includes request JSON serialization. It does not include response body read/deserialization. Server `total_us` excludes Axum JSON extractor parse before handler entry and excludes final response JSON serialization.
4. Benchmark latency includes network round trip up to response availability. Server timings do not include network round trip.
5. Server `signature_verify_us` includes Dilithium verification. Benchmark latency includes it indirectly as part of server processing.
6. Server `nonce_check_us` includes nonce-cache lookup/insertion and possible cleanup. Benchmark latency includes it indirectly.
7. Server `entropy_us` includes entropy acquisition/generation. Benchmark latency includes it indirectly.
8. Server `encapsulation_us` includes Kyber encapsulation. Benchmark latency includes it indirectly.
9. Server `encryption_us` includes HKDF, nonce derivation, AAD construction, and AEAD encryption. Benchmark latency includes it indirectly.
10. Server `response_sign_us` includes response signing. Benchmark latency includes it indirectly.
11. Benchmark load-test latency does not include client-side Kyber decapsulation. Standalone `client_iot` does decapsulate but does not time it.
12. Benchmark load-test latency does not include client-side AEAD decryption. Standalone `client_iot` does decrypt but does not time it.
13. Benchmark load-test latency does not include `SHA256(entropy)`. Standalone `client_iot` computes SHA-256 after decrypting but does not time it.
14. Benchmark latency does not include summary stdout printing. It may include request-failure `eprintln!` only on error paths. Server `total_us` and `request_latency_us` do not include the timing `println!`, but normal tracing occurs before final timing logging on successful requests.

## 3. Gaps and Misleading Metrics

- `benchmark_client` does not currently measure usable plaintext entropy latency. It never decrypts or verifies responses in the load-test path; it only reads and discards the body after recording latency.
- `benchmark_client` latency excludes client-side request preparation: nonce generation, canonical message construction, and Dilithium signing.
- `benchmark_client` latency stops before `resp.text().await`, so it may undercount response body transfer and client body processing.
- Server `total_us` starts after Axum JSON extraction, so it excludes HTTP body parsing and request JSON deserialization.
- Server `serialize_us` is not actual JSON serialization. It is response struct construction plus base64 encoding.
- Server `parse_us` is not full parse time. It is request base64 decode time.
- Server `encryption_us` is broader than AEAD encryption because it includes HKDF, AEAD nonce derivation, and AAD construction.
- `entropy_us` is provider elapsed time, not pure hardware QRNG time.
- `total_entropy_wait_us` is cumulative Config 3 shard mutex wait only, not total entropy acquisition wait across modes.
- Standalone `client_iot` prints full request JSON in `IotClient::enroll` and `IotClient::request_entropy`. This is not inside benchmark timings, but it is noisy and should be gated behind verbose mode before using `client_iot` for timing experiments.

## 4. Recommended Metric Definitions

Ideal paper-facing metrics should be explicitly separated:

- `client_prepare_us`: key/context load, nonce generation, canonical message construction, and client signing. Exclude stdout.
- `network_roundtrip_us`: from immediately before HTTP send to after full response body is read. Exclude client signing and post-processing.
- `server_handler_us`: server handler entry through response object construction, using current `total_us` semantics.
- `server_verify_us`: Dilithium verification only.
- `server_nonce_us`: nonce cache lock, lookup, insertion, and cleanup.
- `server_entropy_provider_us`: configured entropy provider elapsed time.
- `server_entropy_shard_lock_wait_us`: Config 3 shard mutex wait only.
- `server_kem_us`: Kyber encapsulation only.
- `server_hkdf_us`: HKDF key derivation only.
- `server_encrypt_us`: AEAD encryption only.
- `server_response_sign_us`: server response signing only.
- `server_response_build_b64_us`: base64 encoding and response struct construction.
- `client_decap_us`: client Kyber decapsulation only.
- `client_decrypt_us`: client AEAD decrypt only.
- `client_response_verify_us`: client verification of server response signature.
- `client_postprocess_us`: response length check and optional SHA-256 digest. Exclude stdout.
- `end_to_end_usable_entropy_us`: start before client preparation, stop when plaintext entropy is available and verified. Exclude stdout/logging where possible.

## 5. Minimal Code Changes Required for Paper-Accurate Timing

1. In `benchmark_client`, move the current timer or add separate timers:
   - Start `client_prepare_us` before `build_signed_request`.
   - Start `network_roundtrip_us` immediately before `.send()`.
   - Stop `network_roundtrip_us` only after reading the full response body.
2. In `benchmark_client`, optionally parse successful responses and run the same client-side decapsulation, decrypt, and response-signature verification path used by `client_iot`.
   - This requires storing or reconstructing KEM secret keys in benchmark users, not only signing keys, if not already available.
   - If that is too invasive, keep current benchmark as HTTP-service latency and do not call it usable entropy latency.
3. In `auth_server`, rename or duplicate stage fields to avoid ambiguity:
   - `parse_us` -> `request_b64_decode_us`.
   - `serialize_us` -> `response_build_b64_us`.
   - `encryption_us` -> split into `hkdf_us` and `encrypt_us`, or rename to `encrypt_pipeline_us`.
   - `total_us` -> `server_handler_us`.
4. In `auth_server`, if full server serialization time matters, wrap response conversion explicitly or add middleware/tower tracing that measures response future completion. Current handler-level timing cannot see Axum's final JSON serialization and socket write.
5. In `client_iot`, gate full request JSON printing behind a verbose flag before collecting any client-side timing.
6. In both clients, ensure stdout printing occurs after timers stop.

## 6. Measurement Validation Checklist

- Confirm `ENABLE_STAGE_TIMING=1` emits one JSONL timing record per entropy request.
- Confirm server timing records show non-null values for successful requests: `signature_verify_us`, `nonce_check_us`, `entropy_us`, `encapsulation_us`, `encryption_us`, `response_sign_us`, `serialize_us`, and `total_us`.
- Run a known replay and confirm the server record has `status_code=409`, with nonce timing populated and entropy/KEM/encrypt/sign timings omitted.
- Run an invalid signature and confirm `status_code=401`, with signature timing populated and nonce timing omitted.
- Compare `benchmark_client` latency with server `total_us`; the client value should be greater because it includes network/client HTTP overhead, but it currently may not include full body consumption.
- In Config 3, compute average shard lock wait as `total_entropy_wait_us / successful_parallel_hybrid_requests`, and label it as shard mutex wait only.
- Validate that stdout/logging volume is stable across benchmark runs, or disable/gate verbose request JSON printing for timing experiments.
- For publication runs, record whether reported client latency is HTTP response availability or verified plaintext entropy availability.
