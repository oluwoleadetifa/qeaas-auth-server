# Phase 1 Timing Upgrade

This document describes the client-side timing instrumentation added for Phase 1. The cryptographic protocol, request signing message, auth server endpoints, and benchmark throughput calculations are unchanged.

## Scope

Changed crate:

- `client_iot`

Unaffected behavior:

- `benchmark_client` throughput and latency calculations are unchanged.
- `benchmark_client` does not print request JSON.
- The authenticated request format remains:

```text
device_id || 0x00 || n(u64 LE) || 0x00 || nonce
```

## Verbose Output

`client_iot` is quiet by default.

Default output does not include:

- `ENTROPY_REQUEST_JSON`
- enrollment JSON
- private keys
- cryptographic transcripts

Detailed request/enrollment JSON is printed only when `--verbose` is supplied.

## New Client-Side Metrics

The `client_iot request` command now prints the following timing fields after the request has completed and after all measured timers have stopped.

### `client_prepare_us`

Measured in: `client_iot/src/client.rs`, `IotClient::request_entropy_timed`.

Start: immediately before nonce generation.

Stop: immediately after the signed `EntropyRequest` struct is built.

Includes:

- client nonce generation
- canonical request message construction
- client-side request signing
- base64 encoding of nonce and signature into the request object
- request struct construction

Excludes:

- device credential loading from disk
- device key reconstruction from saved state
- verbose JSON serialization
- stdout printing
- HTTP request serialization and transmission
- server processing
- response handling

### `client_decap_us`

Measured in: `client_iot/src/client.rs`, `IotClient::request_entropy_timed`.

Start: immediately before client Kyber decapsulation.

Stop: immediately after decapsulation returns.

Includes:

- Kyber decapsulation of the server KEM ciphertext using the client KEM secret key

Excludes:

- base64 decoding of the KEM ciphertext
- HKDF key derivation
- AEAD decryption
- server response signature verification
- stdout printing

### `client_decrypt_us`

Measured in: `client_iot/src/client.rs`, `IotClient::request_entropy_timed`.

Start: immediately before AEAD decrypt.

Stop: immediately after AEAD decrypt returns plaintext entropy.

Includes:

- AEAD decrypt of `entropy_ct`
- authentication tag verification performed by the AEAD implementation

Excludes:

- Kyber decapsulation
- HKDF key derivation
- AAD construction
- response signature verification
- entropy hashing
- stdout printing

### `client_response_verify_us`

Measured in: `client_iot/src/client.rs`, `IotClient::request_entropy_timed`.

Start: immediately before verifying the server response signature.

Stop: immediately after server signature verification returns.

Includes:

- verification of the server signature over the response transcript

Excludes:

- base64 decoding of the server signature
- server public-key base64 decoding
- response transcript construction
- AEAD decryption
- entropy hashing
- stdout printing

### `client_postprocess_us`

Measured in: `client_iot/src/main.rs`, `request`.

Start: immediately before computing final client display values.

Stop: immediately after those values are computed.

Includes:

- plaintext entropy length read
- `SHA256(entropy)` computation

Excludes:

- stdout printing of status, device ID, entropy length, hash, or timing fields
- server response verification
- AEAD decryption
- network round trip

### `end_to_end_usable_entropy_us`

Measured in: `client_iot/src/client.rs`, `IotClient::request_entropy_timed`.

Start: immediately before client request preparation begins.

Stop: immediately after the server response signature has been verified.

Includes:

- nonce generation
- canonical request message construction
- client request signing
- request object construction
- HTTP request JSON serialization by reqwest
- HTTP request transmission
- network round trip
- server processing time
- HTTP response receipt
- response JSON deserialization
- response parameter checks
- base64 decoding of response fields
- client Kyber decapsulation
- HKDF key derivation
- AAD construction
- AEAD decryption to plaintext entropy
- response transcript construction
- server response signature verification

Excludes:

- device credential loading from disk
- device key reconstruction from saved state
- verbose request JSON serialization
- stdout printing
- `SHA256(entropy)` computation

Interpretation: this is the elapsed time from client request preparation start until verified plaintext entropy is available to the client.

## Timing Hygiene

- All new timing measurements stop before stdout printing.
- `--verbose` request JSON serialization and printing occurs after `end_to_end_usable_entropy_us` has stopped.
- Default client output remains suitable for timing experiments because it prints only after request completion and postprocess timing.
- `benchmark_client` request JSON printing remains disabled; no benchmark throughput logic was changed in this phase.

## Remaining Accuracy Notes

- `client_prepare_us` currently excludes disk credential loading and saved-key reconstruction because those occur before `IotClient::request_entropy_timed` is called.
- `end_to_end_usable_entropy_us` excludes `client_postprocess_us`; the entropy is already plaintext and verified before postprocessing starts.
- Benchmark-client publication metrics still measure the existing benchmark path. They do not yet include client-side decapsulation, decryption, response verification, or usable-entropy timing.
