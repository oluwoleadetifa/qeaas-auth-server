# QEaaS Build and QRNG Workstation Setup

This project is intended to be validated primarily on the Ubuntu 18 / Linux kernel 4 workstation that hosts the ID Quantique PCIe QRNG card. macOS can be useful for ordinary development, formatting, and static checks, but the publication experiments should be run on the QRNG workstation because the QRNG card depends on legacy kernel and driver compatibility.

## Primary Target: Ubuntu 18 / Linux Kernel 4

Install baseline build dependencies:

```sh
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev clang cmake git curl
```

Install Rust:

```sh
curl https://sh.rustup.rs -sSf | sh
source "$HOME/.cargo/env"
rustup default stable
```

Verify the toolchain:

```sh
rustc --version
cargo --version
pkg-config --version
openssl version
```

The QRNG workstation should already have the ID Quantique driver and kernel setup working before QEaaS benchmarks are run. QEaaS does not install or configure the kernel driver.

Verify QRNG device availability using the device path currently used by the QRNG service:

```sh
ls -l /dev/qrandom0
```

The QRNG server reads entropy from `/dev/qrandom0`. If that path is missing, fix the ID Quantique driver/device setup before running QEaaS benchmarks.

Build and test on the QRNG workstation:

```sh
cd qrng_server
cargo test
```

```sh
cd ../auth_server
cargo test
```

```sh
cd ../benchmark_client
cargo test
```

```sh
cd ../client_iot
cargo test
```

Run the usual static checks before experiment runs:

```sh
cargo fmt -- --check
cargo clippy -- -D warnings
```

Run those commands inside each Rust crate, or use a local wrapper if you add one later.

## QRNG Service Smoke Check

Start the QRNG service on the QRNG workstation:

```sh
cd qrng_server
cargo run --release
```

In another terminal, check that the service can return entropy:

```sh
curl http://127.0.0.1:8080/random/32
```

Then start the authenticated QEaaS service in the desired mode, for example:

```sh
cd auth_server
ENTROPY_MODE=direct_qrng cargo run --release
```

## Troubleshooting

### `ld: library 'crypto' not found`

This means the linker cannot find OpenSSL/libcrypto for an OQS-dependent crate.

On Ubuntu:

```sh
sudo apt install -y libssl-dev pkg-config
cargo clean
cargo test
```

Also verify:

```sh
pkg-config --libs openssl
openssl version
```

### Missing `pkg-config`

Install it:

```sh
sudo apt install -y pkg-config
```

Then rebuild:

```sh
cargo clean
cargo test
```

### Missing `libssl-dev`

Install OpenSSL development headers:

```sh
sudo apt install -y libssl-dev
```

Then rebuild:

```sh
cargo clean
cargo test
```

### OQS / liboqs Native Dependency Issues

The Rust `oqs` dependency builds native code and may require a working C/C++ toolchain, CMake, Clang, and OpenSSL development libraries.

On Ubuntu:

```sh
sudo apt install -y build-essential clang cmake pkg-config libssl-dev
cargo clean
cargo test
```

If the build still fails, rerun with verbose output:

```sh
cargo test -vv
```

### QRNG Device Path Not Found

The QRNG server expects:

```text
/dev/qrandom0
```

Check:

```sh
ls -l /dev/qrandom0
```

If the device is missing, confirm that the ID Quantique PCIe card is installed, the legacy Linux kernel/driver setup is loaded, and the device node exists before starting QEaaS.

### Optional macOS Developer Setup

macOS is not the primary QEaaS experiment target. If you use macOS for development and encounter `ld: library 'crypto' not found`, install OpenSSL with Homebrew and expose it to Cargo:

```sh
brew install openssl@3 pkg-config
export OPENSSL_DIR="$(brew --prefix openssl@3)"
export PKG_CONFIG_PATH="$OPENSSL_DIR/lib/pkgconfig"
cargo clean
cargo test
```

Do not commit Homebrew paths or machine-specific paths to source files.
