# Oxidrop

Oxidrop is a Linux stateful firewall built with eBPF and managed through
an Axum backend. The eBPF program is compiled and embedded by the backend
build.

## Install

Install the system dependencies on Debian or Ubuntu:

```shell
sudo apt install -y build-essential clang curl git libelf-dev llvm pkg-config redis-server
```

On Fedora, install the equivalent packages with:

```shell
sudo dnf group install -y development-tools
sudo dnf install -y clang curl elfutils-libelf-devel git llvm pkgconf-pkg-config redis
```

Install Rust, the nightly source component, and the eBPF linker:

```shell
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup toolchain install stable
rustup toolchain install nightly --component rust-src
cargo install bpf-linker --locked
```

Install Oxidrop directly from GitHub with Cargo:

```shell
cargo install --git https://github.com/MythicByte/Oxidrop.git \
  --package oxidrop \
  --locked
```

Start Redis, which is used by the default session store:

```shell
sudo systemctl enable --now redis
```

The backend uses SQLite and creates `oxidrop.db` in the working directory.

## Build and run

Run the installed backend with:

```shell
oxidrop
```

Loading and attaching the eBPF program may require elevated privileges. If the
command fails with a permissions error, run it with `sudo`:

```shell
sudo oxidrop
```

Alternatively, grant the installed binary the required Linux capabilities and
run it as your normal user:

```shell
sudo setcap cap_bpf,cap_net_admin,cap_perfmon+ep "$(command -v oxidrop)"
oxidrop
```

The capabilities approach depends on your kernel and distribution security
policy; use `sudo oxidrop` if it is not supported.

## Configuration

To display the available configuration options:

```shell
cargo run -- --help
```

The backend accepts:

```text
      --http-port <HTTP_PORT>                HTTP port (default: 3000)
  -i, --incoming-adapter <INCOMING_ADAPTER>  incoming network interface index
  -o, --output-adapter <OUTPUT_ADAPTER>      outgoing network interface index
```

For example:

```shell
sudo oxidrop \
  --http-port 3000 \
  --incoming-adapter 2 \
  --output-adapter 3
```

Loading and attaching the eBPF program requires the privileges provided by
`sudo` or an equivalent service capability configuration.

## Development checks

The repository check script runs formatting, Rust checks, eBPF checks, tests,
and frontend checks:

```shell
./scripts/workflow/pre_check_before_commit.fish
```

The namespace and eBPF integration tests require elevated Linux networking
privileges. The frontend is not required to build or run the Axum backend.

## Acknowledgements

Oxidrop uses [Aya](https://github.com/aya-rs/aya) to load and manage its Rust
eBPF programs.

## License

All code is distributed under the terms of the
[GNU General Public License, Version 2](LICENSE-GPL2).
