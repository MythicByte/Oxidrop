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
rustup toolchain install stable
rustup toolchain install nightly --component rust-src
cargo install bpf-linker --locked
```

Install Deno because the Cargo build compiles the frontend before embedding
its assets into the backend binary:

```shell
curl -fsSL https://deno.land/install.sh | sh
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

### Initial administrator account

On first start, Oxidrop creates the default administrator account:

```text
Username: admin
Password: password
```

The administrator must change this password immediately after the first
login. If all users are deleted, Oxidrop automatically recreates this default
administrator account and requires its password to be changed again.

## Build and run

Run the installed backend with:

```shell
sudo oxidrop
```

Once the backend is running, open the web interface at
[https://127.0.0.1:3000](https://127.0.0.1:3000). The server uses HTTPS with a
development self-signed certificate, so your browser will display a certificate
warning the first time. You can also use
[https://localhost:3000](https://localhost:3000).

If you set a different port with `--http-port`, replace `3000` in the links
with that port, for example:
[https://127.0.0.1:8080](https://127.0.0.1:8080).

Creating eBPF maps and attaching the programs requires elevated Linux
privileges. Running the installed binary without `sudo` can fail with
`Operation not permitted` while creating the `AYA_LOGS` map. If you want to
run it as your normal user instead, grant the binary the required capabilities:

```shell
sudo setcap cap_bpf,cap_net_admin,cap_perfmon+ep "$(command -v oxidrop)"
oxidrop
```

The capabilities approach depends on your kernel and distribution security
policy; use `sudo oxidrop` if it is not supported.

## Configuration

To display the available configuration options:

```shell
oxidrop --help
```

The backend accepts:

```text
  -p, --http-port <HTTP_PORT>
          choose http port [default: 3000]
  -i, --incoming-adapter <INCOMING_ADAPTER>
          The network interface index for incoming traffic (e.g., 2)
  -o, --output-adapter <OUTPUT_ADAPTER>
          The network interface index for outgoing traffic (e.g., 3)
  -h, --help
          Print help
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
privileges. The frontend is compiled and embedded during the backend build, so
the installed binary does not need the source checkout or `frontend/dist` at
runtime.

## Acknowledgements

Oxidrop uses [Aya](https://github.com/aya-rs/aya) to load and manage its Rust
eBPF programs.

## License

All code is distributed under the terms of the
[GNU General Public License, Version 2](LICENSE-GPL2).
