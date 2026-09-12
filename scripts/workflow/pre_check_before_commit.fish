#!/usr/bin/env fish

set -l script_dir (dirname (status filename))
set -l workspace_root (realpath "$script_dir/../..")

if test (basename "$workspace_root") != oxidrop
    echo "ERROR: expected workspace root directory to be named 'oxidrop': $workspace_root" >&2
    exit 1
end

set -l git_root (git -C "$workspace_root" rev-parse --show-toplevel 2>/dev/null)
if test "$git_root" != "$workspace_root"
    echo "ERROR: script is not inside the expected Git workspace: $workspace_root" >&2
    exit 1
end

for required_directory in frontend oxidrop oxidrop-ebpf
    if not test -d "$workspace_root/$required_directory"
        echo "ERROR: required workspace directory is missing: $workspace_root/$required_directory" >&2
        exit 1
    end
end

for required_file in Cargo.toml frontend/package.json oxidrop/Cargo.toml oxidrop-ebpf/Cargo.toml
    if not test -f "$workspace_root/$required_file"
        echo "ERROR: required workspace file is missing: $workspace_root/$required_file" >&2
        exit 1
    end
end

cd "$workspace_root"
or begin
    echo "ERROR: failed to change to workspace root: $workspace_root" >&2
    exit 1
end

echo "Checking Rust formatting with nightly rustfmt..."
cargo +nightly fmt --all -- --check
or begin
    echo "ERROR: nightly cargo fmt check failed." >&2
    exit 1
end

echo "Checking the Rust workspace..."
cargo check
or begin
    echo "ERROR: cargo check failed." >&2
    exit 1
end

echo "Checking the eBPF program..."
cargo +nightly check -p oxidrop-ebpf --target bpfel-unknown-none -Z build-std=core
or begin
    echo "ERROR: eBPF cargo check failed." >&2
    exit 1
end

echo "Running Rust tests..."
cargo test
or begin
    echo "ERROR: cargo test failed." >&2
    exit 1
end

echo "Generating the frontend API client..."
cd "$workspace_root/frontend"
or begin
    echo "ERROR: failed to change to the frontend directory." >&2
    exit 1
end

deno task generate:api
or begin
    echo "ERROR: frontend API generation failed." >&2
    exit 1
end

echo "Formatting the frontend..."
deno fmt
or begin
    echo "ERROR: frontend formatting failed." >&2
    exit 1
end

echo "Running frontend tests..."
deno task test
or begin
    echo "ERROR: frontend tests failed." >&2
    exit 1
end

echo "Building the frontend..."
deno task build
or begin
    echo "ERROR: frontend build failed." >&2
    exit 1
end

echo "All pre-commit checks passed."
