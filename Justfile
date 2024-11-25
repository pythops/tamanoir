set export

# List available targets
default:
    just --list

# Build ebpf
build-ebpf:
    #!/usr/bin/env bash
    pushd tamanoir-ebpf
    cargo build  --release
    popd


# Build
build:
    cargo build --release


# Run
run:
    #!/usr/bin/env bash
    just build-ebpf
    RUST_LOG=info cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --target-ip 52.54.115.226 --hijack-ip 8.8.8.8 --layout 1

# Run the proxy
proxy:
    #!/usr/bin/env bash
    pushd proxy &&  \
    docker build -t proxy . && \
    docker run --rm -p53:53/udp  proxy --log +error,-data,-request,-reply,-recv --log-prefix --passthrough
