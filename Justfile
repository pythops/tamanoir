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
run proxy_ip="52.54.115.226" hijack_ip="8.8.8.8" layout="1":
    #!/usr/bin/env bash
    just build-ebpf
    RUST_LOG=info cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --target-ip {{proxy_ip}} --hijack-ip {{hijack_ip}} --layout {{layout}}

# Run the proxy
proxy:
    #!/usr/bin/env bash
    pushd proxy &&  \
    docker build -t proxy . && \
    docker run --rm -p 53:53  proxy --log +error,-data,-request,-reply,-recv --log-prefix --passthrough
