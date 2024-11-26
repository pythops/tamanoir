set export
_default:
    @just --list

# Build ebpf
build-ebpf:
    cd tamanoir-ebpf && cargo +nightly build --release


# Build
build:
    just build-ebpf
    cargo build --release

# Run
run proxy_ip="52.54.115.226" hijack_ip="8.8.8.8" layout="1" log_lvl="info":
    RUST_LOG={{log_lvl}} sudo -E target/release/tamanoir --target-ip {{proxy_ip}} --hijack-ip {{hijack_ip}} --layout {{layout}}

# Run the proxy
proxy:
    cd proxy &&\
    docker build -t proxy . &&\
    docker run --rm -it -p 53:53/udp  proxy --log +error,-data,-request,-reply,-recv --log-prefix --passthrough
