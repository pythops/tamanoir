set export
_default:
    @just --list

# Build ebpf
build-ebpf:
    cd tamanoir-ebpf && cargo build --release

# Build
build:
    just build-ebpf
    cargo build --release

# Run
run proxy_ip hijack_ip="8.8.8.8" layout="1" log_level="info":
    RUST_LOG={{log_level}} sudo -E target/release/tamanoir --proxy-ip {{proxy_ip}} --hijack-ip {{hijack_ip}} --layout {{layout}}

# Run the proxy
proxy dns_ip="8.8.8.8" port="53" payload_len="8" log_level="info" :
    cd tamanoir-proxy && \
    cargo build --release  &&\
    RUST_LOG={{log_level}} sudo -E ./target/release/tamanoir-proxy  --port {{port}} --dns-ip {{dns_ip}} --payload-len {{payload_len}}
