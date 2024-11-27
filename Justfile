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
run proxy_ip hijack_ip="8.8.8.8" layout="1" log_level="info":
    RUST_LOG={{log_level}} sudo -E target/release/tamanoir --proxy-ip {{proxy_ip}} --hijack-ip {{hijack_ip}} --layout {{layout}}

# Run the proxy
proxy c_manager="docker":
    cd proxy && \
    {{c_manager}} build -t proxy . &&\
    {{c_manager}} run --rm -it -p 53:53/udp -e PAYLOAD_LEN=8  proxy
