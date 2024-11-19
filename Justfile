set export

# List available targets
default:
    just --list

# Run
run:
    RUST_LOG=info cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --target-ip 52.54.115.226 --hijack-ip 8.8.8.8 --layout 1

# Run the proxy
proxy:
    cd proxy && docker build -t proxy . && docker run -it --rm -p53:53/udp  proxy   --log +error,-data,-request,-reply,-recv --log-prefix --passthrough
