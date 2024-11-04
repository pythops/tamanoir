set export

# List available targets
default:
    just --list


# Run
run:
    RUST_LOG=info cargo xtask run -- --target-ip 52.54.115.226 --hijack-ip 8.8.8.8

proxy:
    cd proxy && docker build -t proxy . && docker run -it --rm -p53:53/udp  proxy   --log +error,-data,-request,-reply,-recv --log-prefix --passthrough

