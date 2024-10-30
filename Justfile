set export

# List available targets
default:
    just --list


# Run
run:
    RUST_LOG=info cargo xtask run -- --target-ip 2.248.235.89 --hijack-ip 1.1.1.1

proxy:
    cd proxy && docker build -t proxy . && docker run -it --rm -p54:53/udp  proxy   --log +error,+data,-request,-reply,-recv --log-prefix --passthrough
