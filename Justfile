set export

# List available targets
default:
    just --list


# Run
run:
    RUST_LOG=info cargo xtask run -- --target-ip 192.168.1.180 --hijack-ip 8.8.8.8

proxy:
    cd proxy && docker build -t proxy . && docker run -it --rm -p 54:53/udp proxy  -u 1.1.1.1:53 --log +request,+reply,+error,+data,+recv --log-prefix --passthrough