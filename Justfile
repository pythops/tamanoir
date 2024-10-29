set export

# List available targets
default:
    just --list


# Run
run:
    RUST_LOG=info cargo xtask run -- --target-ip 2.248.235.89 --hijack-ip 1.1.1.1

proxy:
    cd proxy && docker build -t proxy . && docker run -it --rm  proxy   --log +request,+reply,+error,+data,+recv --log-prefix --passthrough
