set export

# List available targets
default:
    just --list


# Run
run:
    RUST_LOG=info cargo xtask run -- --target-ip 1.1.1.1 --hijack-ip 8.8.8.8
