<div align="center">
  <h1> Tamanoir </h1>
  <img src="https://github.com/user-attachments/assets/47b8a0ef-6a52-4e2d-8188-e77bb9e98d79" style="width: 40%; height: 40%"</img>
</div>

## 💡Overview

<div align="center">
  <img src="https://github.com/user-attachments/assets/24f80020-9d60-4f2a-825b-ed56574dfb24" </img>
</div>

<br>

## 🪄 Usage

### Dns Proxy

Make sure you have:

- `docker` installed.
- [just](https://github.com/casey/just) installed.

```
just proxy
```

### Tamanoir

Before using `Tamanoir`, make sure you have:

- A Linux based OS.
- [just](https://github.com/casey/just) installed.
- [Rust](https://www.rust-lang.org/tools/install) installed with `nightly` toolchain.

1. Build `Tamanoir` from source

```
just build
```

2. Run

```
just run <Locally onfigured DNS server IP> <DNS Proxy IP> <keyboard layout>
```

for examples:

```
just run 8.8.8.8 192.168.1.75 0
```

Currenly, there is only 2 supported keyboard layout:

`0` : qwery (us)

`1` : azerty (fr)

## 🛠️TODO

- [ ] Automatic discovery of the configured local dns server
- [ ] Automatic discovery of the keyboard layout

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
