use std::env;

use which::which;
use xtask::AYA_BUILD_EBPF;

fn main() {
    println!("cargo:rerun-if-env-changed={}", AYA_BUILD_EBPF);

    let build_ebpf = env::var(AYA_BUILD_EBPF)
        .as_deref()
        .map(str::parse)
        .map(Result::unwrap)
        .unwrap_or_default();

    if build_ebpf {
        let bpf_linker = which("bpf-linker").unwrap();
        println!("cargo:rerun-if-changed={}", bpf_linker.to_str().unwrap());
    }
}
