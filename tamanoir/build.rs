use std::{
    env, fs,
    io::{BufRead as _, BufReader},
    path::PathBuf,
    process::{Child, Command, Stdio},
};

use cargo_metadata::{
    Artifact, CompilerMessage, Message, Metadata, MetadataCommand, Package, Target,
};
use xtask::AYA_BUILD_EBPF;

/// This crate has a runtime dependency on artifacts produced by the `tamanoir-ebpf` crate.
/// This would be better expressed as one or more [artifact-dependencies][bindeps] but issues such
/// as:
///
/// * https://github.com/rust-lang/cargo/issues/12374
/// * https://github.com/rust-lang/cargo/issues/12375
/// * https://github.com/rust-lang/cargo/issues/12385
///
/// prevent their use for the time being.
///
/// This file, along with the xtask crate, allows analysis tools such as `cargo check`, `cargo
/// clippy`, and even `cargo build` to work as users expect. Prior to this file's existence, this
/// crate's undeclared dependency on artifacts from `tamanoir-ebpf` would cause build (and
/// `cargo check`, and `cargo clippy`) failures until the user ran certain other commands in the
/// workspace. Conversely, those same tools (e.g. cargo test --no-run) would produce stale results
/// if run naively because they'd make use of artifacts from a previous build of
/// `tamanoir-ebpf`.
///
/// Note that this solution is imperfect: in particular it has to balance correctness with
/// performance; an environment variable is used to replace true builds of `tamanoir-ebpf`
/// with stubs to preserve the property that code generation and linking (in
/// `tamanoir-ebpf`) do not occur on metadata-only actions such as `cargo check` or `cargo
/// clippy` of this crate. This means that naively attempting to `cargo test --no-run` this crate
/// will produce binaries that fail at runtime because the stubs are inadequate for actually running
/// the tests.
///
/// [bindeps]: https://doc.rust-lang.org/nightly/cargo/reference/unstable.html?highlight=feature#artifact-dependencies
fn main() {
    println!("cargo:rerun-if-env-changed={}", AYA_BUILD_EBPF);

    let build_ebpf = env::var(AYA_BUILD_EBPF)
        .as_deref()
        .map(str::parse)
        .map(Result::unwrap)
        .unwrap_or_default();

    let Metadata { packages, .. } = MetadataCommand::new().no_deps().exec().unwrap();
    let ebpf_package = packages
        .into_iter()
        .find(|Package { name, .. }| name == "tamanoir-ebpf")
        .unwrap();

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir = PathBuf::from(out_dir);

    let endian = env::var_os("CARGO_CFG_TARGET_ENDIAN").unwrap();
    let target = if endian == "big" {
        "bpfeb"
    } else if endian == "little" {
        "bpfel"
    } else {
        panic!("unsupported endian={:?}", endian)
    };

    if build_ebpf {
        let arch = env::var_os("CARGO_CFG_TARGET_ARCH").unwrap();

        let target = format!("{target}-unknown-none");

        let Package { manifest_path, .. } = ebpf_package;
        let ebpf_dir = manifest_path.parent().unwrap();

        // We have a build-dependency on `tamanoir-ebpf`, so cargo will automatically rebuild us
        // if `tamanoir-ebpf`'s *library* target or any of its dependencies change. Since we
        // depend on `tamanoir-ebpf`'s *binary* targets, that only gets us half of the way. This
        // stanza ensures cargo will rebuild us on changes to the binaries too, which gets us the
        // rest of the way.
        println!("cargo:rerun-if-changed={}", ebpf_dir.as_str());

        let mut cmd = Command::new("cargo");
        cmd.args([
            "build",
            "-Z",
            "build-std=core",
            "--bins",
            "--message-format=json",
            "--release",
            "--target",
            &target,
        ]);

        cmd.env("CARGO_CFG_BPF_TARGET_ARCH", arch);

        // Workaround to make sure that the rust-toolchain.toml is respected.
        for key in ["RUSTUP_TOOLCHAIN", "RUSTC"] {
            cmd.env_remove(key);
        }
        cmd.current_dir(ebpf_dir);

        // Workaround for https://github.com/rust-lang/cargo/issues/6412 where cargo flocks itself.
        let ebpf_target_dir = out_dir.join("tamanoir-ebpf");
        cmd.arg("--target-dir").arg(&ebpf_target_dir);

        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|err| panic!("failed to spawn {cmd:?}: {err}"));
        let Child { stdout, stderr, .. } = &mut child;

        // Trampoline stdout to cargo warnings.
        let stderr = stderr.take().unwrap();
        let stderr = BufReader::new(stderr);
        let stderr = std::thread::spawn(move || {
            for line in stderr.lines() {
                let line = line.unwrap();
                println!("cargo:warning={line}");
            }
        });

        let stdout = stdout.take().unwrap();
        let stdout = BufReader::new(stdout);
        let mut executables = Vec::new();
        for message in Message::parse_stream(stdout) {
            #[allow(clippy::collapsible_match)]
            match message.expect("valid JSON") {
                Message::CompilerArtifact(Artifact {
                    executable,
                    target: Target { name, .. },
                    ..
                }) => {
                    if let Some(executable) = executable {
                        executables.push((name, executable.into_std_path_buf()));
                    }
                }
                Message::CompilerMessage(CompilerMessage { message, .. }) => {
                    for line in message.rendered.unwrap_or_default().split('\n') {
                        println!("cargo:warning={line}");
                    }
                }
                Message::TextLine(line) => {
                    println!("cargo:warning={line}");
                }
                _ => {}
            }
        }

        let status = child
            .wait()
            .unwrap_or_else(|err| panic!("failed to wait for {cmd:?}: {err}"));
        assert_eq!(status.code(), Some(0), "{cmd:?} failed: {status:?}");

        stderr.join().map_err(std::panic::resume_unwind).unwrap();

        for (name, binary) in executables {
            let dst = out_dir.join(name);
            let _: u64 = fs::copy(&binary, &dst)
                .unwrap_or_else(|err| panic!("failed to copy {binary:?} to {dst:?}: {err}"));
        }
    } else {
        let Package { targets, .. } = ebpf_package;
        for Target { name, kind, .. } in targets {
            if *kind != ["bin"] {
                continue;
            }
            let dst = out_dir.join(name);
            fs::write(&dst, []).unwrap_or_else(|err| panic!("failed to create {dst:?}: {err}"));
        }
    }
}
