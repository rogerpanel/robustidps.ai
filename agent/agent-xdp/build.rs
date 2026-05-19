//! Build script for `agent-xdp`.
//!
//! Compiles `bpf/xdp_drop.bpf.c` into `$OUT_DIR/xdp_drop.bpf.o` using clang
//! targeting the BPF backend. The userspace crate then embeds the resulting
//! object via `include_bytes!`.
//!
//! ## Graceful degradation
//!
//! If `clang` is not on `$PATH`, or compilation fails, this script writes a
//! zero-byte placeholder at `$OUT_DIR/xdp_drop.bpf.o` and emits a cargo
//! warning. The build proceeds; `XdpAgent::start` then fails fast at
//! runtime with a structured error pointing the operator at the build log.
//!
//! This lets `cargo build -p agent-xdp` succeed in environments without a
//! BPF toolchain (CI smoke tests, dev laptops on macOS / Windows / etc.) so
//! the workspace stays buildable. The actual XDP runtime is only viable on
//! Linux with kernel ≥ 5.7 + clang-bpf + libbpf-headers anyway.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));

    let src = manifest_dir.join("bpf").join("xdp_drop.bpf.c");
    let dst = out_dir.join("xdp_drop.bpf.o");

    println!("cargo:rerun-if-changed={}", src.display());
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=BPF_CLANG");
    println!("cargo:rerun-if-env-changed=BPF_CFLAGS");

    if let Err(e) = compile_bpf(&src, &dst) {
        println!(
            "cargo:warning=BPF compile skipped — emitting zero-byte placeholder at {}. \
             XdpAgent::start will fail at runtime until this is rebuilt on a host \
             with clang ≥ 14 + bpf-headers installed. Reason: {e}",
            dst.display()
        );
        if let Err(e) = std::fs::write(&dst, b"") {
            // We genuinely cannot write OUT_DIR — that's a hard failure.
            panic!("failed to write placeholder BPF object at {}: {e}", dst.display());
        }
    }
}

fn compile_bpf(src: &Path, dst: &Path) -> Result<(), String> {
    if !src.exists() {
        return Err(format!("BPF source missing: {}", src.display()));
    }

    let clang = env::var("BPF_CLANG").unwrap_or_else(|_| "clang".to_string());
    if !is_on_path(&clang) {
        return Err(format!("`{clang}` not on $PATH (set BPF_CLANG to override)"));
    }

    // The default flags compile a BTF-enabled relocatable BPF object suitable
    // for libbpf-style loaders (which aya uses internally).
    // Detect host arch for the bpf-elf endianness target. Default to
    // little-endian (bpfel) which covers x86_64 + aarch64 + most cloud VMs;
    // big-endian users (s390x, etc.) can override via BPF_CLANG_TARGET.
    let bpf_target = env::var("BPF_CLANG_TARGET").unwrap_or_else(|_| "bpfel".to_string());
    let target_arg = format!("--target={bpf_target}");

    // Pass __TARGET_ARCH_<arch> so libbpf's bpf_helpers.h selects the right
    // pt_regs layout. Doesn't affect XDP programs but keeps the BPF object
    // forward-compatible with helpers that need it.
    let arch_define = if cfg!(target_arch = "x86_64") {
        "-D__TARGET_ARCH_x86"
    } else if cfg!(target_arch = "aarch64") {
        "-D__TARGET_ARCH_arm64"
    } else {
        // Fallback — caller can override via BPF_CFLAGS.
        "-D__TARGET_ARCH_x86"
    };

    let default_cflags: Vec<String> = vec![
        "-O2".into(),
        "-g".into(),
        target_arg,
        arch_define.to_string(),
        "-Wall".into(),
        "-Werror".into(),
        // Disable a few warnings that fire on libbpf's stdint shims under
        // newer clang releases.
        "-Wno-unused-function".into(),
        "-Wno-pointer-sign".into(),
        "-Wno-compare-distinct-pointer-types".into(),
        "-Wno-deprecated-declarations".into(),
        "-Wno-gnu-variable-sized-type-not-at-end".into(),
        "-Wno-address-of-packed-member".into(),
    ];

    let extra: Vec<String> = env::var("BPF_CFLAGS")
        .ok()
        .map(|s| s.split_whitespace().map(|x| x.to_string()).collect())
        .unwrap_or_default();

    let mut cmd = Command::new(&clang);
    for f in &default_cflags {
        cmd.arg(f);
    }
    for f in &extra {
        cmd.arg(f);
    }
    cmd.arg("-c").arg(src).arg("-o").arg(dst);

    let output = cmd
        .output()
        .map_err(|e| format!("failed to spawn `{clang}`: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "{clang} exited with {}: stderr=\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    if !dst.exists() {
        return Err(format!("{clang} did not produce {}", dst.display()));
    }

    // Post-process: embed BTF info via `pahole -J`. aya's loader requires
    // a `.BTF` section in the BPF object; clang only emits DWARF debug
    // info, which pahole converts. Without this step the loader fails
    // with "error parsing ELF data".
    let pahole = env::var("BPF_PAHOLE").unwrap_or_else(|_| "pahole".to_string());
    if is_on_path(&pahole) {
        let out = Command::new(&pahole)
            .arg("-J")
            .arg(dst)
            .output()
            .map_err(|e| format!("failed to spawn `{pahole}`: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "{pahole} -J failed ({}): stderr=\n{}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            ));
        }
    } else {
        return Err(format!(
            "`{pahole}` not on $PATH — install `dwarves` (Debian/Ubuntu) for BTF generation"
        ));
    }

    println!("cargo:warning=BPF object built + BTF-annotated at {}", dst.display());
    Ok(())
}

fn is_on_path(name: &str) -> bool {
    if name.contains('/') {
        return Path::new(name).is_file();
    }
    let path = match env::var_os("PATH") {
        Some(p) => p,
        None => return false,
    };
    env::split_paths(&path).any(|p| p.join(name).is_file())
}
