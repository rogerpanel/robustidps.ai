//! Placeholder for the `robustidps-xdp` userspace loader binary.
//!
//! Real implementation (clap CLI, aya `Ebpf::load`, XDP attach with fallback,
//! BPF map population from `--blocks`, periodic stats printer, SIGINT/SIGTERM
//! teardown) lands in the follow-up commit.

fn main() {
    eprintln!(
        "robustidps-xdp: scaffolding stub. The real userspace loader lands in \
         the follow-up commit alongside build.rs + README."
    );
    std::process::exit(1);
}
