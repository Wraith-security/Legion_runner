// Compiles the eBPF crate (legionr-bpf-ebpf) to BPF bytecode at build time and
// exposes it to the userspace binary via OUT_DIR. Requires a nightly toolchain
// with rust-src and `bpf-linker` on PATH.
//
// aya-build 0.1.3 API: build_ebpf(packages: IntoIterator<Item = Package>,
// toolchain: Toolchain), where Package is aya-build's own struct.

use aya_build::{Package, Toolchain};

fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let root_dir = format!("{manifest}/../legionr-bpf-ebpf");
    let ebpf = Package {
        name: "legionr-bpf-ebpf",
        root_dir: &root_dir,
        ..Default::default()
    };
    aya_build::build_ebpf([ebpf], Toolchain::default()).expect("build eBPF program");
}
