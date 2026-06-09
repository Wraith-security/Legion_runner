// Compiles the eBPF crate (legionr-bpf-ebpf) to BPF bytecode at build time and
// makes it available to the userspace binary via OUT_DIR. Requires a nightly
// toolchain with rust-src and `bpf-linker` on PATH.
//
// aya-build 0.1.3: `build_ebpf(packages, Toolchain)` and no re-exported
// cargo_metadata, so we depend on cargo_metadata directly.

use aya_build::Toolchain;
use cargo_metadata::MetadataCommand;

fn main() {
    let metadata = MetadataCommand::new()
        .no_deps()
        .exec()
        .expect("cargo metadata");
    let ebpf = metadata
        .packages
        .into_iter()
        .find(|p| p.name == "legionr-bpf-ebpf")
        .expect("legionr-bpf-ebpf package present");
    aya_build::build_ebpf([ebpf], Toolchain::default()).expect("build eBPF program");
}
