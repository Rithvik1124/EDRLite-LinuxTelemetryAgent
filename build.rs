fn main() {
    let out = "src/trial.skel.rs";

    libbpf_cargo::SkeletonBuilder::new()
        .source("bpf/trial.bpf.c")
        .build_and_generate(out)
        .unwrap();

    println!("cargo:rerun-if-changed=bpf/trial.bpf.c");
}
