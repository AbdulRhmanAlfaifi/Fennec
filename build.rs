fn main() {
    println!("cargo:rerun-if-changed=deps/darwin/fennec.yaml");
    println!("cargo:rerun-if-changed=deps/freebsd/fennec.yaml");
    println!("cargo:rerun-if-changed=deps/linux/fennec.yaml");
}
