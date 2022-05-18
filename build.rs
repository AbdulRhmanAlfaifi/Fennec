fn main() {
    println!("cargo:rerun-if-changed=deps/darwin/config.yaml");
    println!("cargo:rerun-if-changed=deps/freebsd/config.yaml");
    println!("cargo:rerun-if-changed=deps/linux/config.yaml");
}
