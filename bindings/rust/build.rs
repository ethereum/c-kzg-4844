use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let root_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Ensure libblst exists in `OUT_DIR`
    // Assuming blst submodule exists
    Command::new("make")
        .current_dir(root_dir.join("src"))
        .arg("blst")
        .status()
        .unwrap();
    std::fs::copy(root_dir.join("lib/libblst.a"), &out_dir.join("libblst.a")).unwrap();

    // Ensure libckzg exists in `OUT_DIR`
    Command::new("make")
        .current_dir(root_dir.join("src"))
        .arg("all")
        .status()
        .unwrap();

    Command::new("ar")
        .current_dir(&root_dir.join("src"))
        .args(["crus", "libckzg.a", "c_kzg_4844.o"])
        .status()
        .unwrap();
    std::fs::copy(root_dir.join("src/libckzg.a"), &out_dir.join("libckzg.a")).unwrap();

    println!("cargo:rustc-link-search={}", out_dir.display());
    println!("cargo:rustc-link-search={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=ckzg");
    println!("cargo:rustc-link-lib=static=blst");
    println!(
        "cargo:rerun-if-changed={}",
        root_dir.join("src/c_kzg_4844.c").display()
    );
}
