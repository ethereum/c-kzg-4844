use std::env;
use std::path::PathBuf;
use std::process::Command;

const MAINNET_FIELD_ELEMENTS_PER_BLOB: usize = 4096;
const MINIMAL_FIELD_ELEMENTS_PER_BLOB: usize = 4;

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

    let field_elements_per_blob = if cfg!(feature = "minimal-spec") {
        MINIMAL_FIELD_ELEMENTS_PER_BLOB
    } else {
        MAINNET_FIELD_ELEMENTS_PER_BLOB
    };

    eprintln!("Using FIELD_ELEMENTS_PER_BLOB={}", field_elements_per_blob);

    // Ensure libckzg exists in `OUT_DIR`
    Command::new("make")
        .current_dir(root_dir.join("src"))
        .arg("all")
        .arg(format!(
            "FIELD_ELEMENTS_PER_BLOB={}",
            field_elements_per_blob
        ))
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

    // Write the compile time variable to a consts.rs file to be imported to the bindings module.
    let const_file = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("src/consts.rs");
    std::fs::write(
        &const_file,
        format!(
            "pub const FIELD_ELEMENTS_PER_BLOB: usize = {};",
            field_elements_per_blob
        ),
    )
    .unwrap();
}
