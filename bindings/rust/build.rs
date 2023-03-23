use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

const MAINNET_FIELD_ELEMENTS_PER_BLOB: usize = 4096;
const MINIMAL_FIELD_ELEMENTS_PER_BLOB: usize = 4;

fn move_file(src: &Path, dst: &Path) -> Result<(), String> {
    std::fs::copy(src, dst)
        .map_err(|_| format!("Failed to copy {} to {}", src.display(), dst.display()))?;
    std::fs::remove_file(src)
        .map_err(|_| format!("Failed to remove file {} from source", src.display()))?;
    Ok(())
}

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
    move_file(
        root_dir.join("lib/libblst.a").as_path(),
        out_dir.join("libblst.a").as_path(),
    )
    .unwrap();

    let field_elements_per_blob = if cfg!(feature = "minimal-spec") {
        MINIMAL_FIELD_ELEMENTS_PER_BLOB
    } else {
        MAINNET_FIELD_ELEMENTS_PER_BLOB
    };

    eprintln!("Using FIELD_ELEMENTS_PER_BLOB={}", field_elements_per_blob);

    // Deleting any existing assembly and object files to ensure that compiling with a different
    // feature flag changes the final linked library file.
    let obj_file = root_dir.join("src/c_kzg_4844.o");
    if obj_file.exists() {
        std::fs::remove_file(obj_file).unwrap();
    }

    // Ensure libckzg exists in `OUT_DIR`
    Command::new("make")
        .current_dir(root_dir.join("src"))
        .arg("c_kzg_4844.o")
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
    move_file(
        root_dir.join("src/libckzg.a").as_path(),
        out_dir.join("libckzg.a").as_path(),
    )
    .unwrap();

    println!("cargo:rustc-link-search={}", out_dir.display());
    println!("cargo:rustc-link-search={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=ckzg");
    println!("cargo:rustc-link-lib=static=blst");

    // Write the compile time variable to a consts.rs file to be imported to the bindings module.
    let const_file = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("src/bindings/consts.rs");
    std::fs::write(
        const_file,
        format!(
            "pub const FIELD_ELEMENTS_PER_BLOB: usize = {};",
            field_elements_per_blob
        ),
    )
    .unwrap();

    // Cleanup
    let obj_file = root_dir.join("src/c_kzg_4844.o");
    if obj_file.exists() {
        std::fs::remove_file(obj_file).unwrap();
    }
}
