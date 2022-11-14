use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("wrapper.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Finish the builder and generate the bindings.
        .derive_partialeq(true)
        .derive_eq(true)
        .derive_copy(false)
        .opaque_type("blst_uniq")
        .default_enum_style(bindgen::EnumVariation::Rust {
            non_exhaustive: false,
        })
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    let mut root_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let mut cmd = Command::new("make");
    let res = cmd
        .current_dir(root_dir.join("src"))
        .arg("all")
        .status()
        .unwrap();

    let obj_file_path = root_dir.join("c_kzg_4844.o");

    let status = Command::new("ar")
        .args(&["crus", "libckzg.a", "c_kzg_4844.o"])
        .current_dir(&root_dir.join("src"))
        .status()
        .unwrap();

    std::fs::copy(root_dir.join("src/libckzg.a"), &out_dir.join("libckzg.a")).unwrap();
    std::fs::copy(root_dir.join("lib/libblst.a"), &out_dir.join("libblst.a")).unwrap();

    println!("cargo:rustc-link-search={}", out_dir.display());
    println!("cargo:rustc-link-search={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=ckzg");
    println!("cargo:rustc-link-lib=static=blst");
    println!(
        "cargo:rerun-if-changed={}",
        root_dir.join("src/c_kzg_4844.c").display()
    );

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
