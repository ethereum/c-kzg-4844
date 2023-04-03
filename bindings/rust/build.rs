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
    let cargo_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let root_dir = cargo_dir
        .parent()
        .expect("rust dir is nested")
        .parent()
        .expect("bindings dir is nested");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let field_elements_per_blob = if cfg!(feature = "minimal-spec") {
        MINIMAL_FIELD_ELEMENTS_PER_BLOB
    } else {
        MAINNET_FIELD_ELEMENTS_PER_BLOB
    };

    eprintln!("Using FIELD_ELEMENTS_PER_BLOB={}", field_elements_per_blob);

    // Deleting any existing assembly and object files to ensure that compiling with a different
    // feature flag changes the final linked library file.
    let obj_file = root_dir.join("src").join("c_kzg_4844.o");
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
        root_dir.join("src").join("libckzg.a").as_path(),
        out_dir.join("libckzg.a").as_path(),
    )
    .unwrap();

    println!("cargo:rustc-link-search={}", out_dir.display());
    println!("cargo:rustc-link-search={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=ckzg");
    // Tell cargo to search for the static blst exposed by the blst-bindings' crate.
    println!("cargo:rustc-link-lib=static=blst");

    let bindings_out_path = cargo_dir.join("src").join("bindings").join("generated.rs");
    let build_target = env::var("TARGET").unwrap();
    let snapshot_path = cargo_dir.join("snapshots").join(format!(
        "bindings_{build_target}_{field_elements_per_blob}.rs"
    ));

    let header_file_path = root_dir.join("src").join("c_kzg_4844.h");
    let header_file = header_file_path.to_str().expect("valid header file");

    // Obtain the header files exposed by blst-bindings' crate.
    let blst_headers_dir =
        std::env::var_os("DEP_BLST_BINDINGS").expect("BLST exposes header files for bindings");
    make_bindings(
        field_elements_per_blob,
        header_file,
        &blst_headers_dir.to_string_lossy(),
        bindings_out_path,
        snapshot_path,
    );

    // Cleanup
    let obj_file = root_dir.join("src").join("c_kzg_4844.o");
    if obj_file.exists() {
        std::fs::remove_file(obj_file).unwrap();
    }
}

fn make_bindings<P>(
    field_elements_per_blob: usize,
    header_path: &str,
    blst_headers_dir: &str,
    bindings_out_path: P,
    snapshot_path: P,
) where
    P: AsRef<std::path::Path>,
{
    use bindgen::Builder;

    #[derive(Debug)]
    struct Callbacks;
    impl bindgen::callbacks::ParseCallbacks for Callbacks {
        fn int_macro(&self, name: &str, _value: i64) -> Option<bindgen::callbacks::IntKind> {
            match name {
                "FIELD_ELEMENTS_PER_BLOB"
                | "BYTES_PER_COMMITMENT"
                | "BYTES_PER_PROOF"
                | "BYTES_PER_FIELD_ELEMENT"
                | "BYTES_PER_BLOB" => Some(bindgen::callbacks::IntKind::Custom {
                    name: "usize",
                    is_signed: false,
                }),
                _ => None,
            }
        }
    }

    let bindings = Builder::default()
        /*
         * Header definitions.
         */
        // Inject the constant as C code so that the C compiler can use it.
        // -D is not supported by bindgen https://github.com/rust-lang/rust-bindgen/issues/2394
        .header_contents(
            "consts",
            &format!("#define FIELD_ELEMENTS_PER_BLOB {field_elements_per_blob}"),
        )
        .header(header_path)
        .clang_args([format!("-I{blst_headers_dir}")])
        // Since this is not part of the header file, needs to be allowed explicitly.
        .allowlist_var("FIELD_ELEMENTS_PER_BLOB")
        // Get bindings only for the header file.
        .allowlist_file(".*c_kzg_4844.h")
        /*
         * Cleanup instructions.
         */
        // Do no generate layout tests.
        .layout_tests(false)
        // Extern functions do not need individual extern blocks.
        .merge_extern_blocks(true)
        // We implement Drop for this type. Copy is not allowed for types with destructors.
        .no_copy("KZGSettings")
        /*
         * API improvements.
         */
        // Do not create individual constants for enum variants.
        .rustified_enum("C_KZG_RET")
        // Make constants used as sizes `usize`.
        .parse_callbacks(Box::new(Callbacks))
        // Add PartialEq and Eq impls to types.
        .derive_eq(true)
        // Blobs are big, we don't want rust to liberally copy them around.
        .no_copy("Blob")
        // Do not make fields public. If we want to modify them we can create setters/mutable
        // getters when necessary.
        .default_visibility(bindgen::FieldVisibilityKind::Private)
        // Blocklist this type alias to use a custom implementation. If this stops being a type
        // alias this line needs to be removed.
        .blocklist_type("KZGCommitment")
        // Blocklist this type alias to use a custom implementation. If this stops being a type
        // alias this line needs to be removed.
        .blocklist_type("KZGProof")
        /*
         * Re-build instructions
         */
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .unwrap();

    bindings
        .write_to_file(bindings_out_path)
        .expect("Failed to write bindings");
    bindings
        .write_to_file(snapshot_path)
        .expect("Failed to write snapshot");
}
