use std::env;
use std::path::PathBuf;

const MAINNET_FIELD_ELEMENTS_PER_BLOB: usize = 4096;
const MINIMAL_FIELD_ELEMENTS_PER_BLOB: usize = 4;

fn main() {
    let cargo_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let root_dir = cargo_dir
        .parent()
        .expect("rust dir is nested")
        .parent()
        .expect("bindings dir is nested");

    let field_elements_per_blob = if cfg!(feature = "minimal-spec") {
        MINIMAL_FIELD_ELEMENTS_PER_BLOB
    } else {
        MAINNET_FIELD_ELEMENTS_PER_BLOB
    };

    eprintln!("Using FIELD_ELEMENTS_PER_BLOB={}", field_elements_per_blob);

    // Obtain the header files exposed by blst-bindings' crate.
    let blst_headers_dir =
        std::env::var_os("DEP_BLST_BINDINGS").expect("BLST exposes header files for bindings");

    let c_src_dir = root_dir.join("src");

    let mut cc = cc::Build::new();

    #[cfg(windows)]
    cc.compiler("clang").flag("-D_CRT_SECURE_NO_WARNINGS");

    cc.include(blst_headers_dir.clone());
    cc.warnings(false);
    cc.flag(format!("-DFIELD_ELEMENTS_PER_BLOB={}", field_elements_per_blob).as_str());
    cc.file(c_src_dir.join("c_kzg_4844.c"));

    cc.try_compile("ckzg").expect("Failed to compile ckzg");

    // Tell cargo to search for the static blst exposed by the blst-bindings' crate.
    println!("cargo:rustc-link-lib=static=blst");

    let bindings_out_path = cargo_dir.join("src").join("bindings").join("generated.rs");
    let build_target = env::var("TARGET").unwrap();
    let snapshot_path = cargo_dir.join("snapshots").join(format!(
        "bindings_{build_target}_{field_elements_per_blob}.rs"
    ));

    let header_file_path = c_src_dir.join("c_kzg_4844.h");
    let header_file = header_file_path.to_str().expect("valid header file");

    make_bindings(
        field_elements_per_blob,
        header_file,
        &blst_headers_dir.to_string_lossy(),
        bindings_out_path,
        snapshot_path,
    );

    // Finally, tell cargo this provides ckzg
    println!("cargo:rustc-link-lib=ckzg");
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
        // Remove stdio definitions related to FILE.
        .opaque_type("FILE")
        // Remove the definition of FILE to use the libc one, which is more convenient.
        .blocklist_type("FILE")
        // Inject rust code using libc's FILE
        .raw_line("use libc::FILE;")
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
