use std::env;
use std::path::PathBuf;

fn main() {
    let cargo_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let root_dir = cargo_dir
        .parent()
        .expect("rust dir is nested")
        .parent()
        .expect("bindings dir is nested");

    // Obtain the header files of blst
    let blst_base_dir = root_dir.join("blst");
    let blst_headers_dir = blst_base_dir.join("bindings");

    let c_src_dir = root_dir.join("src");

    let mut cc = cc::Build::new();

    #[cfg(windows)]
    {
        cc.flag("-D_CRT_SECURE_NO_WARNINGS");

        // In blst, if __STDC_VERSION__ isn't defined as c99 or greater, it will typedef a bool to
        // an int. There is a bug in bindgen associated with this. It assumes that a bool in C is
        // the same size as a bool in Rust. This is the root cause of the issues on Windows. If/when
        // this is fixed in bindgen, it should be safe to remove this compiler flag.
        cc.flag("/std:c11");
    }

    cc.include(blst_headers_dir.clone());
    cc.warnings(false);
    cc.file(c_src_dir.join("c_kzg_4844.c"));

    cc.try_compile("ckzg").expect("Failed to compile ckzg");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bindings_out_path = out_dir.join("generated.rs");
    let header_file_path = c_src_dir.join("c_kzg_4844.h");
    let header_file = header_file_path.to_str().expect("valid header file");

    make_bindings(
        header_file,
        &blst_headers_dir.to_string_lossy(),
        bindings_out_path,
    );

    // Finally, tell cargo this provides ckzg/ckzg_min
    println!("cargo:rustc-link-lib=ckzg");
}

fn make_bindings<P>(
    header_path: &str,
    blst_headers_dir: &str,
    bindings_out_path: P,
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
        .header(header_path)
        .clang_args([format!("-I{blst_headers_dir}")])
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
}
