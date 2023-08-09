use std::env;
use std::path::{Path, PathBuf};

const MAINNET_FIELD_ELEMENTS_PER_BLOB: usize = 4096;
const MINIMAL_FIELD_ELEMENTS_PER_BLOB: usize = 4;

/// Compiles blst.
//
// NOTE: This code is taken from https://github.com/supranational/blst `build.rs` `main`. The crate
// is not used as a dependency to avoid double link issues on dependants.
fn compile_blst(blst_base_dir: PathBuf) {
    // account for cross-compilation [by examining environment variables]
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();

    if target_os.ne("none") && !env::var("BLST_TEST_NO_STD").is_ok() {
        println!("cargo:rustc-cfg=feature=\"std\"");
        if target_arch.eq("wasm32") {
            println!("cargo:rustc-cfg=feature=\"no-threads\"");
        }
    }
    println!("cargo:rerun-if-env-changed=BLST_TEST_NO_STD");

    println!("Using blst source directory {}", blst_base_dir.display());

    // Set CC environment variable to choose alternative C compiler.
    // Optimization level depends on whether or not --release is passed
    // or implied.

    #[cfg(target_env = "msvc")]
    if env::var("CARGO_CFG_TARGET_POINTER_WIDTH").unwrap().eq("32") && !env::var("CC").is_ok() {
        match std::process::Command::new("clang-cl")
            .arg("--version")
            .output()
        {
            Ok(out) => {
                if String::from_utf8(out.stdout)
                    .unwrap_or("unintelligible".to_string())
                    .contains("Target: i686-")
                {
                    env::set_var("CC", "clang-cl");
                }
            }
            Err(_) => { /* no clang-cl in sight, just ignore the error */ }
        }
    }

    let mut cc = cc::Build::new();

    let c_src_dir = blst_base_dir.join("src");
    println!("cargo:rerun-if-changed={}", c_src_dir.display());
    let mut file_vec = vec![c_src_dir.join("server.c")];

    if target_arch.eq("x86_64") || target_arch.eq("aarch64") {
        let asm_dir = blst_base_dir.join("build");
        println!("cargo:rerun-if-changed={}", asm_dir.display());
        blst_assembly(&mut file_vec, &asm_dir, &target_arch);
    } else {
        cc.define("__BLST_NO_ASM__", None);
    }
    match (cfg!(feature = "portable"), cfg!(feature = "force-adx")) {
        (true, false) => {
            println!("Compiling in portable mode without ISA extensions");
            cc.define("__BLST_PORTABLE__", None);
        }
        (false, true) => {
            if target_arch.eq("x86_64") {
                println!("Enabling ADX support via `force-adx` feature");
                cc.define("__ADX__", None);
            } else {
                println!("`force-adx` is ignored for non-x86_64 targets");
            }
        }
        (false, false) =>
        {
            #[cfg(target_arch = "x86_64")]
            if target_arch.eq("x86_64") && std::is_x86_feature_detected!("adx") {
                println!("Enabling ADX because it was detected on the host");
                cc.define("__ADX__", None);
            }
        }
        (true, true) => panic!("Cannot compile with both `portable` and `force-adx` features"),
    }
    if env::var("CARGO_CFG_TARGET_ENV").unwrap().eq("msvc") {
        cc.flag("-Zl");
    }
    cc.flag_if_supported("-mno-avx") // avoid costly transitions
        .flag_if_supported("-fno-builtin")
        .flag_if_supported("-Wno-unused-function")
        .flag_if_supported("-Wno-unused-command-line-argument");
    if target_arch.eq("wasm32") {
        cc.flag_if_supported("-ffreestanding");
    }
    if !cfg!(debug_assertions) {
        cc.opt_level(2);
    }
    cc.files(&file_vec).compile("blst");
}

/// Adds assembly files for blst compilation.
fn blst_assembly(file_vec: &mut Vec<PathBuf>, base_dir: &Path, _arch: &String) {
    #[cfg(target_env = "msvc")]
    if env::var("CARGO_CFG_TARGET_ENV").unwrap().eq("msvc") {
        let sfx = match _arch.as_str() {
            "x86_64" => "x86_64",
            "aarch64" => "armv8",
            _ => "unknown",
        };
        let files = glob::glob(&format!("{}/win64/*-{}.asm", base_dir.display(), sfx))
            .expect("unable to collect assembly files");
        for file in files {
            file_vec.push(file.unwrap());
        }
        return;
    }

    file_vec.push(base_dir.join("assembly.S"));
}

fn main() {
    let cargo_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let root_dir = cargo_dir
        .parent()
        .expect("rust dir is nested")
        .parent()
        .expect("bindings dir is nested");

    let (lib_name, field_elements_per_blob) = if cfg!(feature = "minimal-spec") {
        ("ckzg_min", MINIMAL_FIELD_ELEMENTS_PER_BLOB)
    } else {
        ("ckzg", MAINNET_FIELD_ELEMENTS_PER_BLOB)
    };

    eprintln!("Using LIB_PREFIX={lib_name}");
    eprintln!("Using FIELD_ELEMENTS_PER_BLOB={field_elements_per_blob}");

    let blst_base_dir = root_dir.join("blst");
    compile_blst(blst_base_dir.clone());

    // Obtain the header files of blst
    let blst_headers_dir = blst_base_dir.join("bindings");

    let c_src_dir = root_dir.join("src");

    let mut cc = cc::Build::new();

    #[cfg(windows)]
    cc.flag("-D_CRT_SECURE_NO_WARNINGS");

    cc.include(blst_headers_dir.clone());
    cc.warnings(false);
    cc.flag(format!("-DLIB_PREFIX={lib_name}").as_str());
    cc.flag(format!("-DFIELD_ELEMENTS_PER_BLOB={}", field_elements_per_blob).as_str());
    cc.file(c_src_dir.join("c_kzg_4844.c"));

    cc.try_compile(lib_name).expect("Failed to compile ckzg");

    // Tell cargo to search for the static blst exposed by the blst-bindings' crate.
    println!("cargo:rustc-link-lib=static=blst");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bindings_out_path = out_dir.join("generated.rs");
    let header_file_path = c_src_dir.join("c_kzg_4844.h");
    let header_file = header_file_path.to_str().expect("valid header file");

    make_bindings(
        lib_name,
        field_elements_per_blob,
        header_file,
        &blst_headers_dir.to_string_lossy(),
        bindings_out_path,
    );

    // Finally, tell cargo this provides ckzg/ckzg_min
    println!("cargo:rustc-link-lib={lib_name}");
}

fn make_bindings<P>(
    lib_name: &str,
    field_elements_per_blob: usize,
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
        // Inject the constant as C code so that the C compiler can use it.
        // -D is not supported by bindgen https://github.com/rust-lang/rust-bindgen/issues/2394
        .header_contents(
            "consts",
            &format!(
                "#define LIB_PREFIX {lib_name}
                 #define FIELD_ELEMENTS_PER_BLOB {field_elements_per_blob}"
            ),
        )
        .header(header_path)
        .clang_args([format!("-I{blst_headers_dir}")])
        // Since this is not part of the header file, needs to be allowed explicitly.
        .allowlist_var("LIB_PREFIX")
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
}
