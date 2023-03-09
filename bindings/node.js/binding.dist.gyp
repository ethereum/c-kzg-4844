{
  "targets": [
    {
      "target_name": "kzg",
      "cflags!": ["-fno-exceptions"],
      "cflags_cc!": ["-fno-exceptions"],
      "xcode_settings": {
        "CLANG_CXX_LIBRARY": "libc++",
        "MACOSX_DEPLOYMENT_TARGET": "13.0"
      },
      "defines": [
        "NAPI_DISABLE_CPP_EXCEPTIONS",
        "FIELD_ELEMENTS_PER_BLOB=<!(echo ${FIELD_ELEMENTS_PER_BLOB:-4096})"
      ],
      "sources": ["src/kzg.cxx"],
      "include_dirs": [
        "<(module_root_dir)/deps/blst/bindings",
        "<(module_root_dir)/deps/c-kzg",
        "<!@(node -p \"require('node-addon-api').include\")"
      ],
      "libraries": [
        "<(module_root_dir)/c_kzg_4844.o",
        "<(module_root_dir)/libblst.a"
      ],
      "dependencies": ["<!(node -p \"require('node-addon-api').gyp\")"],
      "actions": [
        {
          "action_name": "build_blst",
          "inputs": ["<(module_root_dir)/deps/blst/build.sh"],
          "outputs": ["<(module_root_dir)/libblst.a"],
          "action": ["<(module_root_dir)/deps/blst/build.sh"]
        },
        {
          "action_name": "build_ckzg",
          "inputs": [
            "<(module_root_dir)/deps/c-kzg/c_kzg_4844.c",
            "<(module_root_dir)/libblst.a"
          ],
          "outputs": ["<(module_root_dir)/c_kzg_4844.o"],
          "action": [
            "cc",
            "-I<(module_root_dir)/deps/blst/bindings",
            "-DFIELD_ELEMENTS_PER_BLOB=<!(echo ${FIELD_ELEMENTS_PER_BLOB:-4096})",
            "-O2",
            "-c",
            "<(module_root_dir)/deps/c-kzg/c_kzg_4844.c"
          ]
        }
      ]
    }
  ]
}
