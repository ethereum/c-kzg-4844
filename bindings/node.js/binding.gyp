{
  "targets": [
    {
      "target_name": "kzg",
      "sources": [
        "src/kzg.cxx",
        "deps/blst/src/server.c",
        "deps/c-kzg/c_kzg_4844.c"
      ],
      "defines": [
        "NAPI_DISABLE_CPP_EXCEPTIONS",
        "FIELD_ELEMENTS_PER_BLOB=4096"
      ],
      "include_dirs": [
        "<(module_root_dir)/deps/blst/bindings",
        "<(module_root_dir)/deps/c-kzg",
        "<!@(node -p \"require('node-addon-api').include\")"
      ],
      "conditions": [
        ["OS!='win'", {
          "sources": ["deps/blst/build/assembly.S"],
          "cflags_cc": [
            "-std=c++17",
            "-fPIC"
          ]
        }],
        ["OS=='mac'", {
          "xcode_settings": {
            "CLANG_CXX_LIBRARY": "libc++",
            "MACOSX_DEPLOYMENT_TARGET": "13.0"
          }
        }],
        ["OS=='win'", {
          "defines": ["_CRT_SECURE_NO_WARNINGS"],
          "sources": ["deps/blst/build/win64/*-x86_64.asm"],
          "msbuild_settings": {
            "ClCompile": {
              "AdditionalOptions": ["/std:c++17"]
            }
          }
        }]
      ]
    }
  ]
}
