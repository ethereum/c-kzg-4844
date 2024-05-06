{
  "targets": [
    {
      "target_name": "kzg",
      "sources": [
        "src/kzg.cxx",
        "deps/blst/src/server.c",
        "deps/c-kzg/c_kzg_4844.c"
      ],
      "include_dirs": [
        "<(module_root_dir)/deps/blst/bindings",
        "<(module_root_dir)/deps/c-kzg",
        "<!@(node -p \"require('node-addon-api').include\")"
      ],
      "defines": [
        "__BLST_PORTABLE__",
        "NAPI_CPP_EXCEPTIONS"
      ],
      "conditions": [
        ["OS!='win'", {
          "sources": ["deps/blst/build/assembly.S"],
          "cflags_cc": [
            "-fexceptions",
            "-std=c++17",
            "-fPIC"
          ]
        }],
        ["OS=='win'", {
          "sources": ["deps/blst/build/win64/*-x86_64.asm"],
          "defines": [
            "_CRT_SECURE_NO_WARNINGS",
            "_HAS_EXCEPTIONS=1"
          ],
          "msbuild_settings": {
            "ClCompile": {
              "ExceptionHandling": "Sync",
              "AdditionalOptions": ["/std:c++17"]
            }
          }
        }],
        ["OS=='mac'", {
          "xcode_settings": {
            "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
            "CLANG_CXX_LIBRARY": "libc++",
            "MACOSX_DEPLOYMENT_TARGET": "13.0"
          }
        }]
      ]
    }
  ]
}
