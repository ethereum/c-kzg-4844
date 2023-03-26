{
  "targets": [
    {
      "target_name": "kzg",
      "sources": [
        "src/kzg.cxx",
        "deps/c-kzg/c_kzg_4844.c"
        "deps/blst/src/server.c",
        "deps/blst/build/assembly.S",
      ],
      "include_dirs": [
        "<(module_root_dir)/deps/blst/bindings",
        "<(module_root_dir)/deps/c-kzg",
        "<!@(node -p \"require('node-addon-api').include\")"
      ],
      "defines": ["NAPI_DISABLE_CPP_EXCEPTIONS"],
      "conditions": [
        ["OS!='win'", {
          "defines": ["FIELD_ELEMENTS_PER_BLOB=<!(echo ${FIELD_ELEMENTS_PER_BLOB:-4096})"],
          "cflags_cc": [
            "-std=c++17",
            "-fPIC"
          ]
        }],
        ["OS=='win'", {
          "defines": [
            "_CRT_SECURE_NO_WARNINGS",
            "FIELD_ELEMENTS_PER_BLOB=<!(powershell -Command \"if ($env:FIELD_ELEMENTS_PER_BLOB) { $env:FIELD_ELEMENTS_PER_BLOB } else { 4096 }\")"
          ],
          "msbuild_settings": {
            "ClCompile": {
              "AdditionalOptions": ["/std:c++17"]
            }
          }
        }],
        ["OS=='mac'", {
          "xcode_settings": {
            "CLANG_CXX_LIBRARY": "libc++",
            "MACOSX_DEPLOYMENT_TARGET": "13.0"
          }
        }]
      ]
    }
  ]
}
