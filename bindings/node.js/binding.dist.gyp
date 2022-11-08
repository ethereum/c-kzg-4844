{
  "targets": [
    {
      "target_name": "kzg",
      "cflags!": ["-fno-exceptions"],
      "cflags_cc!": ["-fno-exceptions"],
      "xcode_settings": {
        "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
        "CLANG_CXX_LIBRARY": "libc++",
        "MACOSX_DEPLOYMENT_TARGET": "13.0"
      },
      "sources": ["kzg.cxx"],
      "include_dirs": [
        "<(module_root_dir)/dist/deps/blst/bindings",
        "<(module_root_dir)/dist/deps/c-kzg",
        "<!@(node -p \"require('node-addon-api').include\")"
      ],
      "libraries": [
        "<(module_root_dir)/c_kzg_4844.o",
        "<(module_root_dir)/libblst.a"
      ],
      "dependencies": ["<!(node -p \"require('node-addon-api').gyp\")"],
      "defines": ["NAPI_DISABLE_CPP_EXCEPTIONS"],
      "actions": [
        {
          "action_name": "build_blst",
          "inputs": ["<(module_root_dir)/dist/deps/blst/build.sh"],
          "outputs": ["<(module_root_dir)/libblst.a"],
          "action": ["<(module_root_dir)/dist/deps/blst/build.sh"]
        },
        {
          "action_name": "build_ckzg",
          "inputs": [
            "<(module_root_dir)/dist/deps/c-kzg/c_kzg_4844.c",
            "<(module_root_dir)/libblst.a"
          ],
          "outputs": ["<(module_root_dir)/c_kzg_4844.o"],
          "action": [
            "cc",
            "-I<(module_root_dir)/dist/deps/blst/bindings",
            "-O2",
            "-c",
            "<(module_root_dir)/dist/deps/c-kzg/c_kzg_4844.c"
          ]
        }
      ]
    },
    {
      "target_name": "action_after_build",
      "type": "none",
      "dependencies": ["kzg"],
      "copies": [
        {
          "files": ["./build/Release/kzg.node"],
          "destination": "./dist"
        }
      ]
    }
  ]
}
