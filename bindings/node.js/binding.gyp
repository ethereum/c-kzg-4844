{
  "targets": [
    {
      "target_name": "kzg",
      "cflags!": ["-fno-exceptions"],
      "cflags_cc!": ["-fno-exceptions"],
      "conditions": [
        [
          "OS=='win'",
          {
            "defines": ["_HAS_EXCEPTIONS=1"],
            "msvs_settings": {
              "VCCLCompilerTool": {
                "ExceptionHandling": 1
              }
            }
          }
        ],
        [
          "OS=='mac'",
          {
            "cflags+": ["-fvisibility=hidden"],
            "xcode_settings": {
              "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
              "CLANG_CXX_LIBRARY": "libc++",
              "MACOSX_DEPLOYMENT_TARGET": "10.7",
              "GCC_SYMBOLS_PRIVATE_EXTERN": "YES"
            }
          }
        ]
      ],
      "sources": ["kzg.cxx"],
      "include_dirs": [
        "../../inc",
        "../../src",
        "<!@(node -p \"require('node-addon-api').include\")"
      ],
      "libraries": [
        "<(module_root_dir)/c_kzg_4844.o",
        "<(module_root_dir)/../../lib/libblst.a"
      ],
      "dependencies": ["<!(node -p \"require('node-addon-api').gyp\")"]
    },
    {
      "target_name": "action_after_build",
      "type": "none",
      "dependencies": ["kzg"],
      "copies": [
        {
          "files": ["./build/Release/kzg.node"],
          "destination": "."
        }
      ]
    }
  ]
}
