{
  "targets": [
    {
      "target_name": "kzg_bindings",
      "sources": [
        "src/bindings.cc",
        "src/functions.cc",
      ],
      'cflags!': [
          '-fno-exceptions',
          '-Werror',
          '-Wall',
          '-Wextra',
          '-Wpedantic',
          '-Wunused-parameter',
      ],
      'cflags_cc!': [
          '-fno-exceptions',
          '-Werror',
          '-Wall',
          '-Wextra',
          '-Wpedantic',
          '-Wunused-parameter',
      ],
      "defines": [
        'NAPI_CPP_EXCEPTIONS',
        "FIELD_ELEMENTS_PER_BLOB=<!(echo ${FIELD_ELEMENTS_PER_BLOB:-4096})",
      ],
      "include_dirs": [
        "<(module_root_dir)/deps/blst/bindings",
        "<(module_root_dir)/deps/c-kzg",
        "<!@(node -p \"require('node-addon-api').include\")"
      ],
      "libraries": [
        "<(module_root_dir)/libblst.a",
        "<(module_root_dir)/c_kzg_4844.o",
      ],
      "dependencies": ["<!(node -p \"require('node-addon-api').gyp\")"],
      'conditions': [
        [ 'OS=="win"', {
            'defines': [ '_HAS_EXCEPTIONS=1' ],
            'msvs_settings': {
              'VCCLCompilerTool': {
                'ExceptionHandling': 1,
                'EnablePREfast': 'true',
              },
            },
          }
        ],
        [ 'OS=="linux"', {
            'ldflags': [ '-Wl,-Bsymbolic' ],
          }
        ],
        ['OS=="mac"', {
          'cflags+': ['-fvisibility=hidden'],
          'xcode_settings': {
            'OTHER_CFLAGS': ['-fvisibility=hidden'],
            'GCC_ENABLE_CPP_EXCEPTIONS': 'YES',
            'CLANG_CXX_LIBRARY': 'libc++',
            'MACOSX_DEPLOYMENT_TARGET': '13',
          }
        }]
      ],
      "actions": [
        {
          "action_name": "build_blst",
          "inputs": ["<(module_root_dir)/deps/blst/build.sh"],
          "outputs": ["<(module_root_dir)/libblst.a"],
          "action": ["<(module_root_dir)/deps/blst/build.sh"],
        },
        {
          "action_name": "build_ckzg",
          "inputs": [
            "<(module_root_dir)/libblst.a",
            "<(module_root_dir)/deps/c-kzg/c_kzg_4844.c",
          ],
          "outputs": ["<(module_root_dir)/c_kzg_4844.o"],
          "action": [
            "cc",
            "-I<(module_root_dir)/deps/blst/bindings",
            "-DFIELD_ELEMENTS_PER_BLOB=<!(echo ${FIELD_ELEMENTS_PER_BLOB:-4096})",
            "-O2",
            "-c",
            "-fPIC",
            "<(module_root_dir)/deps/c-kzg/c_kzg_4844.c"
          ]
        }
      ]
    }
  ]
}
