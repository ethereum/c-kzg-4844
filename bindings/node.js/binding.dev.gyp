{
  "targets": [
    {
      "target_name": "kzg_bindings",
      "sources": [
        "src/bindings.cc",
        "src/functions.cc",
      ],
      "libraries": [
        "<(module_root_dir)/c_kzg_4844.o",
        "<(module_root_dir)/libblst.a",
      ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")",
        "deps/blst/bindings",
        "deps/c-kzg",
      ],
      "dependencies": ["<!(node -p \"require('node-addon-api').gyp\")"],
      "defines": [
        'NAPI_CPP_EXCEPTIONS',
        "FIELD_ELEMENTS_PER_BLOB=<!(echo ${FIELD_ELEMENTS_PER_BLOB:-4096})",
      ],
      'cflags!': [
          '-fno-exceptions',
          '-fno-builtin-memcpy',
          '-Wextern-c-compat',
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
    }
  ]
}
