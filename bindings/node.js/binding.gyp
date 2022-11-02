{
  'targets': [
    {
      'target_name': 'kzg',
      "cflags!": [ "-fno-exceptions" ],
      "cflags_cc!": [ "-fno-exceptions" ],
      'sources': [
        'kzg.cxx',
      ],
      'include_dirs': ['../../inc', '../../src', "<!@(node -p \"require('node-addon-api').include\")"],
      'libraries': [
        '/Users/coffman@coinbase.com/src/c-kzg/bindings/node.js/c_kzg_4844.o',
        '/Users/coffman@coinbase.com/src/c-kzg/lib/libblst.a'
      ],
      'dependencies': [
            "<!(node -p \"require('node-addon-api').gyp\")"
      ],
      'defines': [ 'NAPI_DISABLE_CPP_EXCEPTIONS' ]
    }
  ]
}
