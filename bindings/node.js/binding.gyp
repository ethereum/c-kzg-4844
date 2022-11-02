{
  'targets': [
    {
      'target_name': 'ckzg',
      'sources': [
        'ckzg.cxx',
        'ckzg_wrap.cxx',
      ],
      'include_dirs': ['../../inc', '../../src', "<!@(node -p \"require('node-addon-api').include\")"],
      'libraries': [
        '/Users/coffman@coinbase.com/src/c-kzg/bindings/node.js/c_kzg_4844.o',
        '/Users/coffman@coinbase.com/src/c-kzg/lib/libblst.a'
      ],
      # https://stackoverflow.com/questions/59799509/how-to-return-a-c-class-to-node-js
      'dependencies': [
            "<!(node -p \"require('node-addon-api').gyp\")"
      ],
      'defines': [ 'NAPI_DISABLE_CPP_EXCEPTIONS' ]
    }
  ]
}
