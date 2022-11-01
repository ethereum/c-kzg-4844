{
  'targets': [
    {
      'target_name': 'ckzg',
      'sources': [
        'ckzg_wrap.cxx',
        '../../src/c_kzg_4844.c',
      ],
      'include_dirs': [ '../../inc' ],
    },
  ]
}
