import
  test_abi,
  test_kzg,
  test_kzg_ex

when (NimMajor, NimMinor) >= (1, 4) and 
     (NimMajor, NimMinor) <= (1, 6):
  # nim devel causes shallowCopy error
  # on yaml
  import
    test_yaml
