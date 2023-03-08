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
else:
  {.warning: "test_yaml skipped because Nim version " &
    $NimMajor & "." & $NimMinor & " currently not supported.".}
