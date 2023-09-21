import
  test_abi,
  test_kzg,
  test_kzg_ex

when (NimMajor, NimMinor) >= (2, 0):
  import
    test_yaml
else:
  {.warning: "test_yaml skipped because Nim version " &
    $NimMajor & "." & $NimMinor & " currently not supported.".}
