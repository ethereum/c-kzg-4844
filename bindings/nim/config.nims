# Helper functions
proc test(args, path: string) =
  if not dirExists "build":
    mkDir "build"
  exec "nim " & getEnv("TEST_LANG", "c") & " " & getEnv("NIMFLAGS") & " " & args &
    " --outdir:build -r -f --hints:off --warnings:off --skipParentCfg " & path

task test, "Run all tests":
  echo ">>>>>>>>>>>>>>>> Run tests in DEBUG mode <<<<<<<<<<<<<<<<"
  test "-d:debug", "tests/test_all"
  echo ">>>>>>>>>>>>>>>> Run tests in RELEASE mode <<<<<<<<<<<<<<<<"
  test "-d:release", "tests/test_all"
  echo ">>>>>>>>>>>>>>>> Run tests in RELEASE and THREADS ON mode <<<<<<<<<<<<<<<<"
  test "--threads:on -d:release", "tests/test_all"
