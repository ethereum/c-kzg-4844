import strutils
from os import DirSep

const
  testPath = currentSourcePath.rsplit(DirSep, 1)[0] & "/tests"

# Helper functions
proc test(args, path: string) =
  if not dirExists "build":
    mkDir "build"
  exec "nim " & getEnv("TEST_LANG", "c") & " " & getEnv("NIMFLAGS") & " " & args &
    " --outdir:build -r -f --hints:off --warnings:off --skipParentCfg " & path

proc runAllTest*() =
  echo ">>>>>>>>>>>>>>>> Run tests in DEBUG mode <<<<<<<<<<<<<<<<"
  test "-d:debug", testPath & "/test_all"
  echo ">>>>>>>>>>>>>>>> Run tests in RELEASE mode <<<<<<<<<<<<<<<<"
  test "-d:release", testPath & "/test_all"
  echo ">>>>>>>>>>>>>>>> Run tests in RELEASE and THREADS ON mode <<<<<<<<<<<<<<<<"
  test "--threads:on -d:release", testPath & "/test_all"

task test, "Run all tests":
  runAllTest()
