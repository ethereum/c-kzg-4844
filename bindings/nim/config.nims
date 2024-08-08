when fileExists("nimble.paths"):
  include "nimble.paths"

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

proc runTests*() =
  echo ">>>>>>>>>>>>>>>> Run tests in DEBUG mode <<<<<<<<<<<<<<<<"
  test "-d:debug", testPath & "/tests"
  echo ">>>>>>>>>>>>>>>> Run tests in RELEASE mode <<<<<<<<<<<<<<<<"
  test "-d:release", testPath & "/tests"
  echo ">>>>>>>>>>>>>>>> Run tests in RELEASE and THREADS ON mode <<<<<<<<<<<<<<<<"
  test "--threads:on -d:release", testPath & "/tests"

task test, "Run tests":
  runTests()
