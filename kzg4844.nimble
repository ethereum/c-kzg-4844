mode = ScriptMode.Verbose

##################################################
# Package definition
##################################################

packageName   = "kzg4844"
version       = "0.1.0"
author        = "Andri Lim"
description   = "Nim wrapper of c-kzg-4844"
license       = "Apache License 2.0"
skipDirs      = @[
  "tests", "lib", "inc", "fuzz",
  "bindings/csharp",
  "bindings/go",
  "bindings/java",
  "bindings/node.js",
  "bindings/python",
  "bindings/rust"
  ]
installDirs   = @[
  "blst",
  "src",
  "bindings/nim"
  ]

requires "nim >= 1.2.0",
         "stew"

##################################################
# Test code
##################################################

import "bindings/nim/config.nims"

task test, "Run all tests":
  runAllTest()

##################################################
# Package installation code
##################################################

after install:
  mvDir("bindings/nim/nimble", ".")
  rmDir("bindings/nim/tests")
