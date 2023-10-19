# C# bindings

This directory contains C# bindings for the C-KZG-4844 library.

## Prerequisites

Build requires:
- `clang` as a preferred build tool for the native wrapper of ckzg. On Windows, it's tested with clang from [Microsoft Visual Studio components](https://learn.microsoft.com/en-us/cpp/build/clang-support-msbuild?view=msvc-170);
- [.NET SDK](https://dotnet.microsoft.com/en-us/download) to build the bindings.

## Build & test

Everything is consolidated into one command:
```
make
```
