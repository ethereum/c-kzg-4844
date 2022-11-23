# Build Shared Library

## Windows

```bat
gcc -c -I..\..\blst\bindings -I..\..\src\ -I"%JAVA_HOME%\include" -I"%JAVA_HOME%\include\win32" c_kzg_4844_jni.c -o c_kzg_4844_jni.o
gcc -shared -o lib/ckzg4844jni.dll c_kzg_4844.o c_kzg_4844_jni.o -Wl,--add-stdcall-alias
```

## Linux

```bash
gcc -c -fPIC -I../../blst/bindings -I../../src/ -I${JAVA_HOME}/include -I${JAVA_HOME}/include/linux c_kzg_4844_jni.c -o c_kzg_4844_jni.o
gcc -shared -fPIC -o lib/libckzg4844jni.so c_kzg_4844.o c_kzg_4844_jni.o -lc
```

## Mac-OS

```bash
gcc -c -fPIC -I../../blst/bindings -I../../src/ -I${JAVA_HOME}/include -I${JAVA_HOME}/include/darwin c_kzg_4844_jni.c -o c_kzg_4844_jni.o
gcc -dynamiclib -o lib/libckzg4844jni.dylib c_kzg_4844.o c_kzg_4844_jni.o -lc
```
