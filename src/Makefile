INCLUDE_DIRS = ../inc
CFLAGS += -O2

blst:
	../blst/build.sh
	cp ../blst/libblst.a ../lib
	cp ../blst/bindings/*.h ../inc

c_kzg_4844.o: c_kzg_4844.c sha256.c Makefile
	clang -Wall -I$(INCLUDE_DIRS) $(CFLAGS) -c c_kzg_4844.c sha256.c

lib: c_kzg_4844.o Makefile
	mv *.o ../bindings/node.js
