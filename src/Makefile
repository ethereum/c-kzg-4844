INCLUDE_DIRS = ../inc
CFLAGS += -O2

blst:
	cd ../blst; \
	./build.sh && \
	cp libblst.a ../lib && \
	cp bindings/*.h ../inc

c_kzg_4844.o: c_kzg_4844.c sha256.c Makefile
	clang -Wall -I$(INCLUDE_DIRS) $(CFLAGS) -c c_kzg_4844.c sha256.c

lib: c_kzg_4844.o Makefile
	cp *.o ../bindings/node.js
