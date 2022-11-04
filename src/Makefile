INCLUDE_DIRS = ../inc
CFLAGS += -O2

blst:
	cd ../blst; \
	git apply < ../blst_sha.patch; \
	./build.sh && \
	cp libblst.a ../lib && \
	cp bindings/*.h ../inc

c_kzg_4844.o: c_kzg_4844.c Makefile
	clang -Wall -I$(INCLUDE_DIRS) $(CFLAGS) -c $<

lib: c_kzg_4844.o Makefile
	cp *.o ../bindings/node.js
