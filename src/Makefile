INCLUDE_DIRS = ../inc
CFLAGS += -O2

c_kzg_4844.o: c_kzg_4844.c Makefile
	clang -Wall -I$(INCLUDE_DIRS) $(CFLAGS) -mmacosx-version-min=10.15 -c $<

lib: c_kzg_4844.c Makefile
	clang -Wall -I$(INCLUDE_DIRS) $(CFLAGS) -mmacosx-version-min=10.15 -c c_kzg_4844.c
	mv c_kzg_4844.o ../bindings/node.js
