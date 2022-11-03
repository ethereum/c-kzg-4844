install:
	brew install llvm
	yarn install

clean:
	yarn clean
	rm -rf build
	rm -f *.node
	rm -f *.a
	rm -f *.o

# objcopy --globalize-symbol=symbolname
#	   Give symbol symbolname global scoping so that it is visible
#    outside of the file in which it is defined.  This option may
#    be given more than once.
# c_kzg_4844's static void hash() calls sha256_... which are private
# We use objcopy's globalize-symbol to make them public.
# libblst.a: ../../lib/libblst.a
# 	$$(brew --prefix llvm)/bin/llvm-objcopy --globalize-symbol=sha256_init --globalize-symbol=sha256_update --globalize-symbol=sha256_final $< $@

build: kzg.cxx Makefile
	cd ../../src; make lib
	yarn build
	cp build/Release/kzg.node .
