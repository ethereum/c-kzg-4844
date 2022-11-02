clean:
	yarn clean
	rm -rf build
	rm -f ckzg.node
	rm -f ckzg_wrap.cxx

build: ckzg.cxx ckzg.h Makefile
	# cd ../../src; make lib
	# swig -c++ -javascript -node ckzg.swg
	yarn build
	cp build/Release/kzg.node .

test:
	env NODE_PATH=.: node runnable.js
