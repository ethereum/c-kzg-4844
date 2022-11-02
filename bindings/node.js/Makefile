clean:
	rm -rf build
	rm -f ckzg.node
	rm -f ckzg_wrap.cxx

build: ckzg.c ckzg.h
	swig -javascript -node ckzg.swg
	node-gyp rebuild
	cp build/Release/ckzg.node .

test:
	env NODE_PATH=.: node runnable.js
