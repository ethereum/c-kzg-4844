clean:
	rm -rf build
	rm -f ckzg.node
	rm -f ckzg_wrap.cxx

build: ../../src/c_kzg_4844.c
	swig -c++ -javascript -node ckzg.swg
	node-gyp rebuild
	cp build/Release/ckzg.node .

test:
	env NODE_PATH=.: node runnable.js
