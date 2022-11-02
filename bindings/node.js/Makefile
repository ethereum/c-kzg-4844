clean:
	yarn clean
	rm -rf build
	rm -f kzg.node

build: kzg.cxx Makefile
	cd ../../src; make lib
	yarn build
	cp build/Release/kzg.node .

test:
	env NODE_PATH=.: node runnable.js
