clean:
	yarn node-gyp clean
	rm -rf build
	rm -f *.node
	rm -f dist/kzg.node
	rm -f *.a
	rm -f *.o

build: kzg.cxx kzg.ts package.json Makefile
	cd ../../src; make lib
	yarn node-gyp rebuild
	cp build/Release/kzg.node .
	cp build/Release/kzg.node ./dist

test:
	yarn jest

format:
	yarn prettier --write .

bundle:
	yarn rollup --config rollup.config.js --bundleConfigAsCjs
