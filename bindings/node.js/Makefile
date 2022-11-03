clean:
	yarn clean
	rm -rf build
	rm -f *.node
	rm -f *.a
	rm -f *.o

build: kzg.cxx Makefile
	cd ../../src; make lib
	yarn build
	cp build/Release/kzg.node .
