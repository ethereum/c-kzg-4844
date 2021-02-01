tests = fft_fr_test

fft_fr.o: fft_fr.c fft_fr.h c-kzg.h
	clang -Wall -c fft_fr.c

%_test: %.o %_test.c
	@clang -Wall -o $@ $@.c $*.o -Llib -lblst
	@./$@

test: $(tests)
	@rm -f $(tests)

clean:
	rm -f *.o
	rm -f $(tests)
	rm -f a.out
