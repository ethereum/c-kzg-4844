tests = fft_util_test fft_fr_test fft_g1_test

.PRECIOUS: %.o

%.o: %.c %.h c-kzg.h
	clang -Wall -c $*.c

fft_fr_test: fft_fr.o fft_fr_test.c test_util.o fft_util.o Makefile
	clang -Wall -o $@ $@.c test_util.o fft_fr.o fft_util.o -L../lib -lblst
	./$@

fft_g1_test: fft_g1.o fft_g1_test.c test_util.o fft_util.o Makefile
	clang -Wall -o $@ $@.c test_util.o fft_g1.o fft_util.o -L../lib -lblst
	./$@

%_test: %.o %_test.c test_util.o Makefile
	clang -Wall -o $@ $@.c test_util.o $*.o -L../lib -lblst
	./$@

test: $(tests)
	rm -f $(tests)

clean:
	rm -f *.o
	rm -f $(tests)
	rm -f a.out
