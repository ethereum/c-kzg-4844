tests = fft_fr_test fft_util_test

.PRECIOUS: %.o

%.o: %.c %.h c-kzg.h
	clang -Wall -c $*.c

fft_fr_test: fft_fr.o fft_fr_test.c test_util.o fft_util.o
	clang -Wall -o $@ $@.c test_util.o fft_fr.o fft_util.o -L../lib -lblst
	./$@

%_test: %.o %_test.c test_util.o
	clang -Wall -o $@ $@.c test_util.o $*.o -L../lib -lblst
	./$@

test: $(tests)
	rm -f $(tests)

clean:
	rm -f *.o
	rm -f $(tests)
	rm -f a.out
