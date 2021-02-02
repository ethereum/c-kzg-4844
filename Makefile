tests = fft_fr_test

.PRECIOUS: %.o

%.o: %.c %.h c-kzg.h
	clang -Wall -c $*.c

%_test: %.o %_test.c test_util.o
	clang -Wall -o $@ $@.c test_util.o $*.o -Llib -lblst
	./$@

test: $(tests)
	rm -f $(tests)

clean:
	rm -f *.o
	rm -f $(tests)
	rm -f a.out
