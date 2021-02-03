tests = fft_util_test fft_fr_test fft_g1_test
c_kzg_sources = fft_util.c fft_fr.c fft_g1.c
c_kzg_objects = $(c_kzg_sources:.c=.o)

.PRECIOUS: %.o

%.o: %.c %.h c-kzg.h
	clang -Wall -c $*.c

libckzg.a: $(c_kzg_objects)
	ar rc libckzg.a $(c_kzg_objects)

%_test: %_test.c test_util.o libckzg.a Makefile
	clang -Wall -o $@ $@.c test_util.o libckzg.a -L../lib -lblst
	./$@

lib: libckzg.a

test: $(tests)

clean:
	rm -f *.o
	rm -f libckzg.a
	rm -f $(tests)
	rm -f a.out
