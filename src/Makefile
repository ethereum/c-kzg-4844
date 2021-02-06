TESTS = blst_util_test fft_common_test fft_fr_test fft_g1_test \
	kzg_proofs_test poly_test
LIB_SRC = blst_util.c fft_common.c fft_fr.c fft_g1.c kzg_proofs.c poly.c
LIB_OBJ = $(LIB_SRC:.c=.o)

CFLAGS =

.PRECIOUS: %.o

%.o: %.c %.h c_kzg.h Makefile
	clang -Wall $(CFLAGS) -c $*.c

libckzg.a: $(LIB_OBJ) Makefile
	ar rc libckzg.a $(LIB_OBJ)

%_test: %_test.c debug_util.o libckzg.a Makefile
	clang -Wall $(CFLAGS) -o $@ $@.c debug_util.o libckzg.a -L../lib -lblst
	./$@

lib: clean libckzg.a

debuglib: CFLAGS += -g -DDEBUG
debuglib: clean libckzg.a

test: $(TESTS)

clean:
	rm -f *.o
	rm -f libckzg.a
	rm -f $(TESTS)
	rm -f a.out
