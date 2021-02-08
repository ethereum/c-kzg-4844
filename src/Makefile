TESTS = blst_util_test c_kzg_util_test fft_common_test fft_fr_test fft_g1_test \
	kzg_proofs_test poly_test
BENCH = fft_fr_bench fft_g1_bench
LIB_SRC = blst_util.c c_kzg_util.c fft_common.c fft_fr.c fft_g1.c kzg_proofs.c poly.c
LIB_OBJ = $(LIB_SRC:.c=.o)

CFLAGS = -g

.PRECIOUS: %.o

%.o: %.c %.h c_kzg.h Makefile
	clang -Wall $(CFLAGS) -c $*.c

libckzg.a: $(LIB_OBJ) Makefile
	ar rc libckzg.a $(LIB_OBJ)

%_test: %_test.c debug_util.o libckzg.a Makefile
	clang -Wall $(CFLAGS) -o $@ $@.c debug_util.o libckzg.a -L../lib -lblst
	./$@

%_bench: %_bench.c bench_util.o $(LIB_OBJ) Makefile
	clang -Wall $(CFLAGS) -o $@ $@.c bench_util.o $(LIB_OBJ) -L../lib -lblst
	./$@

lib: clean libckzg.a

debuglib: CFLAGS += -O1 -DDEBUG
debuglib: clean libckzg.a

optlib: CFLAGS += -O2
optlib: clean libckzg.a

profilelib: CFLAGS += -fprofile-instr-generate -fcoverage-mapping
profilelib: clean libckzg.a

test: $(TESTS)

bench: $(BENCH)

clean:
	rm -f *.o
	rm -f libckzg.a
	rm -f $(TESTS)
	rm -f $(BENCH)
	rm -f a.out
