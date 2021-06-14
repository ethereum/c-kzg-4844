TESTS = bls12_381_test das_extension_test c_kzg_util_test fft_common_test fft_fr_test fft_g1_test \
	fk20_proofs_test kzg_proofs_test poly_test recover_test utility_test zero_poly_test
BENCH = fft_fr_bench fft_g1_bench recover_bench zero_poly_bench
LIB_SRC = bls12_381.c c_kzg_util.c das_extension.c fft_common.c fft_fr.c fft_g1.c fk20_proofs.c kzg_proofs.c poly.c recover.c utility.c zero_poly.c
LIB_OBJ = $(LIB_SRC:.c=.o)

KZG_CFLAGS =
INCLUDE_DIRS = ../inc

.PRECIOUS: %.o

%.o: %.c %.h c_kzg.h Makefile
	clang -Wall -I$(INCLUDE_DIRS) $(CFLAGS) $(KZG_CFLAGS) -c $*.c

libckzg.a: $(LIB_OBJ) Makefile
	ar rc libckzg.a $(LIB_OBJ)

%_test: %_test.c debug_util.o test_util.o libckzg.a Makefile
	clang -Wall -I$(INCLUDE_DIRS) $(CFLAGS) $(KZG_CFLAGS) -o $@ $@.c debug_util.o test_util.o libckzg.a -L../lib -lblst
	./$@

# This version will abort on error and print the file and line number
%_test_debug: KZG_CFLAGS += -g -O0 -DDEBUG
%_test_debug: %_test.c debug_util.o test_util.o libckzg.a Makefile
	clang -Wall -I$(INCLUDE_DIRS) $(CFLAGS) $(KZG_CFLAGS) -o $@ $*_test.c debug_util.o test_util.o libckzg.a -L../lib -lblst

# Benchmarks
%_bench: KZG_CFLAGS += -O
%_bench: %_bench.c bench_util.o test_util.o $(LIB_OBJ) Makefile
	clang -Wall -I$(INCLUDE_DIRS) $(CFLAGS) $(KZG_CFLAGS) -o $@ $@.c bench_util.o test_util.o $(LIB_OBJ) -L../lib -lblst
	./$@

lib: KZG_CFLAGS += -O
lib: clean libckzg.a

profilelib: KZG_CFLAGS += -fprofile-instr-generate -fcoverage-mapping
profilelib: clean libckzg.a

test: $(TESTS)

bench: $(BENCH)

clean:
	rm -f *.o
	rm -f libckzg.a
	rm -f $(TESTS)
	rm -f $(BENCH)
	rm -f *_debug
	rm -f a.out
