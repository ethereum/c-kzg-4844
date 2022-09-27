INCLUDE_DIRS = ../inc

.PRECIOUS: %.o

%.o: %.c Makefile
	clang -Wall -I$(INCLUDE_DIRS) $(CFLAGS) $(KZG_CFLAGS) -c $*.c

libckzg4844.a: c_kzg_4844.o Makefile
	ar rc libckzg4844.a $<

lib: KZG_CFLAGS += -O
lib: clean libckzg4844.a

clean:
	rm -f *.o
	rm -f libckzg4844.a
	rm -f a.out
