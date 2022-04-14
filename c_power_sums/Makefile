CFLAGS += -march=native
CFLAGS += -O3

libpsum.so: libpsum.o
	gcc -shared $^ -o $@

libpsum.o: libpsum.c
	gcc -c -Wall -Werror -fPIC $^ -o $@
