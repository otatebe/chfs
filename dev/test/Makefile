# SANFLAGS, e.g. -fsanitize=address, is for a sanitizer
CFLAGS=$(shell pkg-config --cflags chfs) $(SANFLAGS)
LIBS=$(shell pkg-config --libs chfs) $(SANFLAGS)

all: test flush_error no_space

test: test.c
	cc -O -Wall test.c -o test $(CFLAGS) $(LIBS)

flush_error: flush_error.c
	cc -O -Wall flush_error.c -o flush_error $(CFLAGS) $(LIBS)

no_space: no_space.c
	cc -O -Wall no_space.c -o no_space $(CFLAGS) $(LIBS)

clean:;
	rm -f test flush_error no_space
