CFLAGS=$(shell pkg-config --cflags chfs)
LIBS=$(shell pkg-config --libs chfs)

all: test flush_error

test: test.c
	cc -O -Wall test.c -o test $(CFLAGS) $(LIBS)

flush_error: flush_error.c
	cc -O -Wall flush_error.c -o flush_error $(CFLAGS) $(LIBS)

clean:;
	rm -f test flush_error
