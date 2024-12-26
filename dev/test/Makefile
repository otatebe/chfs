CFLAGS=$(shell pkg-config --cflags chfs)
LIBS=$(shell pkg-config --libs chfs)

test: test.c
	cc -O -Wall test.c -o test $(CFLAGS) $(LIBS)

clean:;
	rm -f test
