CC ?= gcc
CFLAGS ?= -g -O0 -fPIC

all: static shared

static:
	$(CC) $(CFLAGS) -static -c src/fu53.c -o fu53.o

shared:
	$(CC) $(CFLAGS) -shared -c src/fu53.c -o fu53.so

install:
	install -m 644 fu53.o /usr/lib/fu53.o
	install -m 644 fu53.so /usr/lib/fu53.so

clean:
	rm fu53.*o

.PHONY: all static shared install clean