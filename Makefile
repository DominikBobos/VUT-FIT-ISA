CC=gcc
CFLAGS= -std=gnu99 -pedantic -Wall -Wextra -lpcap
DEPS = sslsniff.h

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

all: sslsniff.o list.o
	$(CC) -o sslsniff sslsniff.o list.o -lpcap
	rm -f sslsniff.o list.o

clean:
	rm -f sslsniff