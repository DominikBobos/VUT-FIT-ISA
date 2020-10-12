CC=gcc
CFLAGS= -std=gnu99 -pedantic -Wall -Wextra -lpcap
DEPS = ssl-sniffer.h

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

all: ssl-sniffer.o list.o
	$(CC) -o ssl-sniffer ssl-sniffer.o list.o -lpcap

clean:
	rm -f ssl-sniffer