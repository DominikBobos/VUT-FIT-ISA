CC=gcc
CFLAGS= -std=gnu99 -pedantic -Wall -Wextra #-lpcap
all:
	$(CC) $(CFLAGS) ssl-sniffer.c -o  ssl-sniffer # -lpcap

clean:
	rm -f ipk-sniffer