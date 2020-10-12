CC=gcc
CFLAGS= -std=gnu99 -pedantic -Wall -Wextra -lpcap
DEPS = ssl-monitor.h

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

all: ssl-monitor.o list.o
	$(CC) -o ssl-monitor ssl-monitor.o list.o -lpcap
	rm -f ssl-monitor.o list.o

clean:
	rm -f ssl-monitor 