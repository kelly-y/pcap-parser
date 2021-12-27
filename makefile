SHELL = /bin/bash
CC = gcc

all: parser
parser: parser.c
	${CC} parser.c -o parser -lpcap

exe:
	./parser test.pcap

clean:
	rm -f parser *.o