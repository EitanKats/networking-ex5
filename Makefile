CC=gcc
FLAGS=-Werror -g

all: icmp sniffer

icmp:
	$(CC) $(FLAGS) ICMP.cpp -o icmp

sniffer:
	$(CC) $(FLAGS) sniffer.c -o sniffer

clean:
	rm -f icmp sniffer