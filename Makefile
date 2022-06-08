CC=gcc
FLAGS=-Wall -g

all: icmp

icmp:
	$(CC) $(FLAGS) ICMP.cpp -o icmp

sniffer:
	$(CC) $(FLAGS) sniffer.cpp -o sniffer

clean:
	rm -f icmp