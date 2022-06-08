CC=gcc
FLAGS=-Wall -g

all: icmp

icmp:
	$(CC) $(FLAGS) ICMP.cpp -o icmp

clean:
	rm -f icmp