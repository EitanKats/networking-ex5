CC=gcc
FLAGS=-Werror -g

all: myping sniffer

myping:
	$(CC) $(FLAGS) ICMP.c -o myping

sniffer:
	$(CC) $(FLAGS) sniffer.c -lpcap -o sniffer

clean:
	rm -f myping sniffer