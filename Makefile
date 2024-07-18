all:
	gcc -Wall -o tcp_analyzer tcp_analyzer.c packet_handler.c helpers.c -lpcap -lm
clean:
	rm -f tcp_analyzer
