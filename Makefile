#Makefile
all: pcap-test

pcap-test: main.o pcap-test.o
	g++ -o pcap-test main.o pcap-test.o -lpcap

main.o: pcap-test.h main.c
	g++ -c -o main.o main.c

pcap-test.o: pcap-test.h pcap-test.c
	g++ -c -o pcap-test.o pcap-test.c

clean:
	rm -f pcap-test
	rm -f *.o
