all: pcap_hello

pcap_hello: packet.o main.o
	g++ -g -o pcap_hello packet.o main.o -lpcap

main.o:
	g++ -g -c -o main.o main.cpp

packet.o:
	g++ -g -c -o packet.o packet.cpp

clean:
	rm -f pcap_hello
	rm -f *.o

reall: clean all
