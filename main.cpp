#include <pcap.h>
#include <stdint.h>
#include <stdio.h>

#define ETH_ALEN 6

#define	ETHERTYPE_PUP		0x0200		/* Xerox PUP */
#define ETHERTYPE_SPRITE	0x0500		/* Sprite */
#define	ETHERTYPE_IP		0x0800		/* IP */
#define	ETHERTYPE_ARP		0x0806		/* Address resolution */
#define	ETHERTYPE_REVARP	0x8035		/* Reverse ARP */
#define ETHERTYPE_AT		0x809B		/* AppleTalk protocol */
#define ETHERTYPE_AARP		0x80F3		/* AppleTalk ARP */
#define	ETHERTYPE_VLAN		0x8100		/* IEEE 802.1Q VLAN tagging */
#define ETHERTYPE_IPX		0x8137		/* IPX */
#define	ETHERTYPE_IPV6		0x86dd		/* IP protocol version 6 */
#define ETHERTYPE_LOOPBACK	0x9000		/* used to test interfaces */

struct ether_header{
	uint8_t dst[ETH_ALEN];
	uint8_t src[ETH_ALEN];
	uint16_t ether_type;
} __attribute__ ((__packed__));

void usage(){
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}

int main(int argc, char **argv){
	if(argc!=2){
		usage();
		return -1;
	}
	unsigned int i;

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];	
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL){
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	while(true){
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		unsigned int type;
		if(res == 0) continue;
		if(res == -1 || res == -2) break;
		const ether_header* eth = (ether_header*)packet;
		printf("\n%u bytes captured\n", header->caplen);
		printf("SRC: %02X:%02X:%02X:%02X:%02X:%02X\n", eth->src[0], eth->src[1], eth->src[2], eth->src[3], eth->src[4], eth->src[5]);
		printf("DST: %02X:%02X:%02X:%02X:%02X:%02X\n", eth->dst[0], eth->dst[1], eth->dst[2], eth->dst[3], eth->dst[4], eth->dst[5]);
		type = eth->ether_type;
		type = (type&0x00ff)<<8 | (type&0xff00)>>8;
		printf("Type: ");
		if(type == ETHERTYPE_IP)
			printf("IPv4\n");
		else if(type == ETHERTYPE_IPV6)
			printf("IPv6\n");
		else if(type == ETHERTYPE_ARP)
			printf("ARP\n");
		else if(type == ETHERTYPE_REVARP)
			printf("RARP\n");
		else
			printf("UNKNOWN YET\n");
		
	}

	pcap_close(handle);
	return 0;
}
