#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "protocol/all.h"
#include "packet.h"

const char* HTTP_METHOD_HTTP = "HTTP";
const char* HTTP_METHOD_GET = "GET";
const char* HTTP_METHOD_POST = "POST";
const char* HTTP_METHOD_PUT = "PUT";
const char* HTTP_METHOD_DELETE = "DELETE";
const char* HTTP_METHOD_CONNECT = "CONNECT";
const char* HTTP_METHOD_OPTIONS = "OPTIONS";
const char* HTTP_METHOD_TRACE = "TRACE";
const char* HTTP_METHOD_PATCH = "PATCH";

const void* HTTP_METHOD[9] = 
{
    HTTP_METHOD_HTTP,
    HTTP_METHOD_GET,
    HTTP_METHOD_POST,
    HTTP_METHOD_PUT,
    HTTP_METHOD_DELETE,
    HTTP_METHOD_CONNECT,
    HTTP_METHOD_OPTIONS,
    HTTP_METHOD_TRACE,
    HTTP_METHOD_PATCH
};

bool httpCheck(const u_char* data){
	for(int i=0; i<9; i++ ){
		if(!strncmp((const char*)data, (const char*)HTTP_METHOD[i], strlen((const char*)HTTP_METHOD[i]))){
			printf("HTTP Method: %s\n", HTTP_METHOD[i]);
			return true;
		}
	}
	return false;
}

void printHttp(const u_char* data){
	puts("HTTP DATA");
	puts("================================================");
	puts((char*)data);
	puts("================================================");
}

void usage(char *text){
	printf("syntax: %s <interface>\n", text);
	printf("sample: %s wlan0\n", text);
}

int main(int argc, char **argv){
	if(argc!=2){
		usage(argv[0]);
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];	
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL){
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	while(true){
		struct pcap_pkthdr* header;
		const unsigned char* packet;
		uint type;
		uint headerSize = 0;
		int res = pcap_next_ex(handle, &header, &packet);

		if(res == 0) continue;
		if(res == -1 || res == -2) break;

		const ether_header* eth = (ether_header*)packet;
		headerSize += sizeof(ether_header);
		type = hexswap(eth->ether_type);
		if(type != ETHERTYPE_IP) continue;
		printf("%u bytes captured\n", header->caplen);
		printf("MAC SRC: ");
		printMacaddr(eth->src);
		printf("MAC DEST: ");
		printMacaddr(eth->dst);
		printf("Type: ");
		if(type == ETHERTYPE_IP){
			const ip_header* ip = (ip_header*)(packet + headerSize);
			headerSize += sizeof(ip_header);
			printf("IPv4(%04X)\n", type);
			printf("IP SRC: ");
			printIpaddr(ip->ip_src);
			printf("IP DEST: ");
			printIpaddr(ip->ip_dst);
			if(ip->ip_p == IP_PROTOCOL_TCP){
				const tcp_header* tcp = (tcp_header*)(packet + headerSize);
				uint32_t tcp_header_size = tcp->th_off * 4;
				headerSize += tcp_header_size;
				uint16_t srcport = hexswap(tcp->th_sport);
				uint16_t dstport = hexswap(tcp->th_dport);
				printf("TCP SRC PORT: %u\n", srcport);
				printf("TCP DEST PORT: %u\n", dstport);
				const u_char* data = (u_char*)(packet + headerSize);
				uint datalen = hexswap(ip->ip_len) - ((ip->ip_hl + tcp->th_off) * 4);
				if(datalen)
					if(httpCheck(data))
						printHttp(data);
					else
						printPacket(data, datalen);
			}
			else if(ip->ip_p == IP_PROTOCOL_UDP){
				const udp_header* udp = (udp_header*)(packet + headerSize);
				headerSize += sizeof(udp_header);
				uint16_t srcport = hexswap(udp->udp_srcport);
				uint16_t dstport = hexswap(udp->udp_dstport);
				printf("UDP SRC PORT: %u\n", srcport);
				printf("UDP DEST PORT: %u\n", dstport);
				const u_char* data = (u_char*)(packet + headerSize);
				uint datalen = hexswap(ip->ip_len) - (ip->ip_hl * 4) - sizeof(udp_header);
				if(datalen){
					printPacket(data, datalen);
				}
			}
			else if(ip->ip_p == IP_PROTOCOL_ICMP){
				const icmp_header* icmp = (icmp_header*)(packet + headerSize);
				headerSize += sizeof(icmp_header);
				printf("ICMP Type: ");
				if(icmp->icmp_type == ICMP_PINGREPLY)
					printf("ECHO (PING) REPLY");
				else if(icmp->icmp_type == ICMP_PINGREQUEST)
					printf("ECHO (PING) REQUEST");
				else
					printf("UNKNOWN YET");
				printf("(%02X)\n", icmp->icmp_type);
				
				printf("ICMP Code: %u\n", icmp->icmp_code);
				const u_char* data = (u_char*)(packet + headerSize);
				uint datalen = hexswap(ip->ip_len) - (ip->ip_hl * 4) - sizeof(icmp_header);
				if(datalen){
					printPacket(data, datalen);
				}
			}		
		}
		else if(type == ETHERTYPE_ARP){
			const arp_header* arp = (arp_header*)(packet + sizeof(ether_header));
			uint16_t opcode = hexswap(arp->arp_opcode);
			printf("ARP(%04X)\n", type);
			printf("Opcode: ");
			if(opcode == ARPOP_REQUEST)
				printf("ARP REQUEST");
			else if(opcode == ARPOP_REPLY)
				printf("ARP REPLY");
			else
				printf("UNKNOWN YET");
			printf("(%02X)\n", opcode);
			
			printf("Sender Hardware Address: ");
			printMacaddr(arp->arp_srcmac);
			printf("Sender Protocol Address: ");
			printIpaddr(arp->arp_srcip);
			printf("Target Hardware Address: ");
			printMacaddr(arp->arp_dstmac);
			printf("Target Protocol Address: ");
			printIpaddr(arp->arp_dstip);
			puts("");
		}
		else if(type == ETHERTYPE_IPV6)
			printf("IPv6(%04X)\n", type);
		else if(type == ETHERTYPE_REVARP)
			printf("RARP(%04X)\n", type);
		else
			printf("UNKNOWN YET(%04X)\n", type);
		puts("");
	}

	pcap_close(handle);
	return 0;
}
