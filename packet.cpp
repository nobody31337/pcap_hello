#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "protocol/all.h"

void printPacket(const u_char* data, uint datalen){
	uint i, j;
	char line[] = "====\t================================================\t=================";
	puts("DATA");
	puts(line);
	for(i = 1; i <= datalen; i++){
		if((i-1) % 16 == 0) printf("%04X\t", i-1);
		printf("%02X ", data[i-1]);
		if(i % 8 == 0 || i == datalen)
			if(i % 16 == 0 || i == datalen){
				uint line = i % 16;
				if(!line) line = 16;
				uint offset = 16 - line;
				for(j=0;j<offset*3;j++)
					printf(" ");
				printf("\t");
				for(j=0;j<line;j++){
					printf("%c", data[j+i-line] >= 32 && data[j+i-line] <= 126 ? data[j+i-line] : '.' );
					if((j+1) % 8 == 0)
						printf(" ");
				}
				puts("");
			}
			else
				printf(" ");
	}
	puts(line);
}

void printMacaddr(mac_addr mac){
	printf("%02X:%02X:%02X:%02X:%02X:%02X\n", mac.oui[0], mac.oui[1], mac.oui[2], mac.nic[0], mac.nic[1], mac.nic[2]);
}

void printIpaddr(ip_addr ip){
	printf("%u.%u.%u.%u\n", ip.a, ip.b, ip.c, ip.d);
}