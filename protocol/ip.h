#pragma once

#include <stdint.h>
#include <stdio.h>

#define IP_PROTOCOL_ICMP	0x01
#define IP_PROTOCOL_TCP		0x06
#define IP_PROTOCOL_UDP		0x11

struct ip_addr{
	uint8_t a;
	uint8_t b;
	uint8_t c;
	uint8_t d;
};

struct ip_header{
	#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint32_t ip_hl : 4;
	uint32_t ip_v : 4;
	#elif __BYTE_ORDER == __BIG_ENDIAN
	uint32_t ip_v : 4;
	uint32_t ip_hl : 4;
	#else
	#error "Adjust your <bits/endian.h> defines"
	#endif
	uint8_t ip_tos;
	uint16_t ip_len;
	uint16_t ip_id;
	uint16_t ip_off;
	#define IP_RF		0x8000
	#define IP_DF		0x4000
	#define IP_MF		0x2000
	#define IP_OFFMASK	0x1fff
	uint8_t ip_ttl;
	uint8_t ip_p;
	uint16_t ip_sum;
	ip_addr ip_src;
	ip_addr ip_dst;
};