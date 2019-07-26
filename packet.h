#pragma once

#include <stdio.h>
#include <stdint.h>
#include "protocol/all.h"

void printPacket(const u_char* data, uint datalen);
void printMacaddr(mac_addr mac);
void printIpaddr(ip_addr ip);
bool httpCheck(const u_char* data);