/*
 * Copyright 2009 Christopher Breneman
 *
 * This file is part of ClueVPN.
 *
 * ClueVPN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ClueVPN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ClueVPN.  If not, see <http://www.gnu.org/licenses/>.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include "netpackets.h"

char ctrlpktbuf[65536];
int ctrlpktbuflen;

/*unsigned short ipcksum(void *data, int len) {
	long sum = 0;
	while(len > 1) {
		sum += *((unsigned short *)data)++;
		if(sum & 0x80000000) sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}
	if(len) sum += (unsigned short)*(unsigned char *)data;
	while(sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
	return ~sum;
}*/

unsigned short ipcksum(void *data, int len) {
	register long sum = 0;
	while(len > 1) {
		sum += *(unsigned short *)data;
		data += sizeof(unsigned short);
		len -= 2;
	}
	if(len > 0) sum += *(unsigned char *)data;
	while(sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
	return ~sum;
}

void netpacket_makeipv4(u_int8_t proto, struct in_addr srcaddr, struct in_addr dstaddr, char *data, int datalen) {
	struct ip ipbuf;
	memset(&ipbuf, 0, sizeof(ipbuf));
	ipbuf.ip_hl = sizeof(struct ip) / 4;
	ipbuf.ip_v = 4;
	ipbuf.ip_tos = 0;
	//ipbuf.ip_tos = 0xc0;
	ipbuf.ip_len = htons(sizeof(struct ip) + datalen);
	ipbuf.ip_id = 0;
	//ipbuf.ip_id = rand();
	ipbuf.ip_off = 0;
	ipbuf.ip_ttl = 64;
	ipbuf.ip_p = proto;
	ipbuf.ip_sum = 0;
	ipbuf.ip_src = srcaddr;
	ipbuf.ip_dst = dstaddr;
	ipbuf.ip_sum = ipcksum((void *)&ipbuf, sizeof(ipbuf));
	if(data != (char *)(ctrlpktbuf + sizeof(struct ip))) memmove(ctrlpktbuf + sizeof(struct ip), data, datalen);
	memcpy(ctrlpktbuf, &ipbuf, sizeof(struct ip));
	ctrlpktbuflen = sizeof(struct ip) + datalen;
}

void netpacket_makeipv6(u_int8_t proto, struct in6_addr srcaddr, struct in6_addr dstaddr, char *data, int datalen) {
	struct ip6_hdr ipbuf;
	memset(&ipbuf, 0, sizeof(ipbuf));
	*(unsigned char *)&ipbuf.ip6_ctlun.ip6_un1.ip6_un1_flow = 0x60;
	ipbuf.ip6_ctlun.ip6_un1.ip6_un1_plen = htons(datalen / 2 + datalen % 2);
	ipbuf.ip6_ctlun.ip6_un1.ip6_un1_nxt = proto;
	ipbuf.ip6_ctlun.ip6_un1.ip6_un1_hlim = 64;
	ipbuf.ip6_src = srcaddr;
	ipbuf.ip6_dst = dstaddr;
	if(data != (char *)(ctrlpktbuf + sizeof(struct ip6_hdr))) memmove(ctrlpktbuf + sizeof(struct ip6_hdr), data, datalen);
	memcpy(ctrlpktbuf, &ipbuf, sizeof(struct ip6_hdr));
	ctrlpktbuflen = sizeof(struct ip6_hdr) + datalen;
}

void netpacket_makeicmpmsg(unsigned char type, unsigned char code, char *icmpdata, int icmpdatalen) {
	struct icmp icmpbuf;
	memset(&icmpbuf, 0, sizeof(icmpbuf));
	icmpbuf.icmp_type = type;
	icmpbuf.icmp_code = code;
	memmove(ctrlpktbuf + 8, icmpdata, (8 + icmpdatalen > 65536) ? (65536 - 8) : icmpdatalen);
	//memmove(ctrlpktbuf + sizeof(struct icmp), icmpdata, icmpdatalen);
	memcpy(ctrlpktbuf, &icmpbuf, 8);
	ctrlpktbuflen = 8 + icmpdatalen;
	icmpbuf.icmp_cksum = ipcksum(ctrlpktbuf, ctrlpktbuflen);
	memcpy(ctrlpktbuf, &icmpbuf, 8);
}

void netpacket_make4Unreachable(struct in_addr origsrcaddr, struct in_addr origdstaddr, char *databuf, int *datalen, char *origdata, int origdatalen) {
	netpacket_makeicmpmsg(3, 0, origdata, origdatalen);
	netpacket_makeipv4(IPPROTO_ICMP, origdstaddr, origsrcaddr, ctrlpktbuf, ctrlpktbuflen);
	*datalen = ctrlpktbuflen;
	memcpy(databuf, ctrlpktbuf, ctrlpktbuflen);
}

void netpacket_make6Unreachable(struct in6_addr origsrcaddr, struct in6_addr origdstaddr, char *databuf, int *datalen, char *origdata, int origdatalen) {
	netpacket_makeicmpmsg(3, 0, origdata, origdatalen);
	netpacket_makeipv6(IPPROTO_ICMP, origdstaddr, origsrcaddr, ctrlpktbuf, ctrlpktbuflen);
	*datalen = ctrlpktbuflen;
	memcpy(databuf, ctrlpktbuf, ctrlpktbuflen);
}
