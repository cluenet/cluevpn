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


#ifndef _NETPACKETS_H
#define _NETPACKETS_H

#ifndef __USE_BSD
#define __USE_BSD
#endif

#include <netinet/ip.h>
#include <netinet/ip6.h>

#define IPPACKET_MINLEN ((sizeof(struct ip) > sizeof(struct ip6_hdr)) ? sizeof(struct ip6_hdr) : sizeof(struct ip))

#define IPPACKET_VERSION(pktptr) (((struct ip *)pktptr)->ip_v)
#define IP4PACKET_DESTADDR(pktptr) (((struct ip *)pktptr)->ip_dst)
#define IP6PACKET_DESTADDR(pktptr) (((struct ip6_hdr *)pktptr)->ip6_dst)
#define IP4PACKET_SRCADDR(pktptr) (((struct ip *)pktptr)->ip_src)
#define IP6PACKET_SRCADDR(pktptr) (((struct ip6_hdr *)pktptr)->ip6_src)

void netpacket_make4Unreachable(struct in_addr origsrcaddr, struct in_addr origdstaddr, char *databuf, int *datalen, char *origdata, int origdatalen);
void netpacket_make6Unreachable(struct in6_addr origsrcaddr, struct in6_addr origdstaddr, char *databuf, int *datalen, char *origdata, int origdatalen);

#endif

