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


#ifndef _DATAPACKAGE_H
#define _DATAPACKAGE_H

#define DATAPACKET_HASHSIZE 8
#include <arpa/inet.h>
#include <netinet/in.h>

struct datapacket_cryptdata {
	char packettype;
	char hash[DATAPACKET_HASHSIZE];
	unsigned int seqnum_inc;
	unsigned int seqnum_time;
	char data[];
} __attribute__ ((__packed__));

struct datapacket {
	char packettype;
	int srcnode;
	unsigned int ivec;
	char cryptdata[];
} __attribute__ ((__packed__));

int packageDataForNetwork(char *data, int datalen, char *netbuf, int *netbuflen, int nodeid);
int unpackageDataFromNetwork(char *packet, int packetlen, char *databuf, int *databuflen);

#define DPACK_CHECKPTYPE(data) (((struct datapacket *)data)->packettype == 0x00)
#define DPACK_GETSRCNODE(data) ntohl(((struct datapacket *)data)->srcnode)
#define DPACK_MINPACKLEN (sizeof(struct datapacket) + sizeof(struct datapacket_cryptdata) + 20)

#endif
