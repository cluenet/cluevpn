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


#ifndef __BNL_H
#define __BNL_H

#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "nodeinfo.h"

#define BNL_FILENAME "bnl.bnl"
#define BNL_MINLEN (8 + sizeof(struct bnl_header))

// Structures for BNL subnet records
union bnl_record_subaddr {
	struct in_addr addr4;
	struct in6_addr addr6;
} __attribute__ ((__packed__));

struct bnl_record_subnet {
	unsigned short family;
	union bnl_record_subaddr addr;
	unsigned char cidr;
} __attribute__ ((__packed__));

// Struct for a BNL record *header* (followed by variable length data)
// Everything is stored in NBO
struct bnl_record_hdr {
	char name[NODEINFO_NAMESIZE];
	int id;
	struct in_addr addr4;
	struct in6_addr addr6;
	unsigned short port;
	char addr6preferred;
	int numsubnets;
	struct bnl_record_subnet subnets[];
} __attribute__ ((__packed__));

struct bnl_header {
	int timestamp;
} __attribute__ ((__packed__));


struct bnl_record_hdr *bnl_record_next(struct bnl_record_hdr *r, void *end);
struct bnl_record_hdr *bnl_record_start(void *bnlmem, void *end, struct bnl_header *bnlhdr);
int getbnltimestamp(void *bnlmem);
int bnl_loadnewbnl(void *bnlmem, int bnlsize);
int bnl_loadbnlfile(char **retdata, int *retdatalen);
int bnl_callsubnetups(void *bnlmem, int bnlsize);

extern char *bnl_current;
extern int bnl_current_len;
extern char bnl_filename[CONFIGFILE_FILENAME_LEN];

#endif
