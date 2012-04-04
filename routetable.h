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


#ifndef _ROUTETABLE_H
#define _ROUTETABLE_H

#define ROUTETABLE_OK 0
#define ROUTETABLE_NOROUTE 1

struct routetable_trienode {
	int hostid;
	struct routetable_trienode *zerobranch;
	struct routetable_trienode *onebranch;
};

typedef struct {
	struct routetable_trienode *root;
} routetable_t;

int routetable_init(routetable_t *rt);
void routetable_cleanupnode(struct routetable_trienode *node);
void routetable_cleanup(routetable_t *rt);
int routetable_clear(routetable_t *rt);
int routetable_addroute(routetable_t *rt, void *subnet_vp, unsigned char cidr, int hostid);
int routetable_getroute(routetable_t *rt, void *ip_vp, unsigned char addrbits, int *hostid);

extern routetable_t ipv4routetable;
extern routetable_t ipv6routetable;

#endif
