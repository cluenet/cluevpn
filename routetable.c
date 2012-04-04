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
#include "routetable.h"

routetable_t ipv4routetable;
routetable_t ipv6routetable;

int routetable_init(routetable_t *rt) {
	rt->root = malloc(sizeof(struct routetable_trienode));
	rt->root->hostid = -1;
	rt->root->zerobranch = NULL;
	rt->root->onebranch = NULL;
	return ROUTETABLE_OK;
}

void routetable_cleanupnode(struct routetable_trienode *node) {
	if(node->zerobranch) routetable_cleanupnode(node->zerobranch);
	if(node->onebranch) routetable_cleanupnode(node->onebranch);
	free(node);
}

void routetable_cleanup(routetable_t *rt) {
	routetable_cleanupnode(rt->root);
	rt->root = NULL;
}

int routetable_clear(routetable_t *rt) {
	routetable_cleanup(rt);
	return routetable_init(rt);
}

int routetable_addroute(routetable_t *rt, void *subnet_vp, unsigned char cidr, int hostid) {
	struct routetable_trienode *cnode = rt->root;
	unsigned char *subnet = (unsigned char *)subnet_vp;
	int cbit;
	char bitval;
	for(cbit = 0; cbit < cidr; cbit++) {
		bitval = (subnet[cbit / 8] & (0x80 >> (cbit % 8))) ? 1 : 0;
		if(!bitval) {
			if(!cnode->zerobranch) {
				cnode->zerobranch = malloc(sizeof(struct routetable_trienode));
				cnode->zerobranch->zerobranch = NULL;
				cnode->zerobranch->onebranch = NULL;
				cnode->zerobranch->hostid = -1;
			}
			cnode = cnode->zerobranch;
		} else {
			if(!cnode->onebranch) {
				cnode->onebranch = malloc(sizeof(struct routetable_trienode));
				cnode->onebranch->zerobranch = NULL;
				cnode->onebranch->onebranch = NULL;
				cnode->onebranch->hostid = -1;
			}
			cnode = cnode->onebranch;
		}
	}
	cnode->hostid = hostid;
	return ROUTETABLE_OK;
}

int routetable_getroute(routetable_t *rt, void *ip_vp, unsigned char addrbits, int *hostid) {
	struct routetable_trienode *cnode = rt->root;
	unsigned char *ip = (unsigned char *)ip_vp;
	int cbit;
	char bitval;
	*hostid = -1;
	for(cbit = 0; cbit < addrbits; cbit++) {
		if(cnode->hostid >= 0) *hostid = cnode->hostid;
		bitval = (ip[cbit / 8] & (0x80 >> (cbit % 8))) ? 1 : 0;
		if(!bitval) {
			if(!cnode->zerobranch) break;
			cnode = cnode->zerobranch;
		} else {
			if(!cnode->onebranch) break;
			cnode = cnode->onebranch;
		}
	}
	if(cnode->hostid >= 0) *hostid = cnode->hostid;
	if(*hostid < 0) return ROUTETABLE_NOROUTE;
	return ROUTETABLE_OK;
}

/*
void _routetable_test() {
	unsigned char caddr[4];
	unsigned char ccidr;
	int chostid;
	int p1, p2, p3, p4, p5, p6;
	routetable_t rt;
	routetable_init(&rt);
	while(1) {
		printf("Enter X.X.X.X/X:X to add an address OR X.X.X.X/-1:X to break:\n");
		scanf("%d.%d.%d.%d/%d:%d", &p1, &p2, &p3, &p4, &p5, &p6);
		if(p5 == -1) break;
		caddr[0] = p1;
		caddr[1] = p2;
		caddr[2] = p3;
		caddr[3] = p4;
		ccidr = p5;
		chostid = p6;
		routetable_addroute(&rt, (void *)caddr, ccidr, chostid);
		printf("Added %d.%d.%d.%d/%d to host %d\n", p1, p2, p3, p4, p5, p6);
	}
	while(1) {
		printf("Enter X.X.X.X to route an address OR -1.X.X.X to break:\n");
		scanf("%d.%d.%d.%d", &p1, &p2, &p3, &p4);
		if(p1 == -1) break;
		caddr[0] = p1;
		caddr[1] = p2;
		caddr[2] = p3;
		caddr[3] = p4;
		routetable_getroute(&rt, (void *)caddr, 32, &chostid);
		printf("Routed to host: %d\n", chostid);
	}
}
*/

