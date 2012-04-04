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
#include <strings.h>

struct hostidmap_entry {
	char *name;
	int id;
};

struct hostidmap_entry *hostids = NULL;
int numhostids = 0;

int hostidmap_init() {
	hostids = NULL;
	numhostids = 0;
	return 0;
}

int hostidmap_add(char *name, int id) {
	hostids = realloc(hostids, sizeof(struct hostidmap_entry) * (numhostids + 1));
	hostids[numhostids].name = strdup(name);
	hostids[numhostids].id = id;
	numhostids++;
	return 0;
}

int hostidmap_getidbyname(char *name) {
	int i;
	for(i = 0; i < numhostids; i++) {
		if(strcasecmp(name, hostids[i].name) == 0) return hostids[i].id;
	}
	return -1;
}

char *hostidmap_getnamebyid(int id) {
	int i;
	for(i = 0; i < numhostids; i++) {
		if(hostids[i].id == id) return hostids[i].name;
	}
	return NULL;
}

void hostidmap_free() {
	int i;
	for(i = 0; i < numhostids; i++) free(hostids[i].name);
	free(hostids);
	hostids = NULL;
	numhostids = 0;
}

int hostidmap_getnumhosts() {
	return numhostids;
}

int hostidmap_getmaxid() {
	int i;
	int max = -1;
	for(i = 0; i < numhostids; i++) {
		if(hostids[i].id > max) max = hostids[i].id;
	}
	return max;
}
