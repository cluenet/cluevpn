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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include "logger.h"
#include "crypt.h"
#include "configfile.h"
#include "nodeinfo.h"
#include "bnl.h"
#include "routetable.h"
#include "signature.h"
#include "connections.h"

char *bnl_current = NULL;
int bnl_current_len = 0;

char bnl_filename[CONFIGFILE_FILENAME_LEN] = "";

struct bnl_record_hdr *bnl_record_next(struct bnl_record_hdr *r, void *end) {
	struct bnl_record_hdr *ret;
	ret = (void *)r + sizeof(struct bnl_record_hdr) + ntohl(r->numsubnets) * sizeof(struct bnl_record_subnet);
	if((void *)ret >= end) return NULL;
	return ret;
}

struct bnl_record_hdr *bnl_record_start(void *bnlmem, void *end, struct bnl_header *bnlhdr) {
	if(bnlhdr) *bnlhdr = *(struct bnl_header *)bnlmem;
	if(end) if(bnlmem + sizeof(struct bnl_header) >= end) return NULL;
	return (struct bnl_record_hdr *)((char *)bnlmem + sizeof(struct bnl_header));
}

int getbnltimestamp(void *bnlmem) {
	struct bnl_header bnlhdr;
	if(!bnl_record_start(bnlmem, NULL, &bnlhdr)) return 0;
	return ntohl(bnlhdr.timestamp);
}

void callSubnetUpCmd(char *cmd, struct bnl_record_subnet *subn, char *nodename, int nodeid) {
	static char addrstr[256];
	static char cidrstr[10];
	static char subnstr[256];
	static char tmpstr[10];
	int r;
	if(!cmd) return;
	setenv("TUNDEV", tundevname, 1);
	if(ntohs(subn->family) == AF_INET) {
		setenv("SUBADDRTYPE", "INET", 1);
		inet_ntop(AF_INET, &subn->addr, addrstr, 256);
		setenv("SUBADDR", addrstr, 1);
		sprintf(cidrstr, "%d", subn->cidr);
		setenv("SUBCIDR", cidrstr, 1);
		sprintf(subnstr, "%s/%d", addrstr, subn->cidr);
		setenv("SUBNET", subnstr, 1);
		sprintf(tmpstr, "%d", nodeid);
		setenv("NODEID", tmpstr, 1);
		setenv("NODE", nodename, 1);
	}
	if(ntohs(subn->family) == AF_INET6) {
		setenv("SUBADDRTYPE", "INET6", 1);
		inet_ntop(AF_INET6, &subn->addr, addrstr, 256);
		setenv("SUBADDR", addrstr, 1);
		sprintf(cidrstr, "%d", subn->cidr);
		setenv("SUBCIDR", cidrstr, 1);
		sprintf(subnstr, "%s/%d", addrstr, subn->cidr);
		setenv("SUBNET", subnstr, 1);
		sprintf(tmpstr, "%d", nodeid);
		setenv("NODEID", tmpstr, 1);
		setenv("NODE", nodename, 1);
	}
	r = system(cmd);
	unsetenv("TUNDEV");
	unsetenv("SUBADDRTYPE");
	unsetenv("SUBADDR");
	unsetenv("SUBCIDR");
	unsetenv("SUBNET");
	unsetenv("NODEID");
	unsetenv("NODE");
}

int bnl_callsubnetups(void *bnlmem, int bnlsize) {
	struct bnl_header bnlhdr;
	struct bnl_record_hdr *crecord;
	struct nodeinfo ni;
	void *bnlend = bnlmem + bnlsize;
	int r, i;
	// Iterate through each BNL record
	for(crecord = bnl_record_start(bnlmem, bnlend, &bnlhdr); crecord; crecord = bnl_record_next(crecord, bnlend)) {
		// Convert id and numsubnets to host byte order - don't convert port because it stays in NBO
		crecord->id = ntohl(crecord->id);
		crecord->numsubnets = ntohl(crecord->numsubnets);
		// Make sure an entry for this ID exists
		if(!NODEINFO_EXISTS(crecord->id)) continue;
		// Call the command for each subnet
		for(i = 0; i < crecord->numsubnets; i++) {
			if(crecord->id == global_config.id) {
				callSubnetUpCmd(global_config.mysubnetupcmd, &crecord->subnets[i], NODEINFO_INFO(crecord->id).name, crecord->id);
			} else {
				callSubnetUpCmd(global_config.subnetupcmd, &crecord->subnets[i], NODEINFO_INFO(crecord->id).name, crecord->id);
			}
		}
		// Fix the byte order to the original
		crecord->id = htonl(crecord->id);
		crecord->numsubnets = htonl(crecord->numsubnets);
	}
	return NODEINFO_OK;
}

int bnl_loadnewbnl(void *bnlmem, int bnlsize) {
	struct bnl_header bnlhdr;
	struct bnl_record_hdr *crecord;
	struct nodeinfo ni;
	void *bnlend = bnlmem + bnlsize;
	int r, i;
	// First clear out the routing tables - routes will be readded as BNL records are processed
	r = routetable_clear(&ipv4routetable);
	if(r != ROUTETABLE_OK) {
		logmsg(LOGGER_ERR, "Error clearing out routing tables");
		return NODEINFO_ERROR;
	}
	r = routetable_clear(&ipv6routetable);
	if(r != ROUTETABLE_OK) {
		logmsg(LOGGER_ERR, "Error clearing out routing tables");
		return NODEINFO_ERROR;
	}
	// Set the delete flag on each nodeinfo record to 1 (delete by default unless it's in the BNL)
	for(i = 0; i <= maxvpnnodeid; i++) vpnnodes[i].delete = 1;
	// Iterate through each BNL record
	for(crecord = bnl_record_start(bnlmem, bnlend, &bnlhdr); crecord; crecord = bnl_record_next(crecord, bnlend)) {
		// Convert id and numsubnets to host byte order - don't convert port because it stays in NBO
		crecord->id = ntohl(crecord->id);
		crecord->numsubnets = ntohl(crecord->numsubnets);
		// Check if an entry for this ID exists yet - if it doesn't exist, create a new, blank nodeinfo entry for it
		if(!NODEINFO_EXISTS(crecord->id)) {
			memset(&ni, 0, sizeof(ni));
			memcpy(ni.name, crecord->name, NODEINFO_NAMESIZE);
			ni.name[NODEINFO_NAMESIZE - 1] = 0;
			ni.id = crecord->id;
			ni.addr4.sin_family = AF_INET;
			ni.addr4.sin_port = crecord->port;
			ni.addr4.sin_addr = crecord->addr4;
			ni.addr6.sin6_family = AF_INET6;
			ni.addr6.sin6_port = crecord->port;
			ni.addr6.sin6_addr = crecord->addr6;
			ni.addr6preferred = crecord->addr6preferred;
			ni.delete = 0;
			r = nodeinfo_addnode(ni);
			if(r != NODEINFO_OK) return r;
		} else {
			// The node already exists.  Update the name and address information and set the delete flag to 0.
			memcpy(vpnnodes[crecord->id].name, crecord->name, NODEINFO_NAMESIZE);
			vpnnodes[crecord->id].name[NODEINFO_NAMESIZE - 1] = 0;
			vpnnodes[crecord->id].id = crecord->id;
			vpnnodes[crecord->id].addr4.sin_family = AF_INET;
			vpnnodes[crecord->id].addr4.sin_port = crecord->port;
			vpnnodes[crecord->id].addr4.sin_addr = crecord->addr4;
			vpnnodes[crecord->id].addr6.sin6_family = AF_INET6;
			vpnnodes[crecord->id].addr6.sin6_port = crecord->port;
			vpnnodes[crecord->id].addr6.sin6_addr = crecord->addr6;
			vpnnodes[crecord->id].addr6preferred = crecord->addr6preferred;
			vpnnodes[crecord->id].delete = 0;
		}
		// If this node's name matches the local node's name, update the local ID
		if(strcasecmp(vpnnodes[crecord->id].name, global_config.name) == 0) {
			if(crecord->id != global_config.id && global_config.id != -1) {
				logmsg(LOGGER_WARNING, "Local node ID automatically changed from %d to %d by BNL", global_config.id, crecord->id);
			}
			global_config.id = crecord->id;
		}
		// Add each subnet to the routing tables
		for(i = 0; i < crecord->numsubnets; i++) {
			if(ntohs(crecord->subnets[i].family) == AF_INET) {
				r = routetable_addroute(&ipv4routetable, &crecord->subnets[i].addr, crecord->subnets[i].cidr, crecord->id);
				if(r != ROUTETABLE_OK) return NODEINFO_ERROR;
			}
			if(ntohs(crecord->subnets[i].family) == AF_INET6) {
				r = routetable_addroute(&ipv6routetable, &crecord->subnets[i].addr, crecord->subnets[i].cidr, crecord->id);
				if(r != ROUTETABLE_OK) return NODEINFO_ERROR;
			}
		}
		// Fix the byte order to the original
		crecord->id = htonl(crecord->id);
		crecord->numsubnets = htonl(crecord->numsubnets);
	}
	// Delete nodes that have their delete flag true
	for(i = 0; i <= maxvpnnodeid; i++) {
		if(vpnnodes[i].delete) {
			nodeinfo_freenode(i);
			memset(&vpnnodes[i], 0, sizeof(struct nodeinfo));
			vpnnodes[i].id = -1;
		}
	}
	return NODEINFO_OK;
}

int bnl_loadallocfiletomem(char *filename, char **data, int *datalen) {
	char rbuf[512];
	int r;
	FILE *f;
	f = fopen(filename, "r");
	if(!f) {
		logmsg(LOGGER_ERR, "Could not open file %s: %s", filename, strerror(errno));
		return NODEINFO_ERROR;
	}
	*data = NULL;
	*datalen = 0;
	while((r = fread(rbuf, 1, 512, f)) > 0) {
		*data = realloc(*data, *datalen + r);
		memcpy(*data + *datalen, rbuf, r);
		*datalen += r;
	}
	if(!feof(f)) {
		fclose(f);
		logmsg(LOGGER_ERR, "Error reading from file.");
		free(*data);
		return NODEINFO_ERROR;
	}
	fclose(f);
	return NODEINFO_OK;
}

int bnl_loadbnlfile(char **retdata, int *retdatalen) {
	char *signedbnldata = NULL;
	char *bdata;
	int bdatalen;
	int sbdlen = 0;
	int r;
	//strcpy(bnl_filename, configfile_dir);
	//strcat(bnl_filename, "/");
	//strcat(bnl_filename, BNL_FILENAME);
	if(!*bnl_filename) strcpy(bnl_filename, BNL_FILENAME);
	r = bnl_loadallocfiletomem(bnl_filename, &signedbnldata, &sbdlen);
	if(r != NODEINFO_OK) return r;
	*retdata = signedbnldata;
	*retdatalen = sbdlen;
	r = sig_verifyandgetdata(signedbnldata, sbdlen, &bdata, &bdatalen);
	if(r != SIG_OK) {
		free(signedbnldata);
		if(r == SIG_INCORRECT) {
			logmsg(LOGGER_WARNING, "Incorrect signature.");
			return NODEINFO_INCORRECT;
		} else {
			logmsg(LOGGER_ERR, "Error verifying signature.");
		}
		return NODEINFO_ERROR;
	}
	return NODEINFO_OK;
}

void bnl_free() {
	free(bnl_current);
	bnl_current = NULL;
	bnl_current_len = 0;
}

int handleNewBNL(char *signbnl, int signbnllen) {
	int r;
	char *cbnldata;
	int cbnldatalen;
	FILE *f;
	r = sig_verifyandgetdata(signbnl, signbnllen, &cbnldata, &cbnldatalen);
	if(r != SIG_OK) {
		logmsg(LOGGER_ERR, "BNL does not verify");
		return NODEINFO_ERROR;
	}
	logmsg(LOGGER_INFO, "Merging in new BNL");
	r = bnl_loadnewbnl(cbnldata, cbnldatalen);
	if(r != NODEINFO_OK) {
		logmsg(LOGGER_ERR, "Error merging BNL");
		return NODEINFO_ERROR;
	}
	// Copy to current bnl in memory
	bnl_free();
	bnl_current = malloc(signbnllen);
	memcpy(bnl_current, signbnl, signbnllen);
	bnl_current_len = signbnllen;
	// Write to disk
	f = fopen(bnl_filename, "wb");
	if(!f) {
		logmsg(LOGGER_ERR, "Error opening BNL file for writing");
		return NODEINFO_ERROR;
	}
	fwrite(signbnl, 1, signbnllen, f);
	fclose(f);
	// Save new nodeinfo file
	r = nodeinfo_save();
	if(r != NODEINFO_OK) {
		logmsg(LOGGER_ERR, "Could not save nodeinfo file");
		return NODEINFO_ERROR;
	}
	return NODEINFO_OK;
}

