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


#ifndef _NODEINFO_H
#define _NODEINFO_H

#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "crypt.h"
#include "seqnum.h"
#include "configfile.h"

#define NODEINFOFILE_DEFAULT "/etc/cluevpn/nodeinfo"
#define NODEINFOSIZELIMIT 5000
#define NODEINFO_NAMESIZE 256

#define NODEINFO_OK 0
#define NODEINFO_ERROR 1
#define NODEINFO_NOENT 2
#define NODEINFO_INCORRECT 3

#define NODEINFO_WORKING 2
#define NODEINFO_BROKEN 1
#define NODEINFO_UNVERIFIED 0

#define NODEINFO_FILENAME "nodeinfo.cni"

extern char nodeinfo_filename[CONFIGFILE_FILENAME_LEN];

// Struct for storing nodeinfo in memory
struct nodeinfo {
	char name[NODEINFO_NAMESIZE];	// Index (Saved, from BNL)
	int id;						// Index (Saved, from BNL)
	struct sockaddr_in addr4;	// Saved, default from BNL
	struct sockaddr_in6 addr6;	// Saved, default from BNL
	char addr6preferred;		// Saved
	char negotiated;			// Saved
	int cryptalgo;				// Saved
	int cryptkeybits;			// Saved
	int compalgo;				// Saved
	int complevel;				// Saved
	char cryptkey[CRYPT_MAXKEYBITS / 8];	// Saved
	seqnum_state_t seqnum;		// Receiving seqnum state - Not saved
	unsigned int sendseqnum;	// Sending seqnum state - Not saved
	struct configfile_hostopts *options;	// Pointer to configfile options struct if it exists for this node - not saved
	char delete;				// Flag to delete the record - only temporary
};

// Struct for writing nodeinfo to disk - remember to convert fields to network byte order
struct nodeinfo_record {
	char name[NODEINFO_NAMESIZE];	// Index (Saved, from BNL)
	int id;						// Index (Saved, from BNL)
	struct sockaddr_in addr4;	// Saved, default from BNL
	struct sockaddr_in6 addr6;	// Saved, default from BNL
	char addr6preferred;		// Saved, default from BNL
	char negotiated;			// Saved
	int cryptalgo;				// Saved
	int cryptkeybits;			// Saved
	int compalgo;				// Saved
	int complevel;				// Saved
	char cryptkey[CRYPT_MAXKEYBITS / 8];	// Saved
} __attribute__ ((__packed__));

extern struct nodeinfo *vpnnodes;
extern int maxvpnnodeid;
extern int nodelist_idcounter;

#define NODEINFO_EXISTS(nid) ((nid >= 0 && nid <= maxvpnnodeid) ? ((vpnnodes[nid].id >= 0) ? 1 : 0 ) : 0)
#define NODEINFO_INFO(nid) (vpnnodes[nid])

int nodeinfo_init();
int nodeinfo_free();
int nodeinfo_load();
int nodeinfo_save();
int nodeinfo_addnode(struct nodeinfo ni);
int getnodeidbyname(char *name);
void nodeinfo_assocnodeconfigopts();
int getnodeaddress(int node, struct sockaddr **saddr, socklen_t *slen);
int nodeinfo_saverecord(int recordnum);

#endif
