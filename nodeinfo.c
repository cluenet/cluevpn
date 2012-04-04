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
#include "connections.h"

struct nodeinfo *vpnnodes;
int maxvpnnodeid;
int nodelist_idcounter;
FILE *nodeinfo_file;

char nodeinfo_filename[CONFIGFILE_FILENAME_LEN];

int nodeinfo_init() {
	char *filename;
	//strcpy(nodeinfo_filename, configfile_dir);
	//strcat(nodeinfo_filename, "/");
	//strcat(nodeinfo_filename, NODEINFO_FILENAME);
	strcpy(nodeinfo_filename, NODEINFO_FILENAME);
	filename = nodeinfo_filename;
	vpnnodes = NULL;
	maxvpnnodeid = -1;
	nodelist_idcounter = -1;
	nodeinfo_file = fopen(filename, "r+");
	if(nodeinfo_file == NULL) {
		if(errno == ENOENT) {
			nodeinfo_file = fopen(filename, "w+");
		}
	}
	if(nodeinfo_file == NULL) {
		logmsg(LOGGER_ERR, "Error opening nodeinfo file: %s", strerror(errno));
		return NODEINFO_ERROR;
	}
	return NODEINFO_OK;
}

void nodeinfo_assocnodeconfigopts() {
	int i, j;
	for(i = 0; i <= maxvpnnodeid; i++) {
		vpnnodes[i].options = NULL;
		if(vpnnodes[i].id >= 0) {
			if(host_config) for(j = 0; host_config[j].node; j++) {
				if(strcasecmp(vpnnodes[i].name, host_config[j].node) == 0) {
					vpnnodes[i].options = &host_config[j];
				}
			}
		}
	}
}

void nodeinfo_freenode(int index) {
	//free(vpnnodes[index].name);
}

int nodeinfo_addnode(struct nodeinfo ni) {
	int oldmax, i;
	if(ni.id < 0) return NODEINFO_OK;
	// Expand the array if necessary
	if(ni.id > maxvpnnodeid) {
		if(ni.id >= NODEINFOSIZELIMIT) {
			logmsg(LOGGER_ERR, "Trying to add node with ID above maximum limit");
			return NODEINFO_ERROR;
		}
		vpnnodes = realloc(vpnnodes, (ni.id + 1) * sizeof(struct nodeinfo));
		oldmax = maxvpnnodeid;
		maxvpnnodeid = ni.id;
		for(i = oldmax + 1; i <= ni.id; i++) {
			memset(&vpnnodes[i], 0, sizeof(struct nodeinfo));
			vpnnodes[i].id = -1;
		}
	}
	// Free the old item if it exists at this spot
	if(vpnnodes[ni.id].id >= 0) nodeinfo_freenode(ni.id);
	// Insert the new item
	vpnnodes[ni.id] = ni;
	return NODEINFO_OK;
}

int nodeinfo_free() {
	int i;
	for(i = 0; i <= maxvpnnodeid; i++) {
		if(vpnnodes[i].id >= 0) nodeinfo_freenode(i);
	}
	free(vpnnodes);
	return NODEINFO_OK;
}

int nodeinfo_close() {
	fclose(nodeinfo_file);
	return nodeinfo_free();
}

void nodeinfo_record2ni(struct nodeinfo_record *nir, struct nodeinfo *ni) {
	memset(ni, 0, sizeof(struct nodeinfo));
	memcpy(ni->name, nir->name, NODEINFO_NAMESIZE);
	ni->name[NODEINFO_NAMESIZE - 1] = 0;
	ni->id = ntohl(nir->id);
	ni->addr4 = nir->addr4;
	ni->addr6 = nir->addr6;
	ni->addr6preferred = nir->addr6preferred;
	ni->negotiated = nir->negotiated;
	ni->cryptalgo = ntohl(nir->cryptalgo);
	ni->cryptkeybits = ntohl(nir->cryptkeybits);
	ni->compalgo = ntohl(nir->compalgo);
	ni->complevel = ntohl(nir->complevel);
	memcpy(ni->cryptkey, nir->cryptkey, CRYPT_MAXKEYBITS / 8);
	seqnum_init_state(&ni->seqnum);
	ni->sendseqnum = 1;
}

void nodeinfo_ni2record(struct nodeinfo *ni, struct nodeinfo_record *nir) {
	memset(nir, 0, sizeof(struct nodeinfo_record));
	memcpy(nir->name, ni->name, NODEINFO_NAMESIZE);
	nir->id = htonl(ni->id);
	nir->addr4 = ni->addr4;
	nir->addr6 = ni->addr6;
	nir->addr6preferred = ni->addr6preferred;
	nir->negotiated = ni->negotiated;
	nir->cryptalgo = htonl(ni->cryptalgo);
	nir->cryptkeybits = htonl(ni->cryptkeybits);
	nir->compalgo = htonl(ni->compalgo);
	nir->complevel = htonl(ni->complevel);
	memcpy(nir->cryptkey, ni->cryptkey, CRYPT_MAXKEYBITS / 8);
}

int nodeinfo_saverecord(int recordnum) {
	int fpos, r;
	struct nodeinfo_record nir;
	logmsg(LOGGER_DEBUG, "Saving nodeinfo node %d", recordnum);
	fpos = recordnum * sizeof(struct nodeinfo_record);
	logmsg(LOGGER_DEBUG, "Seeking to position %d", fpos);
	r = fseek(nodeinfo_file, fpos, SEEK_SET);
	if(r) {
		logmsg(LOGGER_ERR, "Error seeking in nodeinfo file: %s", strerror(errno));
		return NODEINFO_ERROR;
	}
	nodeinfo_ni2record(&vpnnodes[recordnum], &nir);
	logmsg(LOGGER_DEBUG, "Writing");
	r = fwrite(&nir, sizeof(struct nodeinfo_record), 1, nodeinfo_file);
	if(r != 1) {
		logmsg(LOGGER_ERR, "Error writing to nodeinfo file: %s", strerror(errno));
		return NODEINFO_ERROR;
	}
	fflush(nodeinfo_file);
	return NODEINFO_OK;
}

int nodeinfo_save() {
	int r, i, fsize, fd;
	struct nodeinfo_record cnir;
	fsize = (maxvpnnodeid + 1) * sizeof(struct nodeinfo_record);
	rewind(nodeinfo_file);
	fd = fileno(nodeinfo_file);
	if(fd < 0) {
		logmsg(LOGGER_ERR, "Error getting nodeinfo file descriptor");
		return NODEINFO_ERROR;
	}
	r = ftruncate(fd, fsize);
	if(r != 0) {
		logmsg(LOGGER_ERR, "Error truncating nodeinfo file");
		return NODEINFO_ERROR;
	}
	for(i = 0; i <= maxvpnnodeid; i++) {
		nodeinfo_ni2record(&vpnnodes[i], &cnir);
		r = fwrite(&cnir, sizeof(struct nodeinfo_record), 1, nodeinfo_file);
		if(r != 1) {
			logmsg(LOGGER_ERR, "Error writing to nodeinfo file: %s", strerror(errno));
			return NODEINFO_ERROR;
		}
	}
	fflush(nodeinfo_file);
	return NODEINFO_OK;
}

int nodeinfo_load() {
	int r;
	struct nodeinfo_record cnir;
	struct nodeinfo cni;
	rewind(nodeinfo_file);
	for(;;) {
		r = fread(&cnir, sizeof(cnir), 1, nodeinfo_file);
		if(r == 1) {
			nodeinfo_record2ni(&cnir, &cni);
			r = nodeinfo_addnode(cni);
			if(r != NODEINFO_OK) {
				return r;
			}
		} else {
			if(!feof(nodeinfo_file)) {
				return NODEINFO_ERROR;
			}
			break;
		}
	}
	return NODEINFO_OK;
}

int getnodeidbyname(char *name) {
	int i;
	for(i = 0; i <= maxvpnnodeid; i++) {
		if(vpnnodes[i].id >= 0) {
			if(strcasecmp(vpnnodes[i].name, name) == 0) return vpnnodes[i].id;
		}
	}
	return -1;
}

int getnodeaddress(int node, struct sockaddr **saddr, socklen_t *slen) {
	if(!NODEINFO_EXISTS(node)) return NODEINFO_ERROR;
	// If either me or the node doesn't have IPv6 support, have to use IPv4.
	if(global_config.disableipv6 || IN6ADDR_ISBLANK(vpnnodes[node].addr6.sin6_addr)) {
		if(INADDR_ISBLANK(vpnnodes[node].addr4.sin_addr)) return NODEINFO_NOENT;
		*saddr = (struct sockaddr *)&vpnnodes[node].addr4;
		*slen = sizeof(struct sockaddr_in);
		return NODEINFO_OK;
	}
	// Does the node in question only support IPv6?  If so, have to use IPv6.
	if(INADDR_ISBLANK(vpnnodes[node].addr4.sin_addr)) {
		if(IN6ADDR_ISBLANK(vpnnodes[node].addr6.sin6_addr)) return NODEINFO_NOENT;
		*saddr = (struct sockaddr *)&vpnnodes[node].addr6;
		*slen = sizeof(struct sockaddr_in6);
		return NODEINFO_OK;
	}
	// Both the local and remote node support both IPv4 and IPv6 ... only use IPv6 if both nodes are set to prefer it
	if(global_config.preferipv6 && vpnnodes[node].addr6preferred) {
		*saddr = (struct sockaddr *)&vpnnodes[node].addr6;
		*slen = sizeof(struct sockaddr_in6);
		return NODEINFO_OK;
	}
	// Otherwise use IPv4
	*saddr = (struct sockaddr *)&vpnnodes[node].addr4;
	*slen = sizeof(struct sockaddr_in);
	return NODEINFO_OK;
}



/*

// Nodeinfo file format: NODENAME,ID,SUBNET4,CIDR4,SUBNET6,CIDR6,ADDR4,PORT4,ADDR6,PORT6,ADDR6PREFERRED,NEGOTIATED,CRYPTALGO,CRYPTKEYBITS,COMPALGO,COMPLEVEL,HEXCRYPTKEY64B

int nodeinfo_load(char *filename) {
	struct nodeinfo cni;
	int r;
	int cport;
	//char *filename = global_config.nodeinfofile;
	//if(!filename) filename = NODEINFOFILE_DEFAULT;
	dsv_fielddelim = ',';
	dsv_linedelim = '\n';
	if(dsv_openread(filename) != DSV_OK) {
		return NODEINFO_ERROR;
	}
	while((r = dsv_readline()) == DSV_OK) {
		memset(&cni, 0, sizeof(cni));
		if(dsv_readallocstring(&cni.name) != DSV_OK) {
			dsv_closeread();
			logmsg(LOGGER_ERR, "Error reading nodeinfo file.");
			return NODEINFO_ERROR;
		}
		if(dsv_readint(&cni.id) != DSV_OK) {
			dsv_closeread();
			logmsg(LOGGER_ERR, "Error reading nodeinfo file.");
			return NODEINFO_ERROR;
		}
		if(dsv_readaddr4(&cni.subnet4net) != DSV_OK) {
			dsv_closeread();
			logmsg(LOGGER_ERR, "Error reading nodeinfo file.");
			return NODEINFO_ERROR;
		}
		if(dsv_readchar(&cni.subnet4cidr) != DSV_OK) {
			dsv_closeread();
			logmsg(LOGGER_ERR, "Error reading nodeinfo file.");
			return NODEINFO_ERROR;
		}
		if(dsv_readaddr6(&cni.subnet6net) != DSV_OK) {
			dsv_closeread();
			logmsg(LOGGER_ERR, "Error reading nodeinfo file.");
			return NODEINFO_ERROR;
		}
		if(dsv_readchar(&cni.subnet6cidr) != DSV_OK) {
			dsv_closeread();
			logmsg(LOGGER_ERR, "Error reading nodeinfo file.");
			return NODEINFO_ERROR;
		}
		if(dsv_readaddr4(&cni.addr4.sin_addr) != DSV_OK) {
			dsv_closeread();
			logmsg(LOGGER_ERR, "Error reading nodeinfo file.");
			return NODEINFO_ERROR;
		}
		if(dsv_readint(&cport) != DSV_OK) {
			dsv_closeread();
			logmsg(LOGGER_ERR, "Error reading nodeinfo file.");
			return NODEINFO_ERROR;
		}
		cni.addr4.sin_port = cport;
		cni.addr4.sin_family = AF_INET;
		if(dsv_readaddr6(&cni.addr6.sin6_addr) != DSV_OK) {
			dsv_closeread();
			logmsg(LOGGER_ERR, "Error reading nodeinfo file.");
			return NODEINFO_ERROR;
		}
		if(dsv_readint(&cport) != DSV_OK) {
			dsv_closeread();
			logmsg(LOGGER_ERR, "Error reading nodeinfo file.");
			return NODEINFO_ERROR;
		}
		cni.addr6.sin6_port = cport;
		cni.addr6.sin6_family = AF_INET6;
		cni.addr6.sin6_flowinfo = 0;
		cni.addr6.sin6_scope_id = 0;
		if(dsv_readchar(&cni.addr6preferred) != DSV_OK) {
			dsv_closeread();
			logmsg(LOGGER_ERR, "Error reading nodeinfo file.");
			return NODEINFO_ERROR;
		}
		if(dsv_readchar(&cni.negotiated) != DSV_OK) {
			dsv_closeread();
			logmsg(LOGGER_ERR, "Error reading nodeinfo file.");
			return NODEINFO_ERROR;
		}
		if(dsv_readint(&cni.cryptalgo) != DSV_OK) {
			dsv_closeread();
			logmsg(LOGGER_ERR, "Error reading nodeinfo file.");
			return NODEINFO_ERROR;
		}
		if(dsv_readint(&cni.cryptkeybits) != DSV_OK) {
			dsv_closeread();
			logmsg(LOGGER_ERR, "Error reading nodeinfo file.");
			return NODEINFO_ERROR;
		}
		if(dsv_readint(&cni.compalgo) != DSV_OK) {
			dsv_closeread();
			logmsg(LOGGER_ERR, "Error reading nodeinfo file.");
			return NODEINFO_ERROR;
		}
		if(dsv_readint(&cni.complevel) != DSV_OK) {
			dsv_closeread();
			logmsg(LOGGER_ERR, "Error reading nodeinfo file.");
			return NODEINFO_ERROR;
		}
		if(dsv_readdatablock(cni.cryptkey, CRYPT_MAXKEYBITS / 8) != DSV_OK) {
			dsv_closeread();
			logmsg(LOGGER_ERR, "Error reading nodeinfo file.");
			return NODEINFO_ERROR;
		}
		if(dsv_nextfield() != DSV_END) {
			dsv_closeread();
			logmsg(LOGGER_ERR, "Error reading nodeinfo file.");
			return NODEINFO_ERROR;
		}
		if(nodeinfo_addnode(cni) != NODEINFO_OK) {
			dsv_closeread();

			return NODEINFO_ERROR;
		}
	}
	dsv_closeread();
	if(r != DSV_END) {
		logmsg(LOGGER_ERR, "Error reading nodeinfo file.");
		return NODEINFO_ERROR;
	}
	return DSV_OK;
}

int nodeinfo_save(char *filename) {
	int i;
	//char *filename = global_config.nodeinfofile;
	//if(!filename) filename = NODEINFOFILE_DEFAULT;
	dsv_fielddelim = ',';
	dsv_linedelim = '\n';
	if(dsv_openwrite(filename) != DSV_OK) {
		dsv_closewrite();
		logmsg(LOGGER_ERR, "Error writing nodeinfo file.");
		return NODEINFO_ERROR;
	}
	for(i = 0; i <= maxvpnnodeid; i++) {
		if(vpnnodes[i].id >= 0) {
			if(dsv_writestring(vpnnodes[i].name) != DSV_OK) {
				dsv_closewrite();
				logmsg(LOGGER_ERR, "Error writing nodeinfo file.");
				return NODEINFO_ERROR;
			}
			if(dsv_writenum(vpnnodes[i].id) != DSV_OK) {
				dsv_closewrite();
				logmsg(LOGGER_ERR, "Error writing nodeinfo file.");
				return NODEINFO_ERROR;
			}
			if(dsv_writeaddr4(vpnnodes[i].subnet4net) != DSV_OK) {
				dsv_closewrite();
				logmsg(LOGGER_ERR, "Error writing nodeinfo file.");
				return NODEINFO_ERROR;
			}
			if(dsv_writenum(vpnnodes[i].subnet4cidr) != DSV_OK) {
				dsv_closewrite();
				logmsg(LOGGER_ERR, "Error writing nodeinfo file.");
				return NODEINFO_ERROR;
			}
			if(dsv_writeaddr6(vpnnodes[i].subnet6net) != DSV_OK) {
				dsv_closewrite();
				logmsg(LOGGER_ERR, "Error writing nodeinfo file.");
				return NODEINFO_ERROR;
			}
			if(dsv_writenum(vpnnodes[i].subnet6cidr) != DSV_OK) {
				dsv_closewrite();
				logmsg(LOGGER_ERR, "Error writing nodeinfo file.");
				return NODEINFO_ERROR;
			}
			if(dsv_writeaddr4(vpnnodes[i].addr4.sin_addr) != DSV_OK) {
				dsv_closewrite();
				logmsg(LOGGER_ERR, "Error writing nodeinfo file.");
				return NODEINFO_ERROR;
			}
			if(dsv_writenum(vpnnodes[i].addr4.sin_port) != DSV_OK) {
				dsv_closewrite();
				logmsg(LOGGER_ERR, "Error writing nodeinfo file.");
				return NODEINFO_ERROR;
			}
			if(dsv_writeaddr6(vpnnodes[i].addr6.sin6_addr) != DSV_OK) {
				dsv_closewrite();
				logmsg(LOGGER_ERR, "Error writing nodeinfo file.");
				return NODEINFO_ERROR;
			}
			if(dsv_writenum(vpnnodes[i].addr6.sin6_port) != DSV_OK) {
				dsv_closewrite();
				logmsg(LOGGER_ERR, "Error writing nodeinfo file.");
				return NODEINFO_ERROR;
			}
			if(dsv_writenum(vpnnodes[i].addr6preferred) != DSV_OK) {
				dsv_closewrite();
				logmsg(LOGGER_ERR, "Error writing nodeinfo file.");
				return NODEINFO_ERROR;
			}
			if(dsv_writenum(vpnnodes[i].negotiated) != DSV_OK) {
				dsv_closewrite();
				logmsg(LOGGER_ERR, "Error writing nodeinfo file.");
				return NODEINFO_ERROR;
			}
			if(dsv_writenum(vpnnodes[i].cryptalgo) != DSV_OK) {
				dsv_closewrite();
				logmsg(LOGGER_ERR, "Error writing nodeinfo file.");
				return NODEINFO_ERROR;
			}
			if(dsv_writenum(vpnnodes[i].cryptkeybits) != DSV_OK) {
				dsv_closewrite();
				logmsg(LOGGER_ERR, "Error writing nodeinfo file.");
				return NODEINFO_ERROR;
			}
			if(dsv_writenum(vpnnodes[i].compalgo) != DSV_OK) {
				dsv_closewrite();
				logmsg(LOGGER_ERR, "Error writing nodeinfo file.");
				return NODEINFO_ERROR;
			}
			if(dsv_writenum(vpnnodes[i].complevel) != DSV_OK) {
				dsv_closewrite();str
				logmsg(LOGGER_ERR, "Error writing nodeinfo file.");
				return NODEINFO_ERROR;
			}
			if(dsv_writedatablock(vpnnodes[i].cryptkey, CRYPT_MAXKEYBITS / 8) != DSV_OK) {
				dsv_closewrite();
				logmsg(LOGGER_ERR, "Error writing nodeinfo file.");
				return NODEINFO_ERROR;
			}
			if(dsv_writeendline() != DSV_OK) {
				dsv_closewrite();
				logmsg(LOGGER_ERR, "Error writing nodeinfo file.");
				return NODEINFO_ERROR;
			}
		}
	}
	dsv_closewrite();
	return NODEINFO_OK;
}

*/

/*
int nodeinfo_addroutes(routetable_t *rt, char includeipv4, char includeipv6) {
	int r;
	for(i = 0; i <= maxvpnnodeid; i++) {
		if(vpnnodes[i].id >= 0) {
			if(includeipv4) {
				r = routetable_addroute(rt, vpnnodes[i].subnet4net, vpnnodes[i].subnet4cidr, vpnnodes[i].id);
				if(r != ROUTETABLE_OK) return NODEINFO_ERROR;
			}
			if(includeipv6) {
				r = routetable_addroute(rt, vpnnodes[i].subnet6net, vpnnodes[i].subnet6cidr, vpnnodes[i].id);
				if(r != ROUTETABLE_OK) return NODEINFO_ERROR;
			}
		}
	}
	return NODEINFO_OK;
}
*/

/*int main() {
	nodeinfo_init();
	nodeinfo_load("testnodeinfoin.txt");
	nodeinfo_save("testnodeinfoout.txt");
}*/

/*int nodeinfo_resolveaddress(char *address, char *port, int family, struct sockaddr *retaddr, socklen_t *retaddrlen) {
	struct addrinfo hints, *res;
	int r;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	r = getaddrinfo(address, port, &hints, &res);
	if(r != 0) return r;
	memcpy(retaddr, res->ai_addr, (*retaddrlen > res->ai_addrlen) ? res->ai_addrlen : *retaddrlen);
	*retaddrlen = (*retaddrlen > res->ai_addrlen) ? res->ai_addrlen : *retaddrlen;
	freeaddrinfo(res);
	return 0;
}

struct nodeinfo nodeinfo_parseinfoline(char *origline) {
	int i, linelen;
	struct nodeinfo ni;
	char *idstart = line, *namestart = NULL, *addr4start = NULL, *addr6start = NULL, *portstart = NULL;
	int idlen = 0, namelen = 0, addr4len = 0, addr6len = 0, portlen = 0;
	char *line = strdup(origline);
	memset(&ni, 0, sizeof(ni));
	ni.id = -1;
	// Line format is:  ID,NAME,V4ADDR,V6ADDR,PORT
	linelen = strlen(line);
	for(i = 0; i <= linelen; i++) {
		if(line[i] == 0 || line[i] == ',') {
			if(namestart == NULL) {
				idlen = i;
				namestart = line + i + 1;
			} else if(addr4start == NULL) {
				namelen = i - idlen - 1;
				addr4start = line + i + 1;
			} else if(addr6start == NULL) {
				addr4len = i - namelen - idlen - 2;
				addr6start = line + i + 1;
			} else if(portstart == NULL) {
				addr6len = i - addr4len - namelen - idlen - 3;
				portstart = line + i + 1;
			} else {
				portlen = i - addr6len - addr4len - namelen - idlen - 4;
				break;
			}
		}
	}
	if(!idstart || !namestart || !addr4start || !addr6start || !portstart) {
		logmsg(LOGGER_ERR, "Invalid node info line");
		free(line);
		return ni;
	}
	idstart[idlen] = 0;
	namestart[namelen] = 0;
	addr4start[addr4len] = 0;
	addr6start[addr6len] = 0;
	ni.id = atoi(idstart);
	ni.name = strdup(namestart);
	
}*/
