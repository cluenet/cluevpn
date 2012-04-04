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
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/err.h>
#include <errno.h>
#include "configfile.h"
#include "signature.h"
#include "bnl.h"
#include "connections.h"

void printUsage(char *cmd);

char *cur_bnlsigdata = NULL;
int cur_bnlsigdata_len;

char *cur_bnldata;
int cur_bnldata_len;

struct bnl_header *cur_bnlhdr;
struct bnl_record_hdr **cur_bnlrecords = NULL;
int numcurbnlrecords;

time_t newtimestamp;
char *argv0;

void parseBNLData() {
	struct bnl_record_hdr *cbnlr;
	free(cur_bnlrecords);
	cur_bnlhdr = (struct bnl_header *)cur_bnldata;
	cur_bnlrecords = malloc(sizeof(struct bnl_record_hdr *));
	*cur_bnlrecords = NULL;
	numcurbnlrecords = 0;
	for(cbnlr = (struct bnl_record_hdr *)(cur_bnldata + sizeof(struct bnl_header)); (char *)cbnlr < cur_bnldata + cur_bnldata_len;) {
		cur_bnlrecords = realloc(cur_bnlrecords, (numcurbnlrecords + 2) * sizeof(struct bnl_record_hdr *));
		cur_bnlrecords[numcurbnlrecords] = cbnlr;
		numcurbnlrecords++;
		cur_bnlrecords[numcurbnlrecords] = NULL;
		cbnlr = (struct bnl_record_hdr *)((char *)cbnlr + sizeof(struct bnl_record_hdr) + ntohl(cbnlr->numsubnets) * sizeof(struct bnl_record_subnet));
	}
}

int loadBNL() {
	int r;
	free(cur_bnlsigdata);
	// Load it into memory
	if(!*bnl_filename) strcpy(bnl_filename, BNL_FILENAME);
	r = bnl_loadallocfiletomem(bnl_filename, &cur_bnlsigdata, &cur_bnlsigdata_len);
	if(r != NODEINFO_OK) {
		fprintf(stderr, "Error loading BNL");
		return 1;
	}
	cur_bnldata = SIG_DATA(cur_bnlsigdata);
	cur_bnldata_len = SIG_DATALEN(cur_bnlsigdata);
	// Check if the signature verifies
	r = sig_verifyandgetdata(cur_bnlsigdata, cur_bnlsigdata_len, NULL, NULL);
	if(r != NODEINFO_OK) {
		fprintf(stderr, "Warning: Signature on BNL does not verify");
	}
	// Parse the BNL data
	parseBNLData();
	return 0;
}

int doPrintBNL() {
	time_t ts;
	int tsint;
	char *tsstr;
	int i, j;
	char addrstr[256];
	struct bnl_record_subnet csub;
	if(loadBNL() != 0) return 1;
	ts = ntohl(cur_bnlhdr->timestamp);
	tsint = ts;
	tsstr = ctime(&ts);
	if(tsstr[strlen(tsstr) - 1] == '\n') tsstr[strlen(tsstr) - 1] = 0;
	printf("Timestamp: %d (%s)\n", tsint, tsstr);
	for(i = 0; i < numcurbnlrecords; i++) {
		printf("%s (ID %d):", cur_bnlrecords[i]->name, ntohl(cur_bnlrecords[i]->id));
		if(!INADDR_ISBLANK(cur_bnlrecords[i]->addr4)) {
			inet_ntop(AF_INET, &cur_bnlrecords[i]->addr4, addrstr, 256);
			printf(" IPv4=%s", addrstr);
			if(!IN6ADDR_ISBLANK(cur_bnlrecords[i]->addr6) && !cur_bnlrecords[i]->addr6preferred) printf("(preferred)");
		}
		if(!IN6ADDR_ISBLANK(cur_bnlrecords[i]->addr6)) {
			inet_ntop(AF_INET6, &cur_bnlrecords[i]->addr6, addrstr, 256);
			printf(" IPv6=%s", addrstr);
			if(!INADDR_ISBLANK(cur_bnlrecords[i]->addr4) && cur_bnlrecords[i]->addr6preferred) printf("(preferred)");
		}
		printf(" Port=%d", ntohs(cur_bnlrecords[i]->port));
		printf(" Subnets:");
		for(j = 0; j < ntohl(cur_bnlrecords[i]->numsubnets); j++) {
			csub = cur_bnlrecords[i]->subnets[j];
			inet_ntop(ntohs(csub.family), &csub.addr, addrstr, 256);
			printf(" %s/%d", addrstr, csub.cidr);
		}
		printf("\n");
	}
	return 0;
}

int doModify(int argc, char **argv, time_t newtimestamp) {
	char *name;
	int i, j, r;
	char *key, *val;
	FILE *f;
	struct bnl_record_hdr *crecord;
	if(argc < 1) {
		printUsage(argv0);
		return 1;
	}
	if(loadBNL() != 0) return 1;
	name = argv[0];
	for(i = 0; i < numcurbnlrecords; i++) {
		if(strcasecmp(cur_bnlrecords[i]->name, name) == 0) break;
	}
	if(i == numcurbnlrecords) {
		fprintf(stderr, "No such name.\n");
		return 1;
	}
	crecord = cur_bnlrecords[i];
	for(i = 1; i < argc; i++) {
		if(strcasecmp(argv[i], "PreferIPv6") == 0) {
			crecord->addr6preferred = 1;
			continue;
		}
		if(strcasecmp(argv[i], "PreferIPv4") == 0 || strcasecmp(argv[i], "NoPreferIPv6") == 0) {
			crecord->addr6preferred = 0;
			continue;
		}
		key = argv[i];
		val = strstr(argv[i], "=");
		if(!val) {
			printUsage(argv[0]);
			return 1;
		}
		*val = 0;
		val++;
		if(strcasecmp(key, "IPv4") == 0 || strcasecmp(key, "IP") == 0) {
			if(strlen(val) == 0) {
				crecord->addr4 = inaddr_none;
			} else {
				r = inet_pton(AF_INET, val, &crecord->addr4);
				if(r != 1) {
					fprintf(stderr, "Invalid IPv4 address\n");
					return 1;
				}
			}
			continue;
		}
		if(strcasecmp(key, "IPv6") == 0) {
			if(strlen(val) == 0) {
				crecord->addr6 = in6addr_none;
			} else {
				r = inet_pton(AF_INET6, val, &crecord->addr6);
				if(r != 1) {
					fprintf(stderr, "Invalid IPv6 address\n");
					return 1;
				}
			}
			continue;
		}
		if(strcasecmp(key, "Port") == 0) {
			if(strlen(val) == 0) {
				crecord->port = htons(3406);
			} else {
				crecord->port = htons(atoi(val));
			}
			continue;
		}
		fprintf(stderr, "Invalid attribute\n");
		return 1;
	}
	cur_bnlhdr->timestamp = htonl(newtimestamp);
	r = sig_signandmakefile(cur_bnldata, cur_bnldata_len, cur_bnlsigdata, &cur_bnlsigdata_len);
	if(r != SIG_OK) {
		fprintf(stderr, "Error signing file\n");
		return 1;
	}
	f = fopen(bnl_filename, "w");
	if(!f) {
		fprintf(stderr, "Error opening file\n");
		return 1;
	}
	fwrite(cur_bnlsigdata, 1, cur_bnlsigdata_len, f);
	fclose(f);
	printf("Node %s modified.\n", name);
	return 0;
}

int doAdd(int argc, char **argv, time_t newtimestamp) {
	struct bnl_record_hdr nrecord;
	int maxid = -1;
	int i, j, r;
	char *key, *val;
	struct bnl_record_subnet *subnets = NULL;
	int numsubnets = 0;
	struct bnl_record_subnet csub;
	char is6;
	char *newdata;
	int newdatalen;
	char *filebuf;
	unsigned int filelen;
	FILE *f;
	if(argc < 1) {
		printUsage(argv0);
		return 1;
	}
	if(loadBNL() != 0) return 1;
	memset(&nrecord, 0, sizeof(nrecord));
	nrecord.port = htons(3406);
	strcpy(nrecord.name, argv[0]);
	for(i = 0; i < numcurbnlrecords; i++) {
		if((signed int)ntohl(cur_bnlrecords[i]->id) > maxid) {
			maxid = ntohl(cur_bnlrecords[i]->id);
		}
	}
	nrecord.id = htonl(maxid + 1);
	for(i = 1; i < argc; i++) {
		if(strcasecmp(argv[i], "PreferIPv6") == 0) {
			nrecord.addr6preferred = 1;
			continue;
		}
		key = argv[i];
		val = strstr(argv[i], "=");
		if(!val) {
			printUsage(argv[0]);
			return 1;
		}
		*val = 0;
		val++;
		if(strcasecmp(key, "ID") == 0) {
			nrecord.id = htonl(atoi(val));
			continue;
		}
		if(strcasecmp(key, "IPv4") == 0 || strcasecmp(key, "IP") == 0) {
			r = inet_pton(AF_INET, val, &nrecord.addr4);
			if(r != 1) {
				fprintf(stderr, "Invalid IPv4 address\n");
				return 1;
			}
			continue;
		}
		if(strcasecmp(key, "IPv6") == 0) {
			r = inet_pton(AF_INET6, val, &nrecord.addr6);
			if(r != 1) {
				fprintf(stderr, "Invalid IPv6 address\n");
				return 1;
			}
			continue;
		}
		if(strcasecmp(key, "Port") == 0) {
			nrecord.port = htons(atoi(val));
			continue;
		}
		if(strcasecmp(key, "Subnet") == 0) {
			memset(&csub, 0, sizeof(csub));
			is6 = 0;
			for(j = 0; j < strlen(val); j++) if(val[j] == ':') is6 = 1;
			for(j = 0; j < strlen(val); j++) if(val[j] == '/') {
				csub.cidr = atoi(val + j + 1);
				val[j] = 0;
			}
			csub.family = htons(is6 ? AF_INET6 : AF_INET);
			r = inet_pton(is6 ? AF_INET6 : AF_INET, val, &csub.addr);
			if(r != 1) {
				fprintf(stderr, "Invalid address\n");
				return 1;
			}
			subnets = realloc(subnets, (numsubnets + 1) * sizeof(struct bnl_record_subnet));
			subnets[numsubnets] = csub;
			numsubnets++;
			continue;
		}
		fprintf(stderr, "Invalid attribute\n");
		return 1;
	}
	for(i = 0; i < numcurbnlrecords; i++) {
		if(cur_bnlrecords[i]->id == nrecord.id) {
			fprintf(stderr, "That ID already exists.\n");
			return 1;
		}
		if(strcasecmp(cur_bnlrecords[i]->name, nrecord.name) == 0) {
			fprintf(stderr, "That name already exists.\n");
			return 1;
		}
	}
	nrecord.numsubnets = htonl(numsubnets);
	newdatalen = cur_bnldata_len + sizeof(struct bnl_record_hdr) + sizeof(struct bnl_record_subnet) * numsubnets;
	newdata = malloc(newdatalen);
	memcpy(newdata, cur_bnldata, cur_bnldata_len);
	(*(struct bnl_header *)newdata).timestamp = htonl(newtimestamp);
	memcpy(newdata + cur_bnldata_len, &nrecord, sizeof(nrecord));
	memcpy(newdata + cur_bnldata_len + sizeof(nrecord), subnets, numsubnets * sizeof(struct bnl_record_subnet));
	filebuf = malloc(newdatalen + 1024);
	filelen = newdatalen + 1024;
	r = sig_signandmakefile(newdata, newdatalen, filebuf, &filelen);
	if(r != SIG_OK) {
		fprintf(stderr, "Error signing file\n");
		return 1;
	}
	f = fopen(bnl_filename, "w");
	if(!f) {
		fprintf(stderr, "Error opening file\n");
		return 1;
	}
	fwrite(filebuf, 1, filelen, f);
	fclose(f);
	printf("Node %s added with ID %d.\n", nrecord.name, ntohl(nrecord.id));
	return 0;
}

int doAddSubnet(char *name, char *subnet, time_t newts) {
	struct bnl_record_hdr *crecord;
	int i, j;
	char *newdata;
	int newdatalen;
	int r;
	FILE *f;
	char *filebuf;
	int filelen;
	char is6;
	struct bnl_record_subnet newsubnet;
	if(loadBNL() != 0) return 1;
	for(i = 0; i < numcurbnlrecords; i++) {
		if(strcasecmp(cur_bnlrecords[i]->name, name) == 0) break;
	}
	if(i == numcurbnlrecords) {
		fprintf(stderr, "No such name.\n");
		return 1;
	}
	memset(&newsubnet, 0, sizeof(newsubnet));
	is6 = 0;
	for(j = 0; j < strlen(subnet); j++) if(subnet[j] == ':') is6 = 1;
	for(j = 0; j < strlen(subnet); j++) if(subnet[j] == '/') {
		newsubnet.cidr = atoi(subnet + j + 1);
		subnet[j] = 0;
	}
	newsubnet.family = htons(is6 ? AF_INET6 : AF_INET);
	r = inet_pton(is6 ? AF_INET6 : AF_INET, subnet, &newsubnet.addr);
	if(r != 1) {
		fprintf(stderr, "Invalid address\n");
		return 1;
	}
	crecord = cur_bnlrecords[i];
	crecord->numsubnets = htonl(ntohl(crecord->numsubnets) + 1);
	newdatalen = cur_bnldata_len + sizeof(struct bnl_record_subnet);
	newdata = malloc(newdatalen);
	memcpy(newdata, cur_bnldata, (char *)crecord - (char *)cur_bnldata + sizeof(struct bnl_record_hdr) + (ntohl(crecord->numsubnets) - 1) * sizeof(struct bnl_record_subnet));
	*(struct bnl_record_subnet *)(newdata + ((char *)crecord - (char *)cur_bnldata) + sizeof(struct bnl_record_hdr) + (ntohl(crecord->numsubnets) - 1) * sizeof(struct bnl_record_subnet)) = newsubnet;
	memcpy(newdata + ((char *)crecord - (char *)cur_bnldata) + sizeof(struct bnl_record_hdr) + (ntohl(crecord->numsubnets)) * sizeof(struct bnl_record_subnet), (char *)crecord + sizeof(struct bnl_record_hdr) + (ntohl(crecord->numsubnets) - 1) * sizeof(struct bnl_record_subnet), cur_bnldata_len - ((char *)crecord - (char *)cur_bnldata) - sizeof(struct bnl_record_hdr) - (ntohl(crecord->numsubnets) - 1) * sizeof(struct bnl_record_subnet));
	((struct bnl_header *)newdata)->timestamp = htonl(newts);
	fprintf(stderr, "Subnet added.\n");
	filebuf = malloc(newdatalen + 1024);
	filelen = newdatalen + 1024;
	r = sig_signandmakefile(newdata, newdatalen, filebuf, &filelen);
	if(r != SIG_OK) {
		fprintf(stderr, "Error signing file\n");
		return 1;
	}
	f = fopen(bnl_filename, "w");
	if(!f) {
		fprintf(stderr, "Error opening file\n");
		return 1;
	}
	fwrite(filebuf, 1, filelen, f);
	fclose(f);
	return 0;
}

int doDelSubnet(char *name, char *subnet, time_t newts) {
	struct bnl_record_hdr *crecord;
	int i, j;
	char *newdata;
	int newdatalen;
	int r;
	FILE *f;
	char *filebuf;
	int filelen;
	char is6;
	struct bnl_record_subnet rsub, *csub;
	if(loadBNL() != 0) return 1;
	for(i = 0; i < numcurbnlrecords; i++) {
		if(strcasecmp(cur_bnlrecords[i]->name, name) == 0) break;
	}
	if(i == numcurbnlrecords) {
		fprintf(stderr, "No such name.\n");
		return 1;
	}
	crecord = cur_bnlrecords[i];
	memset(&rsub, 0, sizeof(rsub));
	is6 = 0;
	for(j = 0; j < strlen(subnet); j++) if(subnet[j] == ':') is6 = 1;
	for(j = 0; j < strlen(subnet); j++) if(subnet[j] == '/') {
		rsub.cidr = atoi(subnet + j + 1);
		subnet[j] = 0;
	}
	rsub.family = htons(is6 ? AF_INET6 : AF_INET);
	r = inet_pton(is6 ? AF_INET6 : AF_INET, subnet, &rsub.addr);
	if(r != 1) {
		fprintf(stderr, "Invalid address\n");
		return 1;
	}
	for(i = 0; i < ntohl(crecord->numsubnets); i++) {
		if(crecord->subnets[i].family != rsub.family) continue;
		if(crecord->subnets[i].cidr != rsub.cidr) continue;
		if(memcmp(&crecord->subnets[i].addr, &rsub.addr, sizeof(struct in6_addr)) != 0) continue;
		break;
	}
	if(i == ntohl(crecord->numsubnets)) {
		fprintf(stderr, "No such subnet.\n");
		return 1;
	}
	csub = &crecord->subnets[i];
	crecord->numsubnets = htonl(ntohl(crecord->numsubnets) - 1);
	memmove((char *)csub, (char *)csub + sizeof(struct bnl_record_subnet), (char *)cur_bnldata + cur_bnldata_len - (char *)csub - sizeof(struct bnl_record_subnet));
	cur_bnldata_len -= sizeof(struct bnl_record_subnet);
	((struct bnl_header *)cur_bnldata)->timestamp = htonl(newts);
	fprintf(stderr, "Subnet deleted.\n");
	filebuf = malloc(cur_bnldata_len + 1024);
	filelen = cur_bnldata_len + 1024;
	r = sig_signandmakefile(cur_bnldata, cur_bnldata_len, filebuf, &filelen);
	if(r != SIG_OK) {
		fprintf(stderr, "Error signing file\n");
		return 1;
	}
	f = fopen(bnl_filename, "w");
	if(!f) {
		fprintf(stderr, "Error opening file\n");
		return 1;
	}
	fwrite(filebuf, 1, filelen, f);
	fclose(f);
	return 0;
}

int doNew(time_t newts) {
	char *filebuf;
	int filelen, r;
	FILE *f;
	struct bnl_header hdr;
	if(!*bnl_filename) strcpy(bnl_filename, BNL_FILENAME);
	filebuf = malloc(1024);
	filelen = 1024;
	memset(&hdr, 0, sizeof(hdr));
	hdr.timestamp = htonl(newts);
	r = sig_signandmakefile((char *)&hdr, sizeof(hdr), filebuf, &filelen);
	if(r != SIG_OK) {
		fprintf(stderr, "Error signing file\n");
		return 1;
	}
	f = fopen(bnl_filename, "w");
	if(!f) {
		fprintf(stderr, "Error opening file %s: %s\n", bnl_filename, strerror(errno));
		return 1;
	}
	fwrite(filebuf, 1, filelen, f);
	fclose(f);
	printf("New blank BNL created.\n");
	return 0;
}

int doRemove(char *name, time_t newts) {
	int i, remidx, remsize, r;
	FILE *f;
	if(loadBNL() != 0) return 1;
	for(i = 0; i < numcurbnlrecords; i++) {
		if(strcasecmp(cur_bnlrecords[i]->name, name) == 0) break;
	}
	if(i == numcurbnlrecords) {
		fprintf(stderr, "No such name in BNL.\n");
		return 1;
	}
	remidx = i;
	remsize = sizeof(struct bnl_record_hdr) + ntohl(cur_bnlrecords[remidx]->numsubnets) * sizeof(struct bnl_record_subnet);
	memmove(cur_bnlrecords[remidx], (char *)cur_bnlrecords[remidx] + remsize, cur_bnldata_len - ((char *)cur_bnlrecords[remidx] - cur_bnldata) - remsize);
	cur_bnldata_len -= remsize;
	cur_bnlhdr->timestamp = htonl(newts);
	r = sig_signandmakefile(cur_bnldata, cur_bnldata_len, cur_bnlsigdata, &cur_bnlsigdata_len);
	if(r != SIG_OK) {
		fprintf(stderr, "Error signing file\n");
		return 1;
	}
	f = fopen(bnl_filename, "w");
	if(!f) {
		fprintf(stderr, "Error opening file\n");
		return 1;
	}
	fwrite(cur_bnlsigdata, 1, cur_bnlsigdata_len, f);
	fclose(f);
	printf("Node %s removed.\n", name);
	return 0;
}

void printUsage(char *cmd) {
	fprintf(stderr, "Usage: %s [-c <ConfigDir>] [-t <TimeStamp>] [-b <BNLFile>] <Command> ...\n", cmd);
	fprintf(stderr, "       Commands:\n");
	fprintf(stderr, "         print\n");
	fprintf(stderr, "         new\n");
	fprintf(stderr, "         add <Name> [ID=<ID>] [IPv4=<IPv4Address>] [IPv6=<IPv6Address>] [Port=<Port>] [PreferIPv6] [Subnet=<Subnet1>] [Subnet=<Subnet2>] ...\n");
	fprintf(stderr, "         modify <Name> [IPv4=[IPv4Address]] [IPv6=[IPv6Address]] [Port=[Port]] [PreferIPv4] [PreferIPv6]\n");
	fprintf(stderr, "         addsubnet <Name> <Subnet>\n");
	fprintf(stderr, "         delsubnet <Name> <Subnet>\n");
	fprintf(stderr, "         remove <Name>\n");
	fprintf(stderr, "       Subnet: <Network>/<CIDR>\n");
}

int main(int argc, char **argv) {
	char *optstring = "c:t:b:";
	int copt;
	char bnlspecified = 0;
	int r;
	char *rptr;
	newtimestamp = time(NULL);
	argv0 = argv[0];
	if(argc < 2) {
		printUsage(argv[0]);
		return 1;
	}
	for(;;) {
		copt = getopt(argc, argv, optstring);
		if(copt == -1) break;
		if(copt == '?') {
			fprintf(stderr, "Invalid option.");
			return 1;
		}
		switch(copt) {
			case 'c':
				strcpy(configfile_dir, optarg);
				break;
			case 't':
				newtimestamp = atoi(optarg);
				break;
			case 'b':
				strcpy(bnl_filename, optarg);
				bnlspecified = 1;
				break;
		}
	}
	// Get orig directory
	rptr = getcwd(configfile_origdir, CONFIGFILE_FILENAME_LEN);
	// cd to the new directory
	r = chdir(configfile_dir);
	if(r != 0) {
		fprintf(stderr, "Error changing to configfile dir");
		return 1;
	}
	// Load config file
	if(configfile_load() != CONFIGFILE_OK) { fprintf(stderr, "Error loading config file.\n"); return 1; }
	// Load SSL error strings
	SSL_load_error_strings();
	// Initialize signatures
	if(sig_init() != SIG_OK) { fprintf(stderr, "Error initializing signatures.\n"); return 1; }
	// Command
	if(argc - optind < 1) {
		printUsage(argv[0]);
		return 1;
	}
	if(bnlspecified) r = chdir(configfile_origdir);
	if(strcmp(argv[optind], "print") == 0) {
		if(argc - optind != 1) {
			printUsage(argv[0]);
			return 1;
		}
		return doPrintBNL();
	}
	if(strcmp(argv[optind], "new") == 0) {
		if(argc - optind != 1) {
			printUsage(argv[0]);
			return 1;
		}
		return doNew(newtimestamp);
	}
	if(strcmp(argv[optind], "add") == 0) {
		return doAdd(argc - optind - 1, &argv[optind + 1], newtimestamp);
	}
	if(strcmp(argv[optind], "modify") == 0) {
		return doModify(argc - optind - 1, &argv[optind + 1], newtimestamp);
	}
	if(strcmp(argv[optind], "remove") == 0) {
		if(argc - optind != 2) {
			printUsage(argv[0]);
			return 1;
		}
		return doRemove(argv[optind + 1], newtimestamp);
	}
	if(strcmp(argv[optind], "addsubnet") == 0) {
		if(argc - optind != 3) {
			printUsage(argv[0]);
			return 1;
		}
		return doAddSubnet(argv[optind + 1], argv[optind + 2], newtimestamp);
	}
	if(strcmp(argv[optind], "delsubnet") == 0) {
		if(argc - optind != 3) {
			printUsage(argv[0]);
			return 1;
		}
		return doDelSubnet(argv[optind + 1], argv[optind + 2], newtimestamp);
	}
	printUsage(argv[0]);
	return 1;
}

