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
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <openssl/err.h>
#include "configfile.h"
#include "signature.h"
#include "bnl.h"
#include "dsv.h"

int main() {
	int linenum;
	int r, i;
	char *str;
	int cfam, ccidr;
	struct bnl_header hdr;
	struct bnl_record_hdr rhdr;
	struct bnl_record_subnet rsubnet;
	char *bnlbuf = NULL;
	int bnlbuflen = 0;
	char *ffbuf;
	int ffbufsize;
	FILE *outfile = stdout;
	if(configfile_load() != CONFIGFILE_OK) { fprintf(stderr, "Error loading config file.\n"); return 1; }
	SSL_load_error_strings();
	if(sig_init() != SIG_OK) { fprintf(stderr, "Error initializing signatures.\n"); return 1; }
	r = dsv_openread("/dev/stdin");
	if(r != DSV_OK) { fprintf(stderr, "Error opening file.\n"); return 1; }
	hdr.timestamp = htonl(time(NULL));
	//fwrite(&hdr, sizeof(hdr), 1, outfile);
	bnlbuf = realloc(bnlbuf, bnlbuflen + sizeof(hdr));
	memcpy(bnlbuf + bnlbuflen, &hdr, sizeof(hdr));
	bnlbuflen += sizeof(hdr);
	linenum = 0;
	while((r = dsv_readline()) == DSV_OK) {
		linenum++;
		fprintf(stderr, "Parsing line %d\n", linenum);
		memset(&rhdr, 0, sizeof(rhdr));
		if(dsv_readallocstring(&str) != DSV_OK) { fprintf(stderr, "Invalid input format.\n"); return 1; }
		strncpy(rhdr.name, str, NODEINFO_NAMESIZE - 1);
		if(dsv_readint(&rhdr.id) != DSV_OK) { fprintf(stderr, "Invalid input format.\n"); return 1; }
		if(dsv_readaddr4(&rhdr.addr4) != DSV_OK) { fprintf(stderr, "Invalid input format.\n"); return 1; }
		if(dsv_readaddr6(&rhdr.addr6) != DSV_OK) { fprintf(stderr, "Invalid input format.\n"); return 1; }
		if(dsv_readushort(&rhdr.port) != DSV_OK) { fprintf(stderr, "Invalid input format.\n"); return 1; }
		if(dsv_readchar(&rhdr.addr6preferred) != DSV_OK) { fprintf(stderr, "Invalid input format.\n"); return 1; }
		if(dsv_readint(&rhdr.numsubnets) != DSV_OK) { fprintf(stderr, "Invalid input format.\n"); return 1; }
		rhdr.id = htonl(rhdr.id);
		rhdr.port = htons(rhdr.port);
		rhdr.numsubnets = htonl(rhdr.numsubnets);
		//fwrite(&rhdr, sizeof(rhdr), 1, outfile);
		bnlbuf = realloc(bnlbuf, bnlbuflen + sizeof(rhdr));
		memcpy(bnlbuf + bnlbuflen, &rhdr, sizeof(rhdr));
		bnlbuflen += sizeof(rhdr);
		for(i = 0; i < ntohl(rhdr.numsubnets); i++) {
			fprintf(stderr, "  Subnet %d ...\n", i + 1);
			memset(&rsubnet, 0, sizeof(rsubnet));
			dsv_fielddelim = ':';
			if(dsv_readint(&cfam) != DSV_OK) { fprintf(stderr, "Invalid input format.\n"); return 1; }
			if(cfam != 4 && cfam != 6) { fprintf(stderr, "Invalid subnet family.  Must be 4 or 6.\n"); return 1; }
			dsv_fielddelim = '/';
			if(cfam == 4) {
				rsubnet.family = htons(AF_INET);
				if(dsv_readaddr4(&rsubnet.addr.addr4) != DSV_OK) { fprintf(stderr, "Invalid input format.\n"); return 1; }
			}
			if(cfam == 6) {
				rsubnet.family = htons(AF_INET6);
				if(dsv_readaddr6(&rsubnet.addr.addr6) != DSV_OK) { fprintf(stderr, "Invalid input format.\n"); return 1; }
			}
			dsv_fielddelim = ',';
			if(dsv_readint(&ccidr) != DSV_OK) { fprintf(stderr, "Invalid input format.\n"); return 1; }
			rsubnet.cidr = ccidr;
			//fwrite(&rsubnet, sizeof(rsubnet), 1, outfile);
			bnlbuf = realloc(bnlbuf, bnlbuflen + sizeof(rsubnet));
			memcpy(bnlbuf + bnlbuflen, &rsubnet, sizeof(rsubnet));
			bnlbuflen += sizeof(rsubnet);
		}
		if(dsv_readint(&ccidr) != DSV_END) { fprintf(stderr, "Warning: More subnets than given count.\n"); }
	}
	ffbufsize = SIG_SIGMAXFILESIZE(bnlbuflen);
	ffbuf = malloc(ffbufsize);
	r = sig_signandmakefile(bnlbuf, bnlbuflen, ffbuf, &ffbufsize);
	if(r != SIG_OK) { fprintf(stderr, "Error signing file.\n"); return 1; }
	fwrite(ffbuf, 1, ffbufsize, outfile);
	free(ffbuf);
	free(bnlbuf);
	sig_close();
	fprintf(stderr, "Done.\n");
	return 0;
}

