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
#include <arpa/inet.h>
#include "dsv.h"

FILE *dsv_wfile = NULL;
FILE *dsv_rfile = NULL;
char dsv_fielddelim = ',';
char dsv_linedelim = '\n';

char dsv_cline[DSV_LINEBUFSIZE];
char dsv_cfield[DSV_FIELDBUFSIZE];
char *dsv_membuf;
int dsv_mempos;
int dsv_linepos;
int dsv_ffil;	// first field in line

int dsv_openread(char *filename) {
	dsv_rfile = fopen(filename, "r");
	if(!dsv_rfile) return DSV_ERR;
	return DSV_OK;
}

int dsv_openreadmem(char *buf) {
	dsv_membuf = buf;
	dsv_mempos = 0;
	dsv_rfile = NULL;
	return DSV_OK;
}

int dsv_openwrite(char *filename) {
	dsv_wfile = fopen(filename, "w");
	if(!dsv_wfile) return DSV_ERR;
	dsv_ffil = 1;
	return DSV_OK;
}

void dsv_closeread() {
	fclose(dsv_rfile);
	dsv_rfile = NULL;
}

void dsv_closewrite() {
	fclose(dsv_wfile);
	dsv_wfile = NULL;
}

int dsv_writeendline() {
	fprintf(dsv_wfile, "\n");
	dsv_ffil = 1;
	return DSV_OK;
}

int dsv_readline() {
	int bufpos;
	int cc;
	int lstart;
	int i;
	if(dsv_rfile) {
		for(bufpos = 0; bufpos < DSV_LINEBUFSIZE - 1; bufpos++) {
			cc = fgetc(dsv_rfile);
			if(cc == EOF) {
				if(bufpos == 0) return DSV_END;
				break;
			}
			if(cc == dsv_linedelim) break;
			dsv_cline[bufpos] = cc;
		}
		dsv_cline[bufpos] = 0;
		dsv_linepos = 0;
	} else {
		if(dsv_membuf[dsv_mempos] == 0) return DSV_END;
		lstart = dsv_mempos;
		for(i = dsv_mempos; dsv_membuf[i] != 0; i++) if(dsv_membuf[i] == '\n') break;
		memcpy(dsv_cline, dsv_membuf + lstart, (i - lstart < DSV_LINEBUFSIZE) ? (i - lstart) : DSV_LINEBUFSIZE);
		dsv_cline[DSV_LINEBUFSIZE - 1] = 0;
		if(i - lstart < DSV_LINEBUFSIZE) dsv_cline[i - lstart] = 0;
		if(dsv_membuf[i] == '\n') dsv_mempos = i + 1; else dsv_mempos = i;
	}
	return DSV_OK;
}

int dsv_nextfield() {
	int i, llen, flen, olp;
	llen = strlen(dsv_cline);
	olp = dsv_linepos;
	if(dsv_linepos > llen) return DSV_END;
	for(i = dsv_linepos; i < llen; i++) {
		if(dsv_cline[i] == dsv_fielddelim) break;
	}
	flen = i - dsv_linepos;
	dsv_linepos += flen + 1;
	if(flen >= DSV_FIELDBUFSIZE) flen = DSV_FIELDBUFSIZE - 1;
	memcpy(dsv_cfield, dsv_cline + olp, flen);
	dsv_cfield[flen] = 0;
	return DSV_OK;
}

int dsv_writenum(int v) {
	if(!dsv_ffil) fprintf(dsv_wfile, ",");
	dsv_ffil = 0;
	fprintf(dsv_wfile, "%d", v);
	return DSV_OK;
}

int dsv_readint(int *v) {
	int r;
	r = dsv_nextfield();
	if(r != DSV_OK) return r;
	*v = atoi(dsv_cfield);
	return DSV_OK;
}

int dsv_readushort(unsigned short *v) {
	int r;
	r = dsv_nextfield();
	if(r != DSV_OK) return r;
	*v = atoi(dsv_cfield);
	return DSV_OK;
}

int dsv_writestring(char *v) {
	if(!dsv_ffil) fprintf(dsv_wfile, ",");
	dsv_ffil = 0;
	fprintf(dsv_wfile, "%s", v);
	return DSV_OK;
}

int dsv_readallocstring(char **v) {
	int r;
	r = dsv_nextfield();
	if(r != DSV_OK) return r;
	*v = malloc(strlen(dsv_cfield) + 1);
	strcpy(*v, dsv_cfield);
	return DSV_OK;
}

int dsv_readchar(char *v) {
	int r;
	r = dsv_nextfield();
	if(r != DSV_OK) return r;
	*v = atoi(dsv_cfield);
	return DSV_OK;
}

int dsv_writedatablock(char *v, int len) {
	int i, d1, d2;
	char chex[3];
	chex[2] = 0;
	if(!dsv_ffil) fprintf(dsv_wfile, ",");
	dsv_ffil = 0;
	for(i = 0; i < len; i++) {
		d1 = (unsigned char)v[i] / 16;
		d2 = (unsigned char)v[i] % 16;
		if(d1 < 10) chex[0] = d1 + '0'; else chex[0] = d1 - 10 + 'A';
		if(d2 < 10) chex[1] = d2 + '0'; else chex[1] = d2 - 10 + 'A';
		fprintf(dsv_wfile, "%s", chex);
	}
	return DSV_OK;
}

int dsv_readdatablock(char *v, int len) {
	int flen, i, l, r;
	char c, h;
	r = dsv_nextfield();
	if(r != DSV_OK) return r;
	flen = strlen(dsv_cfield);
	l = flen;
	if(len * 2 < flen) l = len * 2;
	memset(v, 0, len);
	for(i = 0; i < flen; i++) {
		c = dsv_cfield[i];
		h = 0;
		if(c <= '9' && c >= '0') h = c - '0';
		if(c <= 'F' && c >= 'A') h = c - 'A' + 10;
		if(c <= 'f' && c >= 'a') h = c - 'a' + 10;
		if(i % 2) v[i / 2] += h; else v[i / 2] = h * 16;
	}
	return DSV_OK;
}

int dsv_writeaddr4(struct in_addr addr) {
	int i;
	char strbuf[32];
	if(!inet_ntop(AF_INET, &addr, strbuf, 32)) return DSV_ERR;
	if(!dsv_ffil) fprintf(dsv_wfile, ",");
	dsv_ffil = 0;
	fprintf(dsv_wfile, "%s", strbuf);
	return DSV_OK;
}

int dsv_readaddr4(struct in_addr *addr) {
	int r;
	r = dsv_nextfield();
	if(r != DSV_OK) return r;
	r = inet_pton(AF_INET, dsv_cfield, addr);
	if(r != 1) return DSV_ERR;
	return DSV_OK;
}

int dsv_writeaddr6(struct in6_addr addr) {
	int i;
	char strbuf[64];
	if(!inet_ntop(AF_INET6, &addr, strbuf, 32)) return DSV_ERR;
	if(!dsv_ffil) fprintf(dsv_wfile, ",");
	dsv_ffil = 0;
	fprintf(dsv_wfile, "%s", strbuf);
	return DSV_OK;
}

int dsv_readaddr6(struct in6_addr *addr) {
	int r;
	r = dsv_nextfield();
	if(r != DSV_OK) return r;
	r = inet_pton(AF_INET6, dsv_cfield, addr);
	if(r != 1) return DSV_ERR;
	return DSV_OK;
}

/*
int main() {
	int r;
	// INT,STRING,CHARNUM,32bDATA,ADDR4,ADDR6
	int field1;
	char *field2;
	char field3;
	char field4[32];
	struct in_addr field5;
	struct in6_addr field6;
	dsv_openread("testin.csv");
	r = dsv_openwrite("testout.csv");
	if(r != DSV_OK) printf("writeopenerr\n");
	for(;;) {
		r = dsv_readline();
		if(r != DSV_OK) break;
		r = dsv_readint(&field1);
		r = dsv_readallocstring(&field2);
		r = dsv_readchar(&field3);
		r = dsv_readdatablock(field4, 32);
		r = dsv_readaddr4(&field5);
		r = dsv_readaddr6(&field6);
		r = dsv_writenum(field1);
		r = dsv_writestring(field2);
		r = dsv_writenum(field3);
		r = dsv_writedatablock(field4, 32);
		r = dsv_writeaddr4(field5);
		r = dsv_writeaddr6(field6);
		r = dsv_writeendline();
		free(field2);
	}
	dsv_closewrite();
	dsv_closeread();
}
*/
