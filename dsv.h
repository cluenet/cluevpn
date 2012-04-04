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


#ifndef _DSV_H
#define _DSV_H

#include <stdio.h>
#include <arpa/inet.h>

#define DSV_LINEBUFSIZE 4096
#define DSV_FIELDBUFSIZE 1024

#define DSV_OK 0
#define DSV_ERR 1
#define DSV_END 2

extern FILE *dsv_wfile;
extern FILE *dsv_rfile;
extern char dsv_fielddelim;
extern char dsv_linedelim;

int dsv_openread(char *filename);
int dsv_openwrite(char *filename);
void dsv_closeread();
void dsv_closewrite();
int dsv_writeendline();
int dsv_readline();
int dsv_nextfield();
int dsv_writenum(int v);
int dsv_readint(int *v);
int dsv_readushort(unsigned short *v);
int dsv_writestring(char *v);
int dsv_readallocstring(char **v);
int dsv_readchar(char *v);
int dsv_writedatablock(char *v, int len);
int dsv_readdatablock(char *v, int len);
int dsv_writeaddr4(struct in_addr addr);
int dsv_readaddr4(struct in_addr *addr);
int dsv_writeaddr6(struct in6_addr addr);
int dsv_readaddr6(struct in6_addr *addr);

#endif
