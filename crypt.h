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


#ifndef __CRYPT_H
#define __CRYPT_H

#define CRYPT_MAXKEYBITS 512

#define CRYPT_OK 0
#define CRYPT_MISCERR 1
#define CRYPT_BADALGOERR 2
#define CRYPT_TOOBIG 3

#define CRYPT_AESCBC 0

typedef struct {
	unsigned int (*getencryptbuflen)(unsigned int);
	int (*encrypt)(unsigned char *, unsigned int, unsigned char *, unsigned int, unsigned char *, unsigned int, unsigned char *, unsigned int *);
	int (*decrypt)(unsigned char *, unsigned int, unsigned char *, unsigned int, unsigned char *, unsigned int, unsigned char *, unsigned int *);
} crypt_algo_def_t;

int crypt_init();
int crypt_cleanup();
crypt_algo_def_t *crypt_getalgo(unsigned int algoid);

#define CRYPTBUFLEN 66560
extern char cryptbuf[66560];

#endif

