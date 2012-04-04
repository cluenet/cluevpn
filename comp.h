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


#ifndef __COMP_H
#define __COMP_H

#define COMP_OK 0
#define COMP_SIZERR 1
#define COMP_DATAERR 2
#define COMP_MISCERR 3
#define COMP_BADALGOERR 4

#define COMP_NONE 0
#define COMP_ZLIB 1

typedef struct {
	int (*getcompressbuffersize)(int);
	int (*compress)(char *, unsigned int *, char *, unsigned int, int);
	int (*uncompress)(char *, unsigned int *, char *, unsigned int);
} comp_algo_def_t;

comp_algo_def_t *comp_getalgo(unsigned int algoid);
int comp_init();
int comp_cleanup();

#endif

