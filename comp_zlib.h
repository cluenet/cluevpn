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


#ifndef _COMP_ZLIB_H
#define _COMP_ZLIB_H

int comp_zlib_init();
int comp_zlib_cleanup();
int comp_zlib_getcompressbuffersize(int uncompsize);
int comp_zlib_compress(char *outbuf, unsigned int *outlen, char *source, unsigned int sourcelen, int level);
int comp_zlib_uncompress(char *outbuf, unsigned int *outlen, char *source, unsigned int sourcelen);

#endif
