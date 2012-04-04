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
#include <zlib.h>
#include "comp.h"
#include "comp_zlib.h"

int comp_zlib_init() {
	return COMP_OK;
}

int comp_zlib_cleanup() {
	return COMP_OK;
}

int comp_zlib_getcompressbuffersize(int uncompsize) {
	return uncompsize + uncompsize / 1000 + 13;
}

int comp_zlib_compress(char *outbuf, unsigned int *outlen, char *source, unsigned int sourcelen, int level) {
	int r;
	uLongf t_outlen = *outlen;
	r = compress2(outbuf, &t_outlen, source, sourcelen, level);
	*outlen = t_outlen;
	if(r == Z_OK) return COMP_OK;
	if(r == Z_BUF_ERROR) return COMP_SIZERR;
	return COMP_MISCERR;
}

int comp_zlib_uncompress(char *outbuf, unsigned int *outlen, char *source, unsigned int sourcelen) {
	int r;
	uLongf t_outlen = *outlen;
	r = uncompress(outbuf, &t_outlen, source, sourcelen);
	*outlen = t_outlen;
	if(r == Z_OK) return COMP_OK;
	if(r == Z_BUF_ERROR) return COMP_SIZERR;
	if(r == Z_DATA_ERROR) return COMP_DATAERR;
	return COMP_MISCERR;
}

