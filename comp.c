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


#include <stdlib.h>
#include "comp.h"
#include "comp_zlib.h"

comp_algo_def_t *comp_algos;

int comp_init() {
	if(comp_zlib_init() != COMP_OK) return COMP_MISCERR;
	comp_algos = malloc(2 * sizeof(comp_algo_def_t));
	comp_algos[COMP_ZLIB].getcompressbuffersize = comp_zlib_getcompressbuffersize;
	comp_algos[COMP_ZLIB].compress = comp_zlib_compress;
	comp_algos[COMP_ZLIB].uncompress = comp_zlib_uncompress;
	return COMP_OK;
}

int comp_cleanup() {
	free(comp_algos);
	if(comp_zlib_cleanup() != COMP_OK) return COMP_MISCERR;
	return COMP_OK;
}

comp_algo_def_t *comp_getalgo(unsigned int algoid) {
	if(algoid > 1) return NULL;
	return &(comp_algos[algoid]);
}
