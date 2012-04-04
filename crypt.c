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
#include "crypt.h"
#include "crypt_aescbc.h"

char cryptbuf[66560];

crypt_algo_def_t *crypt_algos;

int crypt_init() {
	crypt_algos = malloc(2 * sizeof(crypt_algo_def_t));
	crypt_algos[CRYPT_AESCBC].getencryptbuflen = crypt_aescbc_getencryptbuflen;
	crypt_algos[CRYPT_AESCBC].encrypt = crypt_aescbc_encrypt;
	crypt_algos[CRYPT_AESCBC].decrypt = crypt_aescbc_decrypt;
	return CRYPT_OK;
}

int crypt_cleanup() {
	free(crypt_algos);
	return CRYPT_OK;
}

crypt_algo_def_t *crypt_getalgo(unsigned int algoid) {
	if(algoid >= 1) return NULL;
	return &(crypt_algos[algoid]);
}
