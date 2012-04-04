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


#ifndef _CRYPT_AESCBC_H
#define _CRYPT_AESCBC_H

unsigned int crypt_aescbc_getencryptbuflen(unsigned int inlen);
int crypt_aescbc_encrypt(unsigned char *key, unsigned int keybits, unsigned char *ivec, unsigned int iveclen, unsigned char *inbuf, unsigned int inlen, unsigned char *outbuf, unsigned int *outlen);
int crypt_aescbc_decrypt(unsigned char *key, unsigned int keybits, unsigned char *ivec, unsigned int iveclen, unsigned char *inbuf, unsigned int inlen, unsigned char *outbuf, unsigned int *outlen);

#endif
