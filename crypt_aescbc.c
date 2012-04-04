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
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include "crypt.h"
#include "crypt_aescbc.h"

void crypt_aescbc_getivec(unsigned char *ivec, unsigned int iveclen, unsigned char *ivecbuf) {
	unsigned char hashbuf[SHA_DIGEST_LENGTH];
	if(!ivec || iveclen < 1) memset(ivecbuf, 0, AES_BLOCK_SIZE); else {
		if(iveclen >= AES_BLOCK_SIZE) {
			memcpy(ivecbuf, ivec, AES_BLOCK_SIZE);
		} else {
			SHA1(ivec, iveclen, hashbuf);
			memset(ivecbuf, 0, AES_BLOCK_SIZE);
			memcpy(ivecbuf, hashbuf, (SHA_DIGEST_LENGTH < AES_BLOCK_SIZE) ? SHA_DIGEST_LENGTH : AES_BLOCK_SIZE);
		}
	}
}

unsigned int crypt_aescbc_getencryptbuflen(unsigned int inlen) {
	return (inlen / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
}

int crypt_aescbc_encrypt(unsigned char *key, unsigned int keybits, unsigned char *ivec, unsigned int iveclen, unsigned char *inbuf, unsigned int inlen, unsigned char *outbuf, unsigned int *outlen) {
	unsigned char ivecbuf[AES_BLOCK_SIZE];
	unsigned char *databuf = (unsigned char *)cryptbuf;
	int databuflen;
	AES_KEY akey;
	// Make sure the keybits is OK
	if(keybits != 128 && keybits != 192 && keybits != 256) return CRYPT_MISCERR;
	// Create the IV.  If a full IV is supplied, use that.  If no IV is supplied, get along without one.  If a partial IV is supplied, form that into a full IV with a hash.
	crypt_aescbc_getivec(ivec, iveclen, ivecbuf);
	// The length of the output data may be greated than the length of the input data due to padding
	databuflen = crypt_aescbc_getencryptbuflen(inlen);
	if(CRYPTBUFLEN < databuflen) return CRYPT_TOOBIG;
	memcpy(databuf, inbuf, inlen);
	// Fill padding with random stuff (doesn't have to be too random)
	RAND_pseudo_bytes(databuf + inlen, databuflen - inlen - 1);
	// The last byte of the data to encrypt is the amount of padding used, not including the last byte
	databuf[databuflen - 1] = databuflen - inlen - 1;
	// Create the AES key
	AES_set_encrypt_key(key, keybits, &akey);
	// Encrypt data to outbuf
	AES_cbc_encrypt(databuf, outbuf, databuflen, &akey, ivecbuf, AES_ENCRYPT);
	// Update outlen, and return
	*outlen = databuflen;
	return CRYPT_OK;
}

int crypt_aescbc_decrypt(unsigned char *key, unsigned int keybits, unsigned char *ivec, unsigned int iveclen, unsigned char *inbuf, unsigned int inlen, unsigned char *outbuf, unsigned int *outlen) {
	unsigned char ivecbuf[AES_BLOCK_SIZE];
	unsigned char *databuf = cryptbuf;
	AES_KEY akey;
	// Make sure the input size is at least one block and in multiples of blocks
	if(inlen < AES_BLOCK_SIZE || inlen % AES_BLOCK_SIZE != 0) return CRYPT_MISCERR;
	// Make sure the keybits setting is OK
	if(keybits != 128 && keybits != 192 && keybits != 256) return CRYPT_MISCERR;
	// Create the IV.  If a full IV is supplied, use that.  If no IV is supplied, get along without one.  If a partial IV is supplied, form that into a full IV with a hash.
	crypt_aescbc_getivec(ivec, iveclen, ivecbuf);
	// Create the AES key
	AES_set_decrypt_key(key, keybits, &akey);
	// Allocate databuf to hold the raw decrypted data
	if(CRYPTBUFLEN < inlen) return CRYPT_TOOBIG;
	// Decrypt data to outbuf
	AES_cbc_encrypt(inbuf, databuf, inlen, &akey, ivecbuf, AES_DECRYPT);
	// Make sure the amount of padding is reasonable
	if(databuf[inlen - 1] >= AES_BLOCK_SIZE) return CRYPT_MISCERR;
	// Calculate the output length based on the amount of padding (taken from last byte)
	*outlen = inlen - databuf[inlen - 1] - 1;
	// Copy data to the output
	memcpy(outbuf, databuf, *outlen);
	// return
	return CRYPT_OK;
}
