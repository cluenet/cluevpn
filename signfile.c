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
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <arpa/inet.h>

int main(int argc, char **argv) {
	EVP_MD_CTX ctx;
	char buf[1024];
	char cpbuf[1024];
	FILE *cpf;
	int num;
	int r;
	unsigned int signum, nsignum;
	unsigned int inlen = 0;
	EVP_PKEY *pkey;
	FILE *f;
	if(argc != 4) {
		printf("Usage: %s <InFile> <OutFile> <KeyFile>\n", argv[0]);
		return 1;
	}
	SSL_load_error_strings();
	f = fopen(argv[1], "r");
	if(!f) {
		printf("Could not open input file.\n");
		return 1;
	}
	EVP_SignInit(&ctx, EVP_dss1());
	while(num = fread(buf, 1, 1024, f)) {
		inlen += num;
		r = EVP_SignUpdate(&ctx, buf, num);
		if(!r) {
			printf("Error updating signature.\n");
			return 1;
		}
	}
	fclose(f);
	f = fopen(argv[3], "r");
	if(!f) {
		printf("Could not open key file.\n");
		return 1;
	}
	pkey = NULL;
	pkey = PEM_read_PrivateKey(f, &pkey, NULL, NULL);
	if(!pkey) {
		printf("Error reading private key.\n");
		return 1;
	}
	fclose(f);
	printf("Private key size: %d\n", EVP_PKEY_size(pkey));
	r = EVP_SignFinal(&ctx, buf, &signum, pkey);
	if(!r) {
		printf("Error creating signature: %s\n", ERR_error_string(ERR_get_error(), NULL));
		return 1;
	}
	EVP_PKEY_free(pkey);
	f = fopen(argv[2], "w");
	if(!f) {
		printf("Could not open output file.\n");
		return 1;
	}
	nsignum = htonl(signum);
	cpf = fopen(argv[1], "r");
	if(!cpf) {
		printf("Could not open input file.\n");
		return 1;
	}
	inlen = htonl(inlen);
	fwrite(&inlen, sizeof(inlen), 1, f);
	while(num = fread(cpbuf, 1, 1024, cpf)) {
		fwrite(cpbuf, 1, num, f);
	}
	fclose(cpf);
	fwrite(&nsignum, sizeof(nsignum), 1, f);
	fwrite(buf, 1, signum, f);
	fclose(f);
	EVP_MD_CTX_cleanup(&ctx);
	return 0;
}
