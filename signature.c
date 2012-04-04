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
#include "logger.h"
#include "signature.h"
#include "configfile.h"

EVP_PKEY *sig_pubkey = NULL;
EVP_PKEY *sig_privkey = NULL;

int sig_init() {
	FILE *f;
	sig_pubkey = NULL;
	sig_privkey = NULL;
	if(global_config.bnlpubkey) {
		f = fopen(global_config.bnlpubkey, "r");
		if(!f) {
			logmsg(LOGGER_ERR, "Could not open BNL public key file");
			return SIG_ERROR;
		}
		sig_pubkey = PEM_read_PUBKEY(f, &sig_pubkey, NULL, NULL);
		if(!sig_pubkey) {
			logmsg(LOGGER_ERR, "Error reading BNL public key: %s", ERR_error_string(ERR_get_error(), NULL));
			return SIG_ERROR;
		}
		fclose(f);
	}
	if(global_config.bnlprivkey) {
		f = fopen(global_config.bnlprivkey, "r");
		if(!f) {
			logmsg(LOGGER_ERR, "Could not open BNL private key file");
			return SIG_ERROR;
		}
		sig_privkey = PEM_read_PrivateKey(f, &sig_privkey, NULL, NULL);
		if(!sig_privkey) {
			logmsg(LOGGER_ERR, "Error reading BNL private key: %s", ERR_error_string(ERR_get_error(), NULL));
			return SIG_ERROR;
		}
		fclose(f);
	}
	return SIG_OK;
}

void sig_close() {
	EVP_PKEY_free(sig_pubkey);
	if(sig_privkey) EVP_PKEY_free(sig_privkey);
}

char *sig_getsigfromfile(char *filedata, unsigned int filelen, unsigned int *siglen) {
	unsigned int datalen;
	if(filelen < 8) return NULL;
	datalen = ntohl(*(unsigned int *)filedata);
	if(datalen + sizeof(datalen) + sizeof(*siglen) > filelen) return NULL;
	*siglen = ntohl(*(unsigned int *)(filedata + sizeof(datalen) + datalen));
	if(sizeof(datalen) + datalen + sizeof(*siglen) + *siglen != filelen) return NULL;
	return filedata + sizeof(datalen) + datalen + sizeof(*siglen);
}

char *sig_getdatafromfile(char *filedata, unsigned int filelen, unsigned int *datalen) {
	if(filelen < 8) return NULL;
	*datalen = ntohl(*(unsigned int *)filedata);
	if(sizeof(*datalen) + *datalen + sizeof(unsigned int) > filelen) return NULL;
	return filedata + sizeof(*datalen);
}

int sig_verify(char *data, unsigned int datalen, char *sig, unsigned int siglen) {
	EVP_MD_CTX ctx;
	int r;
	if(!sig_pubkey) {
		logmsg(LOGGER_ERR, "Error signing BNL: No public key loaded");
		return SIG_ERROR;
	}
	EVP_VerifyInit(&ctx, EVP_dss1());
	if(EVP_VerifyUpdate(&ctx, data, datalen) != 1) {
		logmsg(LOGGER_ERR, "Error verifying signature: %s", ERR_error_string(ERR_get_error(), NULL));
		return SIG_ERROR;
	}
	r = EVP_VerifyFinal(&ctx, sig, siglen, sig_pubkey);
	EVP_MD_CTX_cleanup(&ctx);
	if(r == 1) return SIG_OK;
	if(r == 0) return SIG_INCORRECT;
	logmsg(LOGGER_ERR, "Error verifying signature: %s", ERR_error_string(ERR_get_error(), NULL));
	return SIG_ERROR;
}

int sig_makesig(char *data, unsigned int datalen, char *sigbuf, unsigned int *siglen) {
	EVP_MD_CTX ctx;
	int r;
	if(!sig_privkey) {
		logmsg(LOGGER_ERR, "Error signing BNL: No private key loaded");
		return SIG_ERROR;
	}
	EVP_SignInit(&ctx, EVP_dss1());
	if(EVP_SignUpdate(&ctx, data, datalen) != 1) {
		logmsg(LOGGER_ERR, "Error signing BNL: %s", ERR_error_string(ERR_get_error(), NULL));
		return SIG_ERROR;
	}
	r = EVP_SignFinal(&ctx, sigbuf, siglen, sig_privkey);
	EVP_MD_CTX_cleanup(&ctx);
	if(r == 1) return SIG_OK;
	logmsg(LOGGER_ERR, "Error signing BNL: %s", ERR_error_string(ERR_get_error(), NULL));
	return SIG_ERROR;
}

int sig_makefile(char *data, unsigned int datalen, char *sig, unsigned int siglen, char *filebuf, unsigned int *filelen) {
	*(unsigned int *)filebuf = htonl(datalen);
	memcpy(filebuf + sizeof(int), data, datalen);
	*(unsigned int *)(filebuf + sizeof(int) + datalen) = htonl(siglen);
	memcpy(filebuf + sizeof(int) + datalen + sizeof(int), sig, siglen);
	*filelen = sizeof(int) + datalen + sizeof(int) + siglen;
	return SIG_OK;
}

int sig_signandmakefile(char *data, unsigned int datalen, char *filebuf, unsigned int *filelen) {
	static char sigbuf[SIG_MAXSIGSIZE];
	unsigned int siglen;
	int r;
	siglen = SIG_MAXSIGSIZE;
	r = sig_makesig(data, datalen, sigbuf, &siglen);
	if(r != SIG_OK) return SIG_ERROR;
	r = sig_makefile(data, datalen, sigbuf, siglen, filebuf, filelen);
	return r;
}

int sig_verifyandgetdata(char *filedata, unsigned int filelen, char **dataptr, unsigned int *datalenptr) {
	char *sig, *data;
	unsigned int siglen, datalen;
	int r;
	data = sig_getdatafromfile(filedata, filelen, &datalen);
	if(!data) return SIG_ERROR;
	if(dataptr) *dataptr = data;
	if(datalenptr) *datalenptr = datalen;
	sig = sig_getsigfromfile(filedata, filelen, &siglen);
	if(!sig) return SIG_ERROR;
	r = sig_verify(data, datalen, sig, siglen);
	return r;
}

