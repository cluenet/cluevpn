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


#ifndef _SIGNATURE_H
#define _SIGNATURE_H

#include <arpa/inet.h>

#define SIG_OK 0
#define SIG_ERROR 1
#define SIG_INCORRECT 2

#define SIG_MAXSIGSIZE 512
#define SIG_SIGMAXFILESIZE(fsize) (sizeof(int) + sizeof(int) + fsize + SIG_MAXSIGSIZE)

#define SIG_DATA(fdata) ((char *)fdata + sizeof(int))
#define SIG_DATALEN(fdata) (ntohl(*(int *)fdata))

int sig_init();
void sig_close();
char *sig_getsigfromfile(char *filedata, unsigned int filelen, unsigned int *siglen);
char *sig_getdatafromfile(char *filedata, unsigned int filelen, unsigned int *datalen);
int sig_verify(char *data, unsigned int datalen, char *sig, unsigned int siglen);
int sig_makesig(char *data, unsigned int datalen, char *sigbuf, unsigned int *siglen);
int sig_makefile(char *data, unsigned int datalen, char *sig, unsigned int siglen, char *filebuf, unsigned int *filelen);
int sig_signandmakefile(char *data, unsigned int datalen, char *filebuf, unsigned int *filelen);
int sig_verifyandgetdata(char *filedata, unsigned int filelen, char **dataptr, unsigned int *datalenptr);



/*
int sig_initverify();
void sig_closeverify();
char *sig_getsigfromfile(char *filedata, unsigned int filelen, unsigned int *siglen);
char *sig_getdatafromfile(char *filedata, unsigned int filelen, unsigned int *datalen);
int sig_verify(char *data, unsigned int datalen, char *sig, unsigned int siglen);
int sig_verifyandgetdata(char *filedata, unsigned int filelen, char **dataptr, unsigned int *datalenptr);
*/

#endif
