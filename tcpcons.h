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


#ifndef _TCPCONS_H
#define _TCPCONS_H

#include "connections.h"

#define TCPCON_NONE 0			// No type, or unknown type
#define TCPCON_NEGOTIATION 1	// A negotiation connection
#define TCPCON_BNLPULL 2		// A BNL pull (from server to client) connection
#define TCPCON_BNLPUSH 3		// A BNL push

#define TCPCON_STATE_NEW 0
#define TCPCON_STATE_RECEIVINGTYPE 1
#define TCPCON_STATE_RECEIVINGLENGTH 2
#define TCPCON_STATE_RECEIVINGDATA 3
#define TCPCON_STATE_WAITFORSEND 4
#define TCPCON_STATE_DONE 5

#define TCPCON_OK 0
#define TCPCON_ERROR 1

#define MAXRECVBNL (1024 * 1024)

#define NEGOTIATE_CRYPTKEY_SIZE 64
#define NEGOTIATE_ALGOLIST_SIZE 32

struct negotiate_algo {
	int algoid;
	unsigned short level;
	int preference;
} __attribute__ ((__packed__));

struct negotiate_msg {
	struct negotiate_algo cryptalgos[NEGOTIATE_ALGOLIST_SIZE];
	struct negotiate_algo compalgos[NEGOTIATE_ALGOLIST_SIZE];
	char cryptkey[NEGOTIATE_CRYPTKEY_SIZE];
} __attribute__ ((__packed__));

struct tcpcon_data {
	unsigned char conntype;		// The type/purpose of the connection
	unsigned char connstate;	// The internal state of this type of connection
	int peerid;					// The host ID of the peer
	char *sendbuf;				// The send buffer to use once the connection is established, and will then be freed
	int sendlen;				// Length of sendbuf
	struct negotiate_msg *sentnegmsg;	// If it's a negotiate, the message that was sent is stored here
};

void tcpcon_freeconndata(struct tcpcon_data *tcd);
int tcpcon_newnegotiate(int desthostid);
int tcpcon_newbnlpull(int desthostid);
int tcpcon_handleevent(struct conn_sslcon *con);
char tcpcon_checkExistingConn(int nodeid, char type, char isserver);

#endif
