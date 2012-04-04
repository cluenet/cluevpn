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


#ifndef _CONNECTIONS_H
#define _CONNECTIONS_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <string.h>
#include <time.h>

extern struct in6_addr in6addr_none;
extern struct in_addr inaddr_none;
extern struct in6_addr in6addr_ip4conv;

#define INADDR_ISBLANK(ina) (memcmp(&(ina), &inaddr_none, sizeof(inaddr_none)) == 0)
#define IN6ADDR_ISBLANK(ina) (memcmp(&(ina), &in6addr_none, sizeof(inaddr_none)) == 0)
#define IN6ADDR_ISIP4CONV(ina) (memcmp(&(ina), &in6addr_ip4conv, sizeof(struct in6_addr) - sizeof(struct in_addr)) == 0)
#define IN6ADDR_GETINADDR(ina) (*(struct in_addr *)((char *)&(ina) + 12))

// TCP connection backlog
#define TCP_BACKLOG 10
// Maximum SSL connections
#define MAXSSLCONS 200
// The maximum life of a connection, in seconds
#define CONN_MAXLIFE 60

#define SOCKADDR_SIZE(sa) ((((struct sockaddr *)sa)->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))

#define CONNECTION_STATE_TCPCONNECTING 1
#define CONNECTION_STATE_SSLCONNECTING 2
#define CONNECTION_STATE_CONNECTED 3
#define CONNECTION_STATE_SSLCLOSING 4
#define CONNECTION_STATE_CLOSED 5

// A structure to hold a SSL connection entry
struct conn_sslcon {
	struct conn_sslcon *next;			// Linked list next pointer
	int fd;								// The associated file descriptor
	char isserver;						// 1 if it's on the server side of the connection - 0 for the client
	int state;							// State of the connection (CONNECTION_STATE_*)
	char ssl_want_read;					// If SSL wants a read next
	char ssl_want_write;				// If SSL wants a write next
	// The buffers are pointers to external areas in memory (given and handled by the calling function)
	// The positions are the current place inside of the buffer to send/receive from
	// The lengths are the amount of data to send from the start of the send buffer, or the amount of data to receive from the start of the receive buffer
	char *sendbuf;
	char *sendpos;
	int sendlen;
	char *recvbuf;						// Buffer of data to receive.  Should be allocated to recvlen.
	char *recvpos;						// Current position in the buffer to receive data into.  Amount of data to receive per iteration is recvlen - (recvpos - recvbuf)
	int recvlen;						// Length of recvbuf - amount of data to receive
	int peerid;
	// This is the address of the peer - the length can be determined from the ss_family entry
	struct sockaddr_storage peeraddr;
	char event;							// Set to 1 if an event has occurred on this connection
	// These are handled by the SSL libraries - should be init'd and freed using the SSL library functions
	SSL *ssl;
	BIO *sslbio;
	X509 *peercert;
	// Time the connection was created
	time_t createtime;
	// Data specific to the calling functions
	void *data;
};

typedef struct conn_sslcon * sslcon_t;

// A structure to hold data pertaining to the UDP socket
struct conn_udpsock {
	int fd;
	char *sendbuf;
	int sendbuflen;
	struct sockaddr_storage sendtoaddr;
	char *recvbuf;
	int recvbuflen;
	int recvbufsize;
	struct sockaddr_storage recvfromaddr;
};

// A structure to hold data pertaining to the tun interface
struct conn_tun {
	int fd;
	char *sendbuf;
	int sendbuflen;
	char *recvbuf;
	int recvbuflen;
	int recvbufsize;
};

// A structure to hold data pertaining to the SSL server socket
struct conn_sslserv {
	int fd;
};

extern struct conn_udpsock conn_udpcon;
extern struct conn_tun conn_tuncon;
extern struct conn_sslserv conn_sslservsock;
extern struct conn_sslcon *conn_sslcons;
extern int conn_numsslcons;
extern char tundevname[256];

void conn_setudptunbufs(char *udpsendbuf, char *udprecvbuf, int udprecvbuflen, char *tunsendbuf, char *tunrecvbuf, int tunrecvbuflen);
int conn_closecon(struct conn_sslcon *con);

#define conn_sslconlist_start() (conn_sslcons)
#define conn_sslconlist_next(con) (con->next)

#define conn_sslcon_issent(con) (con->sendbuf + con->sendlen == con->sendpos)
#define conn_sslcon_hasrecv(con) (con->recvbuf && con->recvpos > con->recvbuf)
#define conn_sslcon_hasfullrecv(con) (conn_sslcon_hasrecv(con) && con->recvbuf + con->recvlen == con->recvpos)






#define SSLCON_HASDATA(con) ((con->recvpos - con->recvbuf > 0) ? 1 : 0)
#define SSLCON_FULLDATA(con) ((SSLCON_AVAILABLEDATA(con) == con->recvlen) ? 1 : 0)
#define SSLCON_SENDBUFEMPTY(con) ((con->sendpos == con->sendbuf) ? 1 : 0)
#define SSLCON_USERDATA(con) (con->data)
#define SSLCON_STATE(con) (con->state)

#define UDP_HASDATA() ((conn_udpcon.recvbuflen > 0) ? 1 : 0)
#define UDP_SENDBUFEMPTY() ((conn_udpcon.sendbuflen > 0) ? 0 : 1)
#define UDP_CLEARRECVBUF() conn_udpcon.recvbuflen = 0
#define UDP_SENDBUF (conn_udpcon.sendbuf)
#define UDP_SENDLEN (conn_udpcon.sendbuflen)
#define UDP_RECVBUF (conn_udpcon.recvbuf)
#define UDP_RECVLEN (conn_udpcon.recvbuflen)
#define UDP_SENDADDR (conn_udpcon.sendtoaddr)
#define UDP_RECVADDR (conn_udpcon.recvfromaddr)
#define TUN_HASDATA() ((conn_tuncon.recvbuflen > 0) ? 1 : 0)
#define TUN_SENDBUFEMPTY() ((conn_tuncon.sendbuflen > 0) ? 0 : 1)
#define TUN_CLEARRECVBUF() conn_tuncon.recvbuflen = 0
#define TUN_SENDBUF (conn_tuncon.sendbuf)
#define TUN_SENDLEN (conn_tuncon.sendbuflen)
#define TUN_RECVBUF (conn_tuncon.recvbuf)
#define TUN_RECVLEN (conn_tuncon.recvbuflen)


#endif
