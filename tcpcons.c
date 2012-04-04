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
#include "connections.h"
#include "configfile.h"
#include "nodeinfo.h"
#include "crypt.h"
#include "comp.h"
#include "seqnum.h"
#include "tcpcons.h"
#include "logger.h"
#include "bnl.h"
#include "signature.h"

void tcpcon_freeconndata(struct tcpcon_data *tcd) {
	if(tcd->sendbuf) free(tcd->sendbuf);
	if(tcd->sentnegmsg) free(tcd->sentnegmsg);
}

struct configfile_algo_pref *getDefaultCryptAlgos() {
	static struct configfile_algo_pref ret[2];
	ret[0].algo = CRYPT_AESCBC;
	ret[0].level = 192;
	ret[0].pref = 5;
	ret[1].algo = -1;
	return ret;
}

struct configfile_algo_pref *getDefaultCompAlgos() {
	static struct configfile_algo_pref ret[3];
	ret[0].algo = COMP_NONE;
	ret[0].level = 0;
	ret[0].pref = 2;
	ret[1].algo = COMP_ZLIB;
	ret[1].level = 6;
	ret[1].pref = 1;
	ret[2].algo = -1;
	return ret;
}

char tcpcon_checkExistingConn(int nodeid, char type, char isserver) {
	struct conn_sslcon *ccon;
	int cremnode;
	char ctype;
	for(ccon = conn_sslconlist_start(); ccon; ccon = conn_sslconlist_next(ccon)) {
		// If the connection is closed or closing, skip it.
		if(ccon->state == CONNECTION_STATE_SSLCLOSING || ccon->state == CONNECTION_STATE_CLOSED) continue;
		// Make sure we know the remote node id
		cremnode = -1;
		if(ccon->state == CONNECTION_STATE_CONNECTED) {
			cremnode = ccon->peerid;
		} else {
			if(!ccon->isserver) if(ccon->data) cremnode = ((struct tcpcon_data *)ccon->data)->peerid;
		}
		if(cremnode < 0) continue;
		// Make sure we know the connection type
		if(ccon->data && (ccon->state == CONNECTION_STATE_CONNECTED || !ccon->isserver)) {
			ctype = ((struct tcpcon_data *)ccon->data)->conntype;
		} else continue;
		// If the type and node ids are equal, return 1
		if(isserver == 0) if(nodeid == cremnode && type == ctype && !ccon->isserver) return 1;
		if(isserver == 1) if(nodeid == cremnode && type == ctype && ccon->isserver) return 1;
		if(nodeid == cremnode && type == ctype) return 1;
	}
	return 0;
}

// Receives data in network byte order - returns it in host byte order
int tcpcon_doNegotiateCalc(struct negotiate_msg *negmsg1, struct negotiate_msg *negmsg2, struct negotiate_algo *retcryptalgo, struct negotiate_algo *retcompalgo, char *retcryptkey) {
	int i, j;
	int cpreftotal;
	int maxid, maxpreftotal, max1idx, max2idx;
	// Convert all the inputs to host byte order
	for(i = 0; i < NEGOTIATE_ALGOLIST_SIZE; i++) {
		negmsg1->cryptalgos[i].algoid = ntohl(negmsg1->cryptalgos[i].algoid);
		negmsg1->cryptalgos[i].level = ntohs(negmsg1->cryptalgos[i].level);
		negmsg1->cryptalgos[i].preference = ntohl(negmsg1->cryptalgos[i].preference);
		negmsg1->compalgos[i].algoid = ntohl(negmsg1->compalgos[i].algoid);
		negmsg1->compalgos[i].level = ntohs(negmsg1->compalgos[i].level);
		negmsg1->compalgos[i].preference = ntohl(negmsg1->compalgos[i].preference);
		negmsg2->cryptalgos[i].algoid = ntohl(negmsg2->cryptalgos[i].algoid);
		negmsg2->cryptalgos[i].level = ntohs(negmsg2->cryptalgos[i].level);
		negmsg2->cryptalgos[i].preference = ntohl(negmsg2->cryptalgos[i].preference);
		negmsg2->compalgos[i].algoid = ntohl(negmsg2->compalgos[i].algoid);
		negmsg2->compalgos[i].level = ntohs(negmsg2->compalgos[i].level);
		negmsg2->compalgos[i].preference = ntohl(negmsg2->compalgos[i].preference);
	}
	// For each encryption algorithm in msg1, find the corresponding one in msg2, add the preference levels, and find the max.  For ties, use the highest value.
	maxid = -1;
	maxpreftotal = -1;
	max1idx = -1;
	max2idx = -1;
	for(i = 0; i < NEGOTIATE_ALGOLIST_SIZE; i++) {
		if(negmsg1->cryptalgos[i].algoid < 0) break;
		for(j = 0; j < NEGOTIATE_ALGOLIST_SIZE; j++) {
			if(negmsg2->cryptalgos[j].algoid < 0) break;
			if(negmsg1->cryptalgos[i].algoid == negmsg2->cryptalgos[j].algoid) {
				cpreftotal = negmsg1->cryptalgos[i].preference + negmsg2->cryptalgos[j].preference;
				if(cpreftotal > maxpreftotal || maxid < 0 || (cpreftotal == maxpreftotal && negmsg1->cryptalgos[i].algoid > maxid)) {
					maxid = negmsg1->cryptalgos[i].algoid;
					maxpreftotal = cpreftotal;
					max1idx = i;
					max2idx = j;
				}
				break;
			}
		}
	}
	if(maxid < 0) {
		logmsg(LOGGER_NOTICE, "Could not agree on encryption algorithms");
		return TCPCON_ERROR;
	}
	retcryptalgo->algoid = maxid;
	retcryptalgo->preference = maxpreftotal;
	retcryptalgo->level = (negmsg1->cryptalgos[max1idx].level > negmsg2->cryptalgos[max2idx].level) ? negmsg1->cryptalgos[max1idx].level : negmsg2->cryptalgos[max2idx].level;
	// Do the same for compression algorithms
	maxid = -1;
	maxpreftotal = -1;
	max1idx = -1;
	max2idx = -1;
	for(i = 0; i < NEGOTIATE_ALGOLIST_SIZE; i++) {
		if(negmsg1->compalgos[i].algoid < 0) break;
		for(j = 0; j < NEGOTIATE_ALGOLIST_SIZE; j++) {
			if(negmsg2->compalgos[j].algoid < 0) break;
			if(negmsg1->compalgos[i].algoid == negmsg2->compalgos[j].algoid) {
				cpreftotal = negmsg1->compalgos[i].preference + negmsg2->compalgos[j].preference;
				if(cpreftotal > maxpreftotal || maxid < 0 || (cpreftotal == maxpreftotal && negmsg1->compalgos[i].algoid > maxid)) {
					maxid = negmsg1->compalgos[i].algoid;
					maxpreftotal = cpreftotal;
					max1idx = i;
					max2idx = j;
				}
				break;
			}
		}
	}
	if(maxid < 0) {
		logmsg(LOGGER_NOTICE, "Could not agree on compression algorithms");
		return TCPCON_ERROR;
	}
	retcompalgo->algoid = maxid;
	retcompalgo->preference = maxpreftotal;
	retcompalgo->level = (negmsg1->compalgos[max1idx].level > negmsg2->compalgos[max2idx].level) ? negmsg1->compalgos[max1idx].level : negmsg2->compalgos[max2idx].level;
	// XOR the two encryption keys to get the result
	for(i = 0; i < NEGOTIATE_CRYPTKEY_SIZE; i++) retcryptkey[i] = negmsg1->cryptkey[i] ^ negmsg2->cryptkey[i];
	// Return OK.
	return TCPCON_OK;
}

int tcpcon_makeallocnegotiatemsg(int hostid, char cryptkey[NEGOTIATE_CRYPTKEY_SIZE], struct negotiate_msg **msgret) {
	struct negotiate_msg *msg;
	struct configfile_algo_pref *cryptalgopref, *compalgopref;
	int i;
	if(!NODEINFO_EXISTS(hostid)) return TCPCON_ERROR;
	// Figure out which set of algorithm preferences to use
	cryptalgopref = getDefaultCryptAlgos();
	compalgopref = getDefaultCompAlgos();
	if(global_config.cryptalgos) cryptalgopref = global_config.cryptalgos;
	if(global_config.compalgos) compalgopref = global_config.compalgos;
	if(NODEINFO_INFO(hostid).options) if(NODEINFO_INFO(hostid).options->cryptalgos) cryptalgopref = NODEINFO_INFO(hostid).options->cryptalgos;
	if(NODEINFO_INFO(hostid).options) if(NODEINFO_INFO(hostid).options->compalgos) compalgopref = NODEINFO_INFO(hostid).options->compalgos;
	// Allocate the negotiation message
	msg = malloc(sizeof(struct negotiate_msg));
	memset(msg, 0, sizeof(struct negotiate_msg));
	// Fill in the algorithm lists
	for(i = 0; cryptalgopref[i].algo >= 0 && i < NEGOTIATE_ALGOLIST_SIZE; i++) {
		msg->cryptalgos[i].algoid = htonl(cryptalgopref[i].algo);
		msg->cryptalgos[i].level = htons(cryptalgopref[i].level);
		msg->cryptalgos[i].preference = htonl(cryptalgopref[i].pref);
	}
	if(i < NEGOTIATE_ALGOLIST_SIZE) msg->cryptalgos[i].algoid = htonl(-1);
	for(i = 0; compalgopref[i].algo >= 0 && i < NEGOTIATE_ALGOLIST_SIZE; i++) {
		msg->compalgos[i].algoid = htonl(compalgopref[i].algo);
		msg->compalgos[i].level = htons(compalgopref[i].level);
		msg->compalgos[i].preference = htonl(compalgopref[i].pref);
	}
	if(i < NEGOTIATE_ALGOLIST_SIZE) msg->compalgos[i].algoid = htonl(-1);
	// Fill in the encryption key
	memcpy(msg->cryptkey, cryptkey, NEGOTIATE_CRYPTKEY_SIZE);
	*msgret = msg;
	return TCPCON_OK;
}

int tcpcon_newnegotiate(int desthostid) {
	struct tcpcon_data *tcd;
	int r;
	struct sockaddr *destaddr;
	socklen_t destaddrlen;
	if(tcpcon_checkExistingConn(desthostid, TCPCON_NEGOTIATION, 2)) {
		logmsg(LOGGER_INFO, "Negotiation already in progress");
		return TCPCON_OK;
	}
	tcd = malloc(sizeof(struct tcpcon_data));
	memset(tcd, 0, sizeof(struct tcpcon_data));
	tcd->conntype = TCPCON_NEGOTIATION;
	tcd->connstate = TCPCON_STATE_NEW;
	tcd->peerid = desthostid;
	r = getnodeaddress(desthostid, &destaddr, &destaddrlen);
	if(r == NODEINFO_NOENT) {
		logmsg(LOGGER_NOTICE, "Cannot communicate with node %s - incompatable supported addresses", NODEINFO_INFO(desthostid).name);
		free(tcd);
		return TCPCON_ERROR;
	}
	if(r != NODEINFO_OK) {
		logmsg(LOGGER_NOTICE, "Error getting address for node");
		free(tcd);
		return TCPCON_ERROR;
	}
	r = conn_sslcon_new(destaddr, destaddrlen, tcd);
	if(r != 0) {
		logmsg(LOGGER_ERR, "Error starting connection to node %s", NODEINFO_INFO(desthostid).name);
		free(tcd);
		return TCPCON_ERROR;
	}
	return TCPCON_OK;
}

int tcpcon_newbnlpull(int desthostid) {
	struct tcpcon_data *tcd;
	int r;
	struct sockaddr *destaddr;
	socklen_t destaddrlen;
	if(tcpcon_checkExistingConn(desthostid, TCPCON_BNLPULL, 0) || tcpcon_checkExistingConn(desthostid, TCPCON_BNLPUSH, 1)) {
		logmsg(LOGGER_INFO, "BNL pull already in progress");
		return TCPCON_OK;
	}
	tcd = malloc(sizeof(struct tcpcon_data));
	memset(tcd, 0, sizeof(struct tcpcon_data));
	tcd->conntype = TCPCON_BNLPULL;
	tcd->connstate = TCPCON_STATE_NEW;
	tcd->peerid = desthostid;
	r = getnodeaddress(desthostid, &destaddr, &destaddrlen);
	if(r == NODEINFO_NOENT) {
		logmsg(LOGGER_NOTICE, "Cannot communicate with node %s - incompatable supported addresses", NODEINFO_INFO(desthostid).name);
		free(tcd);
		return TCPCON_ERROR;
	}
	if(r != NODEINFO_OK) {
		logmsg(LOGGER_NOTICE, "Error getting address for node");
		free(tcd);
		return TCPCON_ERROR;
	}
	r = conn_sslcon_new(destaddr, destaddrlen, tcd);
	if(r != 0) {
		logmsg(LOGGER_ERR, "Error starting connection to node %s", NODEINFO_INFO(desthostid).name);
		free(tcd);
		return TCPCON_ERROR;
	}
	return TCPCON_OK;
}

int tcpcon_newbnlpush(int desthostid) {
	struct tcpcon_data *tcd;
	int r;
	struct sockaddr *destaddr;
	socklen_t destaddrlen;
	if(tcpcon_checkExistingConn(desthostid, TCPCON_BNLPUSH, 0) || tcpcon_checkExistingConn(desthostid, TCPCON_BNLPULL, 1)) {
		logmsg(LOGGER_INFO, "BNL push already in progress");
		return TCPCON_OK;
	}
	tcd = malloc(sizeof(struct tcpcon_data));
	memset(tcd, 0, sizeof(struct tcpcon_data));
	tcd->conntype = TCPCON_BNLPUSH;
	tcd->connstate = TCPCON_STATE_NEW;
	tcd->peerid = desthostid;
	r = getnodeaddress(desthostid, &destaddr, &destaddrlen);
	if(r == NODEINFO_NOENT) {
		logmsg(LOGGER_NOTICE, "Cannot communicate with node %s - incompatable supported addresses", NODEINFO_INFO(desthostid).name);
		free(tcd);
		return TCPCON_ERROR;
	}
	if(r != NODEINFO_OK) {
		logmsg(LOGGER_NOTICE, "Error getting address for node");
		free(tcd);
		return TCPCON_ERROR;
	}
	r = conn_sslcon_new(destaddr, destaddrlen, tcd);
	if(r != 0) {
		logmsg(LOGGER_ERR, "Error starting connection to node %s", NODEINFO_INFO(desthostid).name);
		free(tcd);
		return TCPCON_ERROR;
	}
	return TCPCON_OK;
}

int tcpconHandleNegotiate(struct conn_sslcon *con) {
	struct tcpcon_data *tcd;
	int r;
	char randkeybuf[NEGOTIATE_CRYPTKEY_SIZE];
	char *sendbuf;
	int sendbuflen;
	struct negotiate_algo cryptalgo, compalgo;
	tcd = (struct tcpcon_data *)con->data;
	logmsg(LOGGER_DEBUG, "Starting negotiation handling - current state %d", tcd->connstate);
	// If the state is new or receiving the type (which means the type has just been received), generate the negotiation message, send it, and start receiving length
	if(tcd->connstate == TCPCON_STATE_RECEIVINGTYPE || tcd->connstate == TCPCON_STATE_NEW) {
		// Generate random key
		logmsg(LOGGER_DEBUG, "Generating random crypt key");
		r = RAND_bytes(randkeybuf, NEGOTIATE_CRYPTKEY_SIZE);
		if(r != 1) {
			logmsg(LOGGER_ERR, "Error generating random bytes");
			conn_closecon(con);
			return TCPCON_ERROR;
		}
		// Create the negotiation message
		logmsg(LOGGER_DEBUG, "Creating negotiation message");
		r = tcpcon_makeallocnegotiatemsg(con->peerid, randkeybuf, &tcd->sentnegmsg);
		if(r != TCPCON_OK) {
			logmsg(LOGGER_ERR, "Error generating random bytes");
			conn_closecon(con);
			return TCPCON_ERROR;
		}
		// If we're a client, send the command, the length, then the data, otherwise send the length and data
		logmsg(LOGGER_DEBUG, "Queueing data to send");
		if(!con->isserver) {
			sendbuf = malloc(1 + sizeof(int) + sizeof(struct negotiate_msg));
			sendbuf[0] = TCPCON_NEGOTIATION;
			*(int *)(sendbuf + 1) = htonl(sizeof(struct negotiate_msg));
			memcpy(sendbuf + 1 + sizeof(int), tcd->sentnegmsg, sizeof(struct negotiate_msg));
			sendbuflen = 1 + sizeof(int) + sizeof(struct negotiate_msg);
		} else {
			sendbuf = malloc(sizeof(int) + sizeof(struct negotiate_msg));
			*(int *)(sendbuf) = htonl(sizeof(struct negotiate_msg));
			memcpy(sendbuf + sizeof(int), tcd->sentnegmsg, sizeof(struct negotiate_msg));
			sendbuflen = sizeof(int) + sizeof(struct negotiate_msg);
		}
		// Send the negotiation data
		con->sendbuf = sendbuf;
		con->sendpos = sendbuf;
		con->sendlen = sendbuflen;
		// Next thing to do is to receive the length.  Set the recv buffer to do that, and change the state.
		free(con->recvbuf);
		con->recvbuf = malloc(sizeof(int));
		con->recvpos = con->recvbuf;
		con->recvlen = sizeof(int);
		tcd->connstate = TCPCON_STATE_RECEIVINGLENGTH;
		// Done for now ...
		return TCPCON_OK;
	}
	// If the state is receiving length, receive the length, make sure it matches the expected, then start receiving the data
	if(tcd->connstate == TCPCON_STATE_RECEIVINGLENGTH) {
		// Make sure it was received - otherwise, return and spin
		if(!conn_sslcon_hasfullrecv(con)) return TCPCON_OK;
		logmsg(LOGGER_DEBUG, "Received length from peer");
		// Make sure the received length matches the length of the negotiation struct
		if(ntohl(*(int *)(con->recvbuf)) != sizeof(struct negotiate_msg)) {
			logmsg(LOGGER_ERR, "Remote host sent invalid negotiation length");
			conn_closecon(con);
			return TCPCON_ERROR;
		}
		// Set up to receive negotiation data
		free(con->recvbuf);
		con->recvbuf = malloc(sizeof(struct negotiate_msg));
		con->recvpos = con->recvbuf;
		con->recvlen = sizeof(struct negotiate_msg);
		tcd->connstate = TCPCON_STATE_RECEIVINGDATA;
		// Done for now ...
		return TCPCON_OK;
	}
	// If the state is receiving data, receive it and process it
	if(tcd->connstate == TCPCON_STATE_RECEIVINGDATA) {
		// Make sure it was received - otherwise, return and spin
		if(!conn_sslcon_hasfullrecv(con)) {
			logmsg(LOGGER_DEBUG, "Received %d bytes of data so far", con->recvpos - con->recvbuf);
			return TCPCON_OK;
		}
		logmsg(LOGGER_DEBUG, "Received negotiation data - performing calculations");
		// Calculate the negotiated stuffs
		r = tcpcon_doNegotiateCalc(tcd->sentnegmsg, (struct negotiate_msg *)con->recvbuf, &cryptalgo, &compalgo, randkeybuf);
		if(r != TCPCON_OK) {
			logmsg(LOGGER_ERR, "Negotiation failed.");
			conn_closecon(con);
			return TCPCON_ERROR;
		}
		// Update the nodeinfo entry with the newly negotiated stuff
		NODEINFO_INFO(con->peerid).cryptalgo = cryptalgo.algoid;
		NODEINFO_INFO(con->peerid).cryptkeybits = cryptalgo.level;
		NODEINFO_INFO(con->peerid).compalgo = compalgo.algoid;
		NODEINFO_INFO(con->peerid).complevel = compalgo.level;
		memset(NODEINFO_INFO(con->peerid).cryptkey, 0, CRYPT_MAXKEYBITS / 8);
		memcpy(NODEINFO_INFO(con->peerid).cryptkey, randkeybuf, (CRYPT_MAXKEYBITS / 8 > NEGOTIATE_CRYPTKEY_SIZE) ? NEGOTIATE_CRYPTKEY_SIZE : (CRYPT_MAXKEYBITS / 8));
		NODEINFO_INFO(con->peerid).negotiated = 1;
		seqnum_init_state(&NODEINFO_INFO(con->peerid).seqnum);
		NODEINFO_INFO(con->peerid).sendseqnum = 1;
		r = nodeinfo_saverecord(con->peerid);
		if(r != NODEINFO_OK) {
			logmsg(LOGGER_ERR, "Error saving nodeinfo record");
		}
		logmsg(LOGGER_DEBUG, "Negotiation updated locally");
		// If the stuff we're sending is sent, we're done - close the connection.  Otherwise, set state to waiting for close.
		if(conn_sslcon_issent(con)) {
			logmsg(LOGGER_INFO, "Negotiation complete.");
			conn_closecon(con);
			return TCPCON_OK;
		} else {
			tcd->connstate = TCPCON_STATE_WAITFORSEND;
			return TCPCON_OK;
		}
	}
	// If we're waiting for a send, keep spinning until the data is sent
	if(tcd->connstate == TCPCON_STATE_WAITFORSEND) {
		if(!conn_sslcon_issent(con)) return TCPCON_OK;
		logmsg(LOGGER_INFO, "Negotiation complete.");
		conn_closecon(con);
		return TCPCON_OK;
	}
	// Any other state shouldn't happen
	logmsg(LOGGER_ERR, "Invalid state - see developers.");
	return TCPCON_ERROR;
}

int tcpconHandleBnlTransfer(struct conn_sslcon *con, char ispull) {
	struct tcpcon_data *tcd;
	int r;
	char *sendbuf;
	int sendbuflen;
	int recvlen;
	int myts;
	struct negotiate_algo cryptalgo, compalgo;
	char *cbnl, *cbnldata;
	int cbnllen;
	unsigned int cbnldatalen;
	tcd = (struct tcpcon_data *)con->data;
	logmsg(LOGGER_DEBUG, "Starting bnl transfer handling as ispull=%d isserver=%d - current state %d", ispull, con->isserver, tcd->connstate);
	// This is an asymmetric operation - do different things depending on if it's a client or server
	if((con->isserver && ispull) || (!con->isserver && !ispull)) {
		// It's a server
		// New connection - receive the minimum timestamp
		if(tcd->connstate == TCPCON_STATE_RECEIVINGTYPE || tcd->connstate == TCPCON_STATE_NEW) {
			logmsg(LOGGER_DEBUG, "transferbnl - receiving the min timestamp");
			// If we're a client (and it's a push), send the command first
			if(!con->isserver) {
				free(con->sendbuf);
				con->sendbuf = malloc(1);
				con->sendbuf[0] = TCPCON_BNLPUSH;
				con->sendpos = con->sendbuf;
				con->sendlen = 1;
			}
			// First receive the minimum timestamp
			free(con->recvbuf);
			con->recvbuf = malloc(sizeof(int));
			con->recvpos = con->recvbuf;
			con->recvlen = sizeof(int);
			tcd->connstate = TCPCON_STATE_RECEIVINGDATA;
			return TCPCON_OK;
		}
		// Receiving the minimum timestamp
		if(tcd->connstate == TCPCON_STATE_RECEIVINGDATA) {
			// Make sure it was received
			if(!conn_sslcon_hasfullrecv(con)) {
				logmsg(LOGGER_DEBUG, "Received %d bytes of data so far", con->recvpos - con->recvbuf);
				return TCPCON_OK;
			}
			logmsg(LOGGER_DEBUG, "transferbnl - received min timestamp");
			// If it's later than the timestamp we have, just send a length of 0 and wait for the send - otherwise send the BNL
			myts = getbnltimestamp(SIG_DATA(bnl_current));
			if(ntohl(*(int *)con->recvbuf) >= myts) {
				logmsg(LOGGER_DEBUG, "transferbnl - timestamp is later or equal to ours - not sending bnl");
				free(con->recvbuf);
				con->recvbuf = NULL;
				con->recvpos = NULL;
				con->recvlen = 0;
				free(con->sendbuf);
				con->sendbuf = malloc(sizeof(int));
				*(int *)con->sendbuf = 0;
				con->sendpos = con->sendbuf;
				con->sendlen = sizeof(int);
				tcd->connstate = TCPCON_STATE_WAITFORSEND;
				return TCPCON_OK;
			} else {
				logmsg(LOGGER_DEBUG, "transferbnl - sending bnl");
				// Create a send buffer with the length and the BNL
				sendbuf = malloc(sizeof(int) + bnl_current_len);
				sendbuflen = sizeof(int) + bnl_current_len;
				*(int *)sendbuf = htonl(bnl_current_len);
				memcpy(sendbuf + sizeof(int), bnl_current, bnl_current_len);
				free(con->recvbuf);
				con->recvbuf = NULL;
				con->recvpos = NULL;
				con->recvlen = 0;
				free(con->sendbuf);
				con->sendbuf = sendbuf;
				con->sendpos = con->sendbuf;
				con->sendlen = sendbuflen;
				tcd->connstate = TCPCON_STATE_WAITFORSEND;
				return TCPCON_OK;
			}
		}
		// Waiting for data to be sent
		if(tcd->connstate == TCPCON_STATE_WAITFORSEND) {
			if(!conn_sslcon_issent(con)) return TCPCON_OK;
			logmsg(LOGGER_INFO, "transferbnl - complete");
			conn_closecon(con);
			return TCPCON_OK;
		}
		// Invalid state
		logmsg(LOGGER_ERR, "Invalid state - see developers.");
		return TCPCON_ERROR;
	} else {
		// It's the client on a pull or server on a push
		// New connection - send the min timestamp
		if(tcd->connstate == TCPCON_STATE_RECEIVINGTYPE || tcd->connstate == TCPCON_STATE_NEW) {
			logmsg(LOGGER_DEBUG, "transferbnl - sending type, min timestamp and receiving length");
			myts = getbnltimestamp(SIG_DATA(bnl_current));
			free(con->recvbuf);
			free(con->sendbuf);
			con->sendbuf = malloc(sizeof(int) + 1);
			con->sendpos = con->sendbuf;
			con->sendlen = sizeof(int);
			if(!con->isserver) {
				con->sendlen++;
				con->sendbuf[0] = TCPCON_BNLPULL;
				*(int *)(con->sendbuf + 1) = htonl(myts);
			} else {
				*(int *)(con->sendbuf) = htonl(myts);
			}
			// Receive the length of the response
			con->recvbuf = malloc(sizeof(int));
			con->recvpos = con->recvbuf;
			con->recvlen = sizeof(int);
			tcd->connstate = TCPCON_STATE_RECEIVINGLENGTH;
			return TCPCON_OK;
		}
		// Receiving the length
		if(tcd->connstate == TCPCON_STATE_RECEIVINGLENGTH) {
			// Make sure it was received - otherwise, return and spin
			if(!conn_sslcon_hasfullrecv(con)) return TCPCON_OK;
			recvlen = ntohl(*(int *)con->recvbuf);
			logmsg(LOGGER_DEBUG, "Received length from peer: %d", recvlen);
			free(con->recvbuf);
			con->recvbuf = NULL;
			con->recvlen = 0;
			// If it's zero, there's no BNL, and the connection should be closed
			if(recvlen == 0) {
				logmsg(LOGGER_DEBUG, "Received no BNL");
				conn_closecon(con);
				return TCPCON_OK;
			}
			// Make sure the length is reasonable
			if(recvlen > MAXRECVBNL || recvlen < BNL_MINLEN) {
				logmsg(LOGGER_ERR, "Received BNL wrong size");
				conn_closecon(con);
				return TCPCON_ERROR;
			}
			// Set up to receive a BNL of that size
			con->recvbuf = malloc(recvlen);
			con->recvpos = con->recvbuf;
			con->recvlen = recvlen;
			tcd->connstate = TCPCON_STATE_RECEIVINGDATA;
			return TCPCON_OK;
		}
		// Receiving the BNL
		if(tcd->connstate == TCPCON_STATE_RECEIVINGDATA) {
			// Make sure it was received - otherwise, return and spin
			if(!conn_sslcon_hasfullrecv(con)) return TCPCON_OK;
			logmsg(LOGGER_DEBUG, "Received BNL - processing");
			// Make sure the timestamp really is newer
			cbnl = con->recvbuf;
			cbnllen = con->recvlen;
			if(getbnltimestamp(SIG_DATA(cbnl)) <= getbnltimestamp(SIG_DATA(bnl_current))) {
				logmsg(LOGGER_ERR, "Received timestamp too old");
				conn_closecon(con);
				return TCPCON_ERROR;
			}
			// Verify the BNL and extract the data
			r = handleNewBNL(cbnl, cbnllen);
			if(r != NODEINFO_OK) {
				logmsg(LOGGER_ERR, "Error receiving BNL");
				conn_closecon(con);
				return TCPCON_ERROR;
			}
			free(con->recvbuf);
			con->recvbuf = NULL;
			con->recvlen = 0;
			conn_closecon(con);
			return TCPCON_OK;
		}
		logmsg(LOGGER_ERR, "Invalid state - see developers.");
		return TCPCON_ERROR;
	}
}

int tcpconHandleBnlpull(struct conn_sslcon *con) {
	return tcpconHandleBnlTransfer(con, 1);
}

int tcpconHandleBnlpush(struct conn_sslcon *con) {
	return tcpconHandleBnlTransfer(con, 0);
}

/*int tcpconHandleBnlpull(struct conn_sslcon *con) {
	struct tcpcon_data *tcd;
	int r;
	char *sendbuf;
	int sendbuflen;
	int recvlen;
	int myts;
	struct negotiate_algo cryptalgo, compalgo;
	char *cbnl, *cbnldata;
	int cbnllen;
	unsigned int cbnldatalen;
	tcd = (struct tcpcon_data *)con->data;
	logmsg(LOGGER_DEBUG, "Starting bnlpull handling as isserver=%d - current state %d", con->isserver, tcd->connstate);
	// This is an asymmetric operation - do different things depending on if it's a client or server
	if(con->isserver) {
		// It's a server
		// New connection - receive the minimum timestamp
		if(tcd->connstate == TCPCON_STATE_RECEIVINGTYPE || tcd->connstate == TCPCON_STATE_NEW) {
			logmsg(LOGGER_DEBUG, "pullbnlserver - receiving the min timestamp");
			// First receive the minimum timestamp
			free(con->recvbuf);
			con->recvbuf = malloc(sizeof(int));
			con->recvpos = con->recvbuf;
			con->recvlen = sizeof(int);
			tcd->connstate = TCPCON_STATE_RECEIVINGDATA;
			return TCPCON_OK;
		}
		// Receiving the minimum timestamp
		if(tcd->connstate == TCPCON_STATE_RECEIVINGDATA) {
			// Make sure it was received
			if(!conn_sslcon_hasfullrecv(con)) {
				logmsg(LOGGER_DEBUG, "Received %d bytes of data so far", con->recvpos - con->recvbuf);
				return TCPCON_OK;
			}
			logmsg(LOGGER_DEBUG, "pullbnlserver - received min timestamp");
			// If it's later than the timestamp we have, just send a length of 0 and wait for the send - otherwise send the BNL
			myts = getbnltimestamp(SIG_DATA(bnl_current));
			if(ntohl(*(int *)con->recvbuf) >= myts) {
				logmsg(LOGGER_DEBUG, "pullbnlserver - timestamp is later or equal to ours - not sending bnl");
				free(con->recvbuf);
				con->recvbuf = NULL;
				con->recvpos = NULL;
				con->recvlen = 0;
				free(con->sendbuf);
				con->sendbuf = malloc(sizeof(int));
				*(int *)con->sendbuf = 0;
				con->sendpos = con->sendbuf;
				con->sendlen = sizeof(int);
				tcd->connstate = TCPCON_STATE_WAITFORSEND;
				return TCPCON_OK;
			} else {
				logmsg(LOGGER_DEBUG, "pullbnlserver - sending bnl");
				// Create a send buffer with the length and the BNL
				sendbuf = malloc(sizeof(int) + bnl_current_len);
				sendbuflen = sizeof(int) + bnl_current_len;
				*(int *)sendbuf = htonl(bnl_current_len);
				memcpy(sendbuf + sizeof(int), bnl_current, bnl_current_len);
				free(con->recvbuf);
				con->recvbuf = NULL;
				con->recvpos = NULL;
				con->recvlen = 0;
				free(con->sendbuf);
				con->sendbuf = sendbuf;
				con->sendpos = con->sendbuf;
				con->sendlen = sendbuflen;
				tcd->connstate = TCPCON_STATE_WAITFORSEND;
				return TCPCON_OK;
			}
		}
		// Waiting for data to be sent
		if(tcd->connstate == TCPCON_STATE_WAITFORSEND) {
			if(!conn_sslcon_issent(con)) return TCPCON_OK;
			logmsg(LOGGER_INFO, "pullbnlserver - complete");
			conn_closecon(con);
			return TCPCON_OK;
		}
		// Invalid state
		logmsg(LOGGER_ERR, "Invalid state - see developers.");
		return TCPCON_ERROR;
	} else {
		// It's the client
		// New connection - send the min timestamp
		if(tcd->connstate == TCPCON_STATE_RECEIVINGTYPE || tcd->connstate == TCPCON_STATE_NEW) {
			logmsg(LOGGER_DEBUG, "pullbnlclient - sending type, min timestamp and receiving length");
			myts = getbnltimestamp(SIG_DATA(bnl_current));
			free(con->recvbuf);
			free(con->sendbuf);
			con->sendbuf = malloc(sizeof(int) + 1);
			con->sendpos = con->sendbuf;
			con->sendlen = sizeof(int) + 1;
			con->sendbuf[0] = TCPCON_BNLPULL;
			*(int *)(con->sendbuf + 1) = htonl(myts);
			// Receive the length of the response
			con->recvbuf = malloc(sizeof(int));
			con->recvpos = con->recvbuf;
			con->recvlen = sizeof(int);
			tcd->connstate = TCPCON_STATE_RECEIVINGLENGTH;
			return TCPCON_OK;
		}
		// Receiving the length
		if(tcd->connstate == TCPCON_STATE_RECEIVINGLENGTH) {
			// Make sure it was received - otherwise, return and spin
			if(!conn_sslcon_hasfullrecv(con)) return TCPCON_OK;
			recvlen = ntohl(*(int *)con->recvbuf);
			logmsg(LOGGER_DEBUG, "Received length from peer: %d", recvlen);
			free(con->recvbuf);
			con->recvbuf = NULL;
			con->recvlen = 0;
			// If it's zero, there's no BNL, and the connection should be closed
			if(recvlen == 0) {
				logmsg(LOGGER_DEBUG, "Received no BNL");
				conn_closecon(con);
				return TCPCON_OK;
			}
			// Make sure the length is reasonable
			if(recvlen > MAXRECVBNL || recvlen < BNL_MINLEN) {
				logmsg(LOGGER_ERR, "Received BNL wrong size");
				conn_closecon(con);
				return TCPCON_ERROR;
			}
			// Set up to receive a BNL of that size
			con->recvbuf = malloc(recvlen);
			con->recvpos = con->recvbuf;
			con->recvlen = recvlen;
			tcd->connstate = TCPCON_STATE_RECEIVINGDATA;
			return TCPCON_OK;
		}
		// Receiving the BNL
		if(tcd->connstate == TCPCON_STATE_RECEIVINGDATA) {
			// Make sure it was received - otherwise, return and spin
			if(!conn_sslcon_hasfullrecv(con)) return TCPCON_OK;
			logmsg(LOGGER_DEBUG, "Received BNL - processing");
			// Make sure the timestamp really is newer
			cbnl = con->recvbuf;
			cbnllen = con->recvlen;
			if(getbnltimestamp(SIG_DATA(cbnl)) <= getbnltimestamp(SIG_DATA(bnl_current))) {
				logmsg(LOGGER_ERR, "Received timestamp too old");
				conn_closecon(con);
				return TCPCON_ERROR;
			}
			// Verify the BNL and extract the data
			r = handleNewBNL(cbnl, cbnllen);
			if(r != NODEINFO_OK) {
				logmsg(LOGGER_ERR, "Error receiving BNL");
				conn_closecon(con);
				return TCPCON_ERROR;
			}
			free(con->recvbuf);
			con->recvbuf = NULL;
			con->recvlen = 0;
			conn_closecon(con);
			return TCPCON_OK;
		}
		logmsg(LOGGER_ERR, "Invalid state - see developers.");
		return TCPCON_ERROR;
	}
}*/

int tcpcon_handleevent(struct conn_sslcon *con) {
	struct tcpcon_data *tcd;
	logmsg(LOGGER_DEBUG, "Starting tcp event handling");
	// If the connection is closed/closing, free up any data it might have.
	if(con->state == CONNECTION_STATE_SSLCLOSING || con->state == CONNECTION_STATE_CLOSED) {
		if(con->data) {
			tcpcon_freeconndata((struct tcpcon_data *)con->data);
			free(con->data);
			con->data = NULL;
		}
		return TCPCON_OK;
	}
	// If the connection is pre-connected, do nothing.
	if(con->state == CONNECTION_STATE_TCPCONNECTING || con->state == CONNECTION_STATE_SSLCONNECTING) return TCPCON_OK;
	// Make sure the state is connected, as expected.
	if(con->state != CONNECTION_STATE_CONNECTED) {
		logmsg(LOGGER_ERR, "Unknown connection state - see developers");
		return TCPCON_ERROR;
	}
	// If we're the client and we have no data, something is off ...
	if(!con->isserver && !con->data) {
		logmsg(LOGGER_ERR, "Client connection has no data - see developers");
		return TCPCON_ERROR;
	}
	tcd = (struct tcpcon_data *)con->data;
	// If we're a client making an outgoing connection, make sure the peer id is the one we're expecting
	if(!con->isserver) if(tcd->peerid != con->peerid) {
		logmsg(LOGGER_NOTICE, "Peer ID mismatch - We want id %d and they are id %d", tcd->peerid, con->peerid);
		conn_closecon(con);
		return TCPCON_ERROR;
	}
	// If we already know the connection type, branch off into the function handling that type
	if(tcd) if(tcd->conntype != TCPCON_NONE) {
		if(tcd->conntype == TCPCON_NEGOTIATION) {
			return tcpconHandleNegotiate(con);
		}
		if(tcd->conntype == TCPCON_BNLPULL) {
			return tcpconHandleBnlpull(con);
		}
		if(tcd->conntype == TCPCON_BNLPUSH) {
			return tcpconHandleBnlpush(con);
		}
		logmsg(LOGGER_ERR, "Unknown connection type - see developers");
		return TCPCON_ERROR;
	}
	// If it's a client that doesn't know the type, something is wrong
	if(!con->isserver && tcd->conntype == TCPCON_NONE) {
		logmsg(LOGGER_ERR, "Client connection has no type - see developers");
		return TCPCON_ERROR;
	}
	// At this point, the connection must be as a server
	// If there's no data, it must be newly connected - allocate a new data for the server connection
	if(!tcd) {
		// Allocate and initialize the data structure
		tcd = malloc(sizeof(struct tcpcon_data));
		memset(tcd, 0, sizeof(struct tcpcon_data));
		tcd->conntype = TCPCON_NONE;
		tcd->connstate = TCPCON_STATE_RECEIVINGTYPE;
		tcd->peerid = con->peerid;
		// Set up buffer to receive one byte of type
		con->recvbuf = malloc(1);
		con->recvpos = con->recvbuf;
		con->recvlen = 1;
		// Set data to tcd
		con->data = tcd;
		// Return
		return TCPCON_OK;
	}
	// It's a server, there's already data, but there's no type ... check to be sure that the state is receiving type - it should be
	if(tcd->connstate != TCPCON_STATE_RECEIVINGTYPE) {
		logmsg(LOGGER_ERR, "State inconsistency - see developers");
		return TCPCON_ERROR;
	}
	// If we haven't received the type yet, just return ... do nothing.
	if(!conn_sslcon_hasfullrecv(con)) return TCPCON_OK;
	// We have received the type.  Free and reset the receive buffer, set the type to the type received, leave the state the way it is, and call the relevant routine
	tcd->conntype = con->recvbuf[0];
	free(con->recvbuf);
	con->recvbuf = NULL;
	con->recvpos = NULL;
	con->recvlen = 0;
	if(tcd->conntype == TCPCON_NEGOTIATION) {
		return tcpconHandleNegotiate(con);
	}
	if(tcd->conntype == TCPCON_BNLPULL) {
		return tcpconHandleBnlpull(con);
	}
	if(tcd->conntype == TCPCON_BNLPUSH) {
		return tcpconHandleBnlpush(con);
	}
	// Unknown type received
	logmsg(LOGGER_NOTICE, "Received unknown connection type from node %s", NODEINFO_INFO(con->peerid).name);
	tcpcon_freeconndata((struct tcpcon_data *)con->data);
	free(con->data);
	con->data = NULL;
	conn_closecon(con);
	return TCPCON_ERROR;
}


