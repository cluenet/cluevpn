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
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <time.h>
#include "connections.h"
#include "tunio.h"
#include "logger.h"
#include "nodeinfo.h"
#include "configfile.h"

struct in6_addr in6addr_none = { {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} };
struct in_addr inaddr_none = { 0 };
struct in6_addr in6addr_ip4conv = { {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0} };

struct conn_udpsock conn_udpcon;
struct conn_tun conn_tuncon;
struct conn_sslserv conn_sslservsock;
struct conn_sslcon *conn_sslcons;
int conn_numsslcons;

SSL_CTX *conn_sslctx;

char tundevname[256];

#define MAX(a, b) ((a > b) ? a : b)

void conn_log_ssl_err_queue(int level) {
	unsigned long err;
	while((err = ERR_get_error()) != 0) logmsg(level, "SSL error: %s", ERR_error_string(err, NULL));
}

int conn_tun_init() {
	int fd;
	tundevname[0] = 0;
	if(global_config.devname) strcpy(tundevname, global_config.devname);
	fd = tunio_open(tundevname);
	if(fd < 0) return -1;
	fcntl(fd, F_SETFL, O_NONBLOCK);
	conn_tuncon.fd = fd;
	conn_tuncon.sendbuf = NULL;
	conn_tuncon.sendbuflen = 0;
	conn_tuncon.recvbuf = NULL;
	conn_tuncon.recvbuflen = 0;
	conn_tuncon.recvbufsize = 0;
	return 0;
}

void conn_tun_close() {
	if(conn_tuncon.fd >= 0) close(conn_tuncon.fd);
}

int conn_udpcon_init() {
	int fd, r;
	struct sockaddr_in6 baddr;
	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if(fd == -1) {
		logmsg(LOGGER_WARNING, "socket(): %s", strerror(errno));
		return -1;
	}
	fcntl(fd, F_SETFL, O_NONBLOCK);
	memset(&baddr, 0, sizeof(baddr));
	baddr.sin6_family = AF_INET6;
	baddr.sin6_port = htons(global_config.port);
	baddr.sin6_addr = in6addr_any;
	baddr.sin6_scope_id = 0;
	r = bind(fd, (struct sockaddr *)&baddr, sizeof(baddr));
	if(r == -1) {
		close(fd);
		logmsg(LOGGER_WARNING, "bind(): %s", strerror(errno));
		return -1;
	}
	conn_udpcon.fd = fd;
	conn_udpcon.sendbuf = NULL;
	conn_udpcon.sendbuflen = 0;
	conn_udpcon.recvbuf = NULL;
	conn_udpcon.recvbuflen = 0;
	conn_udpcon.recvbufsize = 0;
	return 0;
}

void conn_udpcon_close() {
	if(conn_udpcon.fd >= 0) close(conn_udpcon.fd);
}

int conn_sslserv_init() {
	int r, fd, yes = 1;
	struct sockaddr_in6 baddr;
	fd = socket(AF_INET6, SOCK_STREAM, 0);
	if(fd == -1) {
		logmsg(LOGGER_WARNING, "socket(): %s", strerror(errno));
		return -1;
	}
	fcntl(fd, F_SETFL, O_NONBLOCK);
	r = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
	if(r == -1) {
		close(fd);
		logmsg(LOGGER_WARNING, "setsockopt(): %s", strerror(errno));
		return -1;
	}
	memset(&baddr, 0, sizeof(baddr));
	baddr.sin6_family = AF_INET6;
	baddr.sin6_port = htons(global_config.port);
	baddr.sin6_addr = in6addr_any;
	baddr.sin6_scope_id = 0;
	r = bind(fd, (struct sockaddr *)&baddr, sizeof(baddr));
	if(r == -1) {
		close(fd);
		logmsg(LOGGER_WARNING, "bind(): %s", strerror(errno));
		return -1;
	}
	r = listen(fd, TCP_BACKLOG);
	if(r == -1) {
		close(fd);
		logmsg(LOGGER_WARNING, "listen(): %s", strerror(errno));
		return -1;
	}
	conn_sslservsock.fd = fd;
	return 0;
}

void conn_sslserv_close() {
	close(conn_sslservsock.fd);
}

int conn_sslcons_init() {
	conn_sslcons = NULL;
	conn_numsslcons = 0;
	return 0;
}

void conn_sslconlist_delete(sslcon_t n) {
	struct conn_sslcon *ccon;
	logmsg(LOGGER_INFO, "Deleting connection from list: %p", n);
	if(conn_sslcons == n) {
		conn_sslcons = n->next;
		free(n);
	} else {
		for(ccon = conn_sslcons; ccon; ccon = ccon->next) {
			if(ccon->next == n) {
				ccon->next = n->next;
				free(n);
				break;
			}
		}
	}
	conn_numsslcons--;
}

void conn_sslconlist_add(sslcon_t n) {
	sslcon_t newn;
	newn = malloc(sizeof(struct conn_sslcon));
	memcpy(newn, n, sizeof(struct conn_sslcon));
	newn->next = conn_sslcons;
	conn_sslcons = newn;
	conn_numsslcons++;
	logmsg(LOGGER_DEBUG, "Added new connection to list: %p", newn);
}

void conn_sslcon_free(sslcon_t n) {
	free(n->data);
	free(n->sendbuf);
	free(n->recvbuf);
	//printf("BIOFREEBIOBIOBIO %p\n", n->sslbio);
	//if(n->sslbio) BIO_free(n->sslbio);   SSL_free will free the BIO
	if(n->ssl) SSL_free(n->ssl);
	if(n->peercert) X509_free(n->peercert);
	if(n->state != CONNECTION_STATE_CLOSED) close(n->fd);
	n->data = NULL;
	n->sendbuf = NULL;
	n->recvbuf = NULL;
	n->ssl = NULL;
	n->sslbio = NULL;
	n->peercert = NULL;
}

void conn_sslcons_close() {
	struct conn_sslcon *ccon;
	struct conn_sslcon *ncon;
	for(ccon = conn_sslcons; ccon; ccon = ncon) {
		ncon = ccon->next;
		conn_sslcon_free(ccon);
		free(ccon);
	}
}

void conn_sslcons_cleanupclosed() {
	struct conn_sslcon *ccon, *ncon, *fcon;
	// First try to cleanup everything but the head
	for(ccon = conn_sslcons; ccon; ccon = ncon) {
		if(!ccon->next) break;
		if(ccon->next->state == CONNECTION_STATE_CLOSED) {
			logmsg(LOGGER_INFO, "Deleting connection from list: %p", ccon->next);
			ncon = ccon;
			conn_sslcon_free(ccon->next);
			fcon = ccon->next;
			ccon->next = ccon->next->next;
			free(fcon);
			conn_numsslcons--;
		} else {
			ncon = ccon->next;
		}
	}
	// Now, if the head is closed, fix that
	if(conn_sslcons) if(conn_sslcons->state == CONNECTION_STATE_CLOSED) {
		logmsg(LOGGER_INFO, "Deleting connection from list: %p", conn_sslcons);
		fcon = conn_sslcons;
		conn_sslcons = conn_sslcons->next;
		conn_sslcon_free(fcon);
		free(fcon);
		conn_numsslcons--;
	}
}

int conn_initsocks() {
	int r;
	logmsg(LOGGER_INFO, "Initializing tun");
	r = conn_tun_init();
	if(r != 0) return r;
	logmsg(LOGGER_INFO, "Initializing UDP");
	r = conn_udpcon_init();
	if(r != 0) {
		conn_tun_close();
		return r;
	}
	logmsg(LOGGER_INFO, "Initializing SSL server socket");
	r = conn_sslserv_init();
	if(r != 0) {
		conn_tun_close();
		conn_udpcon_close();
		return r;
	}
	logmsg(LOGGER_INFO, "Initializing SSL connection list");
	r = conn_sslcons_init();
	if(r != 0) {
		conn_tun_close();
		conn_udpcon_close();
		conn_sslserv_close();
		return r;
	}
	return 0;
}

void conn_closesocks() {
	conn_tun_close();
	conn_udpcon_close();
	conn_sslserv_close();
	conn_sslcons_close();
}

int conn_initssl() {
	int r;
	// Initialize the main library
	SSL_library_init();
	// Load the string representations of errors
	SSL_load_error_strings();
	// Initialize the context
	conn_sslctx = SSL_CTX_new(SSLv23_method());
	if(!conn_sslctx) {
		logmsg(LOGGER_CRIT, "Error in SSL_CTX_new()");
		ERR_free_strings();
		return -1;
	}
	// Load our certificate
	r = SSL_CTX_use_certificate_chain_file(conn_sslctx, global_config.cert);
	if(r != 1) {
		logmsg(LOGGER_CRIT, "Error loading certificate: %s", ERR_error_string(ERR_get_error(), NULL));
		ERR_free_strings();
		SSL_CTX_free(conn_sslctx);
		return -1;
	}
	// Load our private key
	r = SSL_CTX_use_PrivateKey_file(conn_sslctx, global_config.privkey, SSL_FILETYPE_PEM);
	if(r != 1) {
		logmsg(LOGGER_CRIT, "Error loading private key: %s", ERR_error_string(ERR_get_error(), NULL));
		ERR_free_strings();
		SSL_CTX_free(conn_sslctx);
		return -1;
	}
	// Load CA file
	r = SSL_CTX_load_verify_locations(conn_sslctx, global_config.cacert, NULL);
	if(r != 1) {
		logmsg(LOGGER_CRIT, "Error loading CA certificate: %s", ERR_error_string(ERR_get_error(), NULL));
		ERR_free_strings();
		SSL_CTX_free(conn_sslctx);
		return -1;
	}
	// Set session ID
	r = SSL_CTX_set_session_id_context(conn_sslctx, "cluevpn", strlen("cluevpn"));
	if(r != 1) {
		logmsg(LOGGER_CRIT, "Error setting session ID: %s", ERR_error_string(ERR_get_error(), NULL));
		ERR_free_strings();
		SSL_CTX_free(conn_sslctx);
		return -1;
	}
	// Set the certificate verification defaults to verify both client and server
	SSL_CTX_set_verify(conn_sslctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_CLIENT_ONCE, NULL);
	SSL_CTX_set_verify_depth(conn_sslctx, 5);
	// All done - return 0 for success
	return 0;
}

void conn_closessl() {
	ERR_free_strings();
	SSL_CTX_free(conn_sslctx);
}

char *conn_getcommonname(X509 *peercert) {
	static char cnbuf[256];
	X509_NAME *xname;
	int r;
	xname = X509_get_subject_name(peercert);
	if(!xname) return NULL;
	r = X509_NAME_get_text_by_NID(xname, NID_commonName, cnbuf, 256);
	cnbuf[255] = 0;
	if(r < 1) return NULL;
	return cnbuf;
}

char *conn_getOUname(X509 *peercert) {
	static char cnbuf[256];
	X509_NAME *xname;
	int r;
	xname = X509_get_subject_name(peercert);
	if(!xname) {
		logmsg(LOGGER_INFO, "X509_get_subject_name() failed");
		return NULL;
	}
	r = X509_NAME_get_text_by_NID(xname, NID_organizationalUnitName, cnbuf, 256);
	cnbuf[255] = 0;
	if(r < 1) {
		logmsg(LOGGER_INFO, "X509_NAME_get_text_by_NID() failed");
		return NULL;
	}
	return &cnbuf[0];
}

int conn_sslcon_new(struct sockaddr *addr, socklen_t addrlen, void *data) {
	int fd;
	int r, i;
	struct conn_sslcon newcon;
	char addrstr[256];
	void *addrptr;
	fd = socket(addr->sa_family, SOCK_STREAM, 0);
	if(fd == -1) {
		logmsg(LOGGER_WARNING, "socket(): %s", strerror(errno));
		return -1;
	}
	fcntl(fd, F_SETFL, O_NONBLOCK);
	r = connect(fd, addr, addrlen);
	if(r != 0 && errno != EINPROGRESS) {
		logmsg(LOGGER_NOTICE, "connect(): %s", strerror(errno));
		return -1;
	}
	memset(&newcon, 0, sizeof(struct conn_sslcon));
	newcon.fd = fd;
	newcon.isserver = 0;
	newcon.peerid = -1;
	newcon.data = data;
	newcon.createtime = time(NULL);
	memcpy(&newcon.peeraddr, addr, addrlen);
	newcon.state = CONNECTION_STATE_TCPCONNECTING;
	// Log message
	addrstr[0] = 0;
	if(addr->sa_family == AF_INET) addrptr = &((struct sockaddr_in *)addr)->sin_addr; else addrptr = &((struct sockaddr_in6 *)addr)->sin6_addr;
	inet_ntop(addr->sa_family, addrptr, addrstr, 256);
	logmsg(LOGGER_INFO, "Creating new outgoing connection to %s", addrstr);
	// Add the new node to the set
	conn_sslconlist_add(&newcon);
	// Return success
	return 0;
}

int conn_sslcon_accept() {
	int fd;
	int r;
	struct conn_sslcon newcon;
	char addrstr[256];
	void *addrptr;
	socklen_t peeraddrlen;
	peeraddrlen = sizeof(newcon.peeraddr);
	memset(&newcon, 0, sizeof(newcon));
	fd = accept(conn_sslservsock.fd, (struct sockaddr *)&newcon.peeraddr, &peeraddrlen);
	if(fd == -1) {
		logmsg(LOGGER_WARNING, "accept(): %s", strerror(errno));
		return -1;
	}
	// Log message
	addrstr[0] = 0;
	if(((struct sockaddr *)&newcon.peeraddr)->sa_family == AF_INET) addrptr = &((struct sockaddr_in *)((struct sockaddr *)&newcon.peeraddr))->sin_addr; else addrptr = &((struct sockaddr_in6 *)((struct sockaddr *)&newcon.peeraddr))->sin6_addr;
	inet_ntop(((struct sockaddr *)&newcon.peeraddr)->sa_family, addrptr, addrstr, 256);
	logmsg(LOGGER_INFO, "Accepted incoming connection from %s", addrstr);
	// Create new item
	fcntl(fd, F_SETFL, O_NONBLOCK);
	newcon.fd = fd;
	newcon.isserver = 1;
	newcon.peerid = -1;
	newcon.data = NULL;
	newcon.createtime = time(NULL);
	newcon.state = CONNECTION_STATE_TCPCONNECTING;
	newcon.event = 1;
	// Add the new node to the set
	conn_sslconlist_add(&newcon);
	// Return success
	return 0;
}

void conn_sslcon_setsendbuf(sslcon_t con, char *data, int len) {
	con->sendbuf = data;
	con->sendpos = data;
	con->sendlen = len;
}

void conn_sslcon_setrecvbuf(sslcon_t con, char *buf, int buflen) {
	con->recvbuf = buf;
	con->recvpos = buf;
	con->recvlen = buflen;
}

void conn_setudptunbufs(char *udpsendbuf, char *udprecvbuf, int udprecvbuflen, char *tunsendbuf, char *tunrecvbuf, int tunrecvbuflen) {
	conn_udpcon.sendbuf = udpsendbuf;
	conn_udpcon.sendbuflen = 0;
	conn_udpcon.recvbuf = udprecvbuf;
	conn_udpcon.recvbuflen = 0;
	conn_udpcon.recvbufsize = udprecvbuflen;
	conn_tuncon.sendbuf = tunsendbuf;
	conn_tuncon.sendbuflen = 0;
	conn_tuncon.recvbuf = tunrecvbuf;
	conn_tuncon.recvbuflen = 0;
	conn_tuncon.recvbufsize = tunrecvbuflen;
}

int conn_closecon(struct conn_sslcon *con) {
	if(con->state == CONNECTION_STATE_TCPCONNECTING || con->state == CONNECTION_STATE_SSLCONNECTING) {
		close(con->fd);
		con->state = CONNECTION_STATE_CLOSED;
		return 0;
	}
	if(con->state == CONNECTION_STATE_SSLCLOSING || con->state == CONNECTION_STATE_CLOSED) return 0;
	if(con->state != CONNECTION_STATE_CONNECTED) {
		close(con->fd);
		con->state = CONNECTION_STATE_CLOSED;
		return 0;
	}
	con->ssl_want_read = 0;
	con->ssl_want_write = 1;
	con->state = CONNECTION_STATE_SSLCLOSING;
	return 0;
}

int conn_mainsendrecv(int timeout_ms) {
	static char addrstrbuf[128];
	struct timeval timeout;
	struct timeval *timeoutp = &timeout;
	static fd_set read_fds;
	static fd_set write_fds;
	char skipselect = 0;
	int maxfd, numretfd;
	sslcon_t ccon;
	int r, sslerr;
	int tcperr, tcperrsize;
	int peerhostid;
	char *peercn, *peerou;
	X509 *peercert;
	socklen_t recvaddrlen;
	time_t ctime = time(NULL);
	// Calculate the timeout value (in timeoutp)
	if(timeout_ms < 1) timeoutp = NULL; else {
		timeout.tv_sec = timeout_ms / 1000;
		timeout.tv_usec = (timeout_ms % 1000) * 1000;
	}
	// Initialize the FD sets
	FD_ZERO(&read_fds);
	FD_ZERO(&write_fds);
	maxfd = -1;
	// For UDP and tun, try to write to them if there's data in the send buffer
	if(conn_udpcon.sendbuflen > 0) {
		FD_SET(conn_udpcon.fd, &write_fds);
		maxfd = MAX(maxfd, conn_udpcon.fd);
	}
	if(conn_tuncon.sendbuflen > 0) {
		FD_SET(conn_tuncon.fd, &write_fds);
		maxfd = MAX(maxfd, conn_tuncon.fd);
	}
	// For UDP and tun, try to read from them if the receive buffer is empty
	if(conn_udpcon.recvbuf && conn_udpcon.recvbuflen <= 0 && conn_udpcon.recvbufsize > 0) {
		FD_SET(conn_udpcon.fd, &read_fds);
		maxfd = MAX(maxfd, conn_udpcon.fd);
	}
	if(conn_tuncon.recvbuf && conn_tuncon.recvbuflen <= 0 && conn_tuncon.recvbufsize > 0) {
		FD_SET(conn_tuncon.fd, &read_fds);
		maxfd = MAX(maxfd, conn_tuncon.fd);
	}
	// If there are fewer than the maximum number of connections, add the server socket to the read FD set
	if(conn_numsslcons < MAXSSLCONS) {
		FD_SET(conn_sslservsock.fd, &read_fds);
		maxfd = MAX(maxfd, conn_sslservsock.fd);
	}
	// For each TCP/SSL connection, add different things depending on the state
	for(ccon = conn_sslconlist_start(); ccon; ccon = conn_sslconlist_next(ccon)) {
		// Set event to 0 for each one
		ccon->event = 0;
		switch(ccon->state) {
			case CONNECTION_STATE_TCPCONNECTING:
				// Socket should be polled for writability to indicate end of TCP connection (if it's a client) - otherwise skip the select and advance immediately
				if(!ccon->isserver) {
					logmsg(LOGGER_DEBUG, "Client connection %p is in TCPCONNECTING state - checking for write", ccon);
					FD_SET(ccon->fd, &write_fds);
					maxfd = MAX(maxfd, ccon->fd);
				} else {
					logmsg(LOGGER_DEBUG, "Server connection %p is in TCPCONNECTING state - skipping select", ccon);
					skipselect = 1;
				}
				break;
			case CONNECTION_STATE_SSLCONNECTING:
			case CONNECTION_STATE_SSLCLOSING:
				logmsg(LOGGER_DEBUG, "Connection %p is SSL connecting or closing.  sslwantread=%d and sslwantwrite=%d", ccon, ccon->ssl_want_read, ccon->ssl_want_write);
				// Look for whatever SSL wants.  If SSL wants nothing, look for writability.
				if(ccon->ssl_want_read) {
					FD_SET(ccon->fd, &read_fds);
					maxfd = MAX(maxfd, ccon->fd);
				}
				if(ccon->ssl_want_write) {
					FD_SET(ccon->fd, &write_fds);
					maxfd = MAX(maxfd, ccon->fd);
				}
				if(!ccon->ssl_want_write && !ccon->ssl_want_read) {
					FD_SET(ccon->fd, &write_fds);
					maxfd = MAX(maxfd, ccon->fd);
				}
				break;
			case CONNECTION_STATE_CONNECTED:
				logmsg(LOGGER_DEBUG, "Connection %p is connected.  sslwantread=%d sslwantwrite=%d recvbuf=%p recvpos=%p recvlen=%d sendbuf=%p sendpos=%p sendlen=%d", ccon, ccon->ssl_want_read, ccon->ssl_want_write, ccon->recvbuf, ccon->recvpos, ccon->recvlen, ccon->sendbuf, ccon->sendpos, ccon->sendlen);
				// If SSL wants a read, or SSL wants a write, check for that
				if(ccon->ssl_want_read) {
					FD_SET(ccon->fd, &read_fds);
					maxfd = MAX(maxfd, ccon->fd);
				}
				if(ccon->ssl_want_write) {
					FD_SET(ccon->fd, &write_fds);
					maxfd = MAX(maxfd, ccon->fd);
				}
				// Check for reading first
				// If there's still more data to read, and there's data pending in the SSL buffer, read that data now, and set a flag to make select() timeout immediately
				if(ccon->recvbuf && ccon->recvlen > 0) if(ccon->recvbuf + ccon->recvlen > ccon->recvpos) {
					// Read in data pending in the SSL buffers if it exists
					if(SSL_pending(ccon->ssl) > 0) {
						r = SSL_read(ccon->ssl, ccon->recvpos, ccon->recvbuf + ccon->recvlen - ccon->recvpos);
						sslerr = SSL_get_error(ccon->ssl, r);
						if(r > 0) {
							ccon->recvpos += r;
							skipselect = 1;
							ccon->event = 1;
						} else if(r == 0) {
							close(ccon->fd);
							ccon->state = CONNECTION_STATE_CLOSED;
							ccon->event = 1;
							continue;
						} else if(sslerr == SSL_ERROR_WANT_READ) {
							ccon->ssl_want_read = 1;
							FD_SET(ccon->fd, &read_fds);
							maxfd = MAX(maxfd, ccon->fd);
						} else if(sslerr == SSL_ERROR_WANT_WRITE) {
							ccon->ssl_want_write = 1;
							FD_SET(ccon->fd, &write_fds);
							maxfd = MAX(maxfd, ccon->fd);
						} else {
							logmsg(LOGGER_ERR, "SSL Error: %s", ERR_error_string(sslerr, NULL));
							close(ccon->fd);
							ccon->state = CONNECTION_STATE_CLOSED;
							ccon->event = 1;
							continue;
						}
					}
					// If we want a read, and SSL wants neither reading nor writing, check for reading
					if(ccon->recvbuf + ccon->recvlen > ccon->recvpos) if(!ccon->ssl_want_write && !ccon->ssl_want_read) {
						FD_SET(ccon->fd, &read_fds);
						maxfd = MAX(maxfd, ccon->fd);
					}
				}
				// Check for writing
				if(ccon->sendbuf && ccon->sendlen > 0) if(ccon->sendbuf + ccon->sendlen > ccon->sendpos) {
					if(!ccon->ssl_want_write && !ccon->ssl_want_read) {
						FD_SET(ccon->fd, &write_fds);
						maxfd = MAX(maxfd, ccon->fd);
					}
				}
				break;
			case CONNECTION_STATE_CLOSED:
				break;
		}
	}
	// If we're skipping the select, set the timeout to 0
	if(skipselect) {
		timeoutp = &timeout;
		timeout.tv_sec = 0;
		timeout.tv_usec = 0;
	}
	// Run the select
	logmsg(LOGGER_DEBUG, "Running select()");
	r = select(maxfd + 1, &read_fds, &write_fds, NULL, timeoutp);
	logmsg(LOGGER_DEBUG, "select() finished");
	// If there was an error, return immediately and PANIC!!!!!!!!!!!!!!
	if(r < 0 && errno != EINTR) {
		logmsg(LOGGER_ERR, "select() error");
		return -1;
	}
	if(r < 0 && errno == EINTR) return 1;
	// Select is finished - check all the TCP connections first
	for(ccon = conn_sslconlist_start(); ccon; ccon = conn_sslconlist_next(ccon)) {
		if(FD_ISSET(ccon->fd, &write_fds) || FD_ISSET(ccon->fd, &read_fds)) {
			ccon->ssl_want_read = 0;
			ccon->ssl_want_write = 0;
		}
		// If the connection is past its maximum lifetime, kill it
		if(ctime - ccon->createtime > CONN_MAXLIFE) {
			logmsg(LOGGER_NOTICE, "Connection lifetime expired.");
			close(ccon->fd);
			ccon->state = CONNECTION_STATE_CLOSED;
			ccon->event = 1;
			continue;
		}
		switch(ccon->state) {
			case CONNECTION_STATE_TCPCONNECTING:
				// If this is a server socket, it's already accept()ed and can move on.  If it's a client socket, only move on if connect() completed
				if(!ccon->isserver) {
					if(FD_ISSET(ccon->fd, &write_fds)) {
						// The connect() is finished - make sure it was successful
						tcperrsize = sizeof(tcperr);
						r = getsockopt(ccon->fd, SOL_SOCKET, SO_ERROR, (void *)&tcperr, &tcperrsize);
						if(r != 0) {	// Check for error in getsockopt()
							logmsg(LOGGER_ERR, "getsockopt(): %s", strerror(errno));
							close(ccon->fd);
							ccon->state = CONNECTION_STATE_CLOSED;
							ccon->event = 1;
							break;
						}
						// Check if connect() errored
						if(tcperr != 0) {
							logmsg(LOGGER_NOTICE, "connect(): %s", strerror(tcperr));
							close(ccon->fd);
							ccon->state = CONNECTION_STATE_CLOSED;
							ccon->event = 1;
							break;
						}
						// connect() finished successfully - continue
						logmsg(LOGGER_DEBUG, "Outgoing TCP connection %p connected", ccon);
					} else {
						// It's a client in the middle of connecting, and it's not finished connecting
						break;
					}
				} else {
					logmsg(LOGGER_DEBUG, "Incoming TCP connection %p accepted", ccon);
				}
				// At this point, it's either a client that has successfully finished connect(), or a server that just finished accept()
				// Set the state to SSL connecting
				ccon->state = CONNECTION_STATE_SSLCONNECTING;
				// Initialize the ssl_want_* variables
				ccon->ssl_want_read = 0;
				ccon->ssl_want_write = 0;
				// Create a new SSL object
				ccon->ssl = SSL_new(conn_sslctx);
				if(!ccon->ssl) {
					logmsg(LOGGER_ERR, "Error creating SSL object: %s", ERR_error_string(ERR_get_error(), NULL));
					close(ccon->fd);
					ccon->state = CONNECTION_STATE_CLOSED;
					ccon->event = 1;
					break;
				}
				SSL_set_verify(ccon->ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_CLIENT_ONCE, NULL);
				// Create a socket BIO for the socket
				ccon->sslbio = BIO_new_socket(ccon->fd, BIO_NOCLOSE);
				//printf("BIOBIOBIOBIO %p\n", ccon->sslbio);
				if(!ccon->sslbio) {
					logmsg(LOGGER_ERR, "Error creating SSL BIO");
					close(ccon->fd);
					ccon->state = CONNECTION_STATE_CLOSED;
					ccon->event = 1;
					break;
				}
				// Connect the SSL object to the underlying socket BIO
				SSL_set_bio(ccon->ssl, ccon->sslbio, ccon->sslbio);
				// If we're a server, want a read - if we're a client, want a write
				if(ccon->isserver) {
					ccon->ssl_want_read = 1;
					ccon->ssl_want_write = 0;
				} else {
					ccon->ssl_want_read = 0;
					ccon->ssl_want_write = 1;
				}
				logmsg(LOGGER_DEBUG, "Initialized SSL objects for connection %p - setting state to SSLCONNECTING", ccon);
				// Done - Break out of the switch
				break;
			case CONNECTION_STATE_SSLCONNECTING:
				// If the connection was in either FD set, something happened that we're interested in, and we should try to start/continue the SSL connect
				if(FD_ISSET(ccon->fd, &read_fds) || FD_ISSET(ccon->fd, &write_fds)) {
					logmsg(LOGGER_DEBUG, "Connection %p is SSLCONNECTING and is readable or writable", ccon);
					// Do different things depending on if this is a client or server
					if(ccon->isserver) {
						logmsg(LOGGER_DEBUG, "SSL Accepting");
						r = SSL_accept(ccon->ssl);
					} else {
						logmsg(LOGGER_DEBUG, "SSL Connecting");
						r = SSL_connect(ccon->ssl);
					}
					// Check the result
					if(r > 0) {
						logmsg(LOGGER_DEBUG, "SSL successfully connected - doing connection verification");
						// SSL was successfully negotiated
						// Make sure the verification succeeded
						if(SSL_get_verify_result(ccon->ssl) != X509_V_OK) {
							logmsg(LOGGER_ERR, "Peer certificate did not verify");
							close(ccon->fd);
							ccon->state = CONNECTION_STATE_CLOSED;
							ccon->event = 1;
							break;
						}
						// Get the peer certificate
						peercert = SSL_get_peer_certificate(ccon->ssl);
						if(!peercert) {
							logmsg(LOGGER_ERR, "Peer did not present certificate");
							close(ccon->fd);
							ccon->state = CONNECTION_STATE_CLOSED;
							ccon->event = 1;
							break;
						}
						ccon->peercert = peercert;
						// If configured, make sure the peer's OU matches what it should
						if(global_config.restrictouname) {
							peerou = conn_getOUname(peercert);
							if(!peerou) {
								logmsg(LOGGER_ERR, "Error getting peer OU name as required");
								close(ccon->fd);
								ccon->state = CONNECTION_STATE_CLOSED;
								ccon->event = 1;
								break;
							}
							if(strcmp(peerou, global_config.restrictouname) != 0) {
								logmsg(LOGGER_ERR, "Peer OU does not match required value - received value was %s", peerou);
								close(ccon->fd);
								ccon->state = CONNECTION_STATE_CLOSED;
								ccon->event = 1;
								break;
							}
						}
						// Get the common name of the peer from its certificate
						peercn = conn_getcommonname(peercert);
						if(!peercn) {
							logmsg(LOGGER_ERR, "Error getting peer common name");
							close(ccon->fd);
							ccon->state = CONNECTION_STATE_CLOSED;
							ccon->event = 1;
							break;
						}
						// Look up the peer's host ID
						peerhostid = getnodeidbyname(peercn);
						if(peerhostid < 0) {
							logmsg(LOGGER_ERR, "Could not find peer %s in host ID table", peercn);
							close(ccon->fd);
							ccon->state = CONNECTION_STATE_CLOSED;
							ccon->event = 1;
							break;
						}
						ccon->peerid = peerhostid;
						// If the address of the remote host differs from the address in nodeinfo, update nodeinfo
						if(ccon->peeraddr.ss_family == AF_INET) {
							if(memcmp(&((struct sockaddr_in *)&ccon->peeraddr)->sin_addr, &(NODEINFO_INFO(ccon->peerid).addr4.sin_addr), sizeof(struct in_addr)) != 0) {
								memcpy(&(NODEINFO_INFO(ccon->peerid).addr4.sin_addr), &((struct sockaddr_in *)&ccon->peeraddr)->sin_addr, sizeof(struct in_addr));
								logmsg(LOGGER_NOTICE, "Updated address for node %s to %s", NODEINFO_INFO(ccon->peerid).name, inet_ntop(AF_INET, &(NODEINFO_INFO(ccon->peerid).addr4.sin_addr), addrstrbuf, 128));
								if(nodeinfo_saverecord(ccon->peerid) != NODEINFO_OK) logmsg(LOGGER_WARNING, "Error saving nodeinfo record");
							}
						} else if(ccon->peeraddr.ss_family == AF_INET6) {
							if(IN6ADDR_ISIP4CONV(((struct sockaddr_in6 *)&ccon->peeraddr)->sin6_addr)) {
								if(memcmp(&IN6ADDR_GETINADDR(((struct sockaddr_in6 *)&ccon->peeraddr)->sin6_addr), &(NODEINFO_INFO(ccon->peerid).addr4.sin_addr), sizeof(struct in_addr)) != 0) {
									memcpy(&(NODEINFO_INFO(ccon->peerid).addr4.sin_addr), &IN6ADDR_GETINADDR(((struct sockaddr_in6 *)&ccon->peeraddr)->sin6_addr), sizeof(struct in_addr));
									logmsg(LOGGER_NOTICE, "Updated address for node %s to %s", NODEINFO_INFO(ccon->peerid).name, inet_ntop(AF_INET, &(NODEINFO_INFO(ccon->peerid).addr4.sin_addr), addrstrbuf, 128));
									if(nodeinfo_saverecord(ccon->peerid) != NODEINFO_OK) logmsg(LOGGER_WARNING, "Error saving nodeinfo record");
								}
							} else {
								if(memcmp(&((struct sockaddr_in6 *)&ccon->peeraddr)->sin6_addr, &(NODEINFO_INFO(ccon->peerid).addr6.sin6_addr), sizeof(struct in6_addr)) != 0) {
									memcpy(&(NODEINFO_INFO(ccon->peerid).addr6.sin6_addr), &((struct sockaddr_in6 *)&ccon->peeraddr)->sin6_addr, sizeof(struct in6_addr));
									logmsg(LOGGER_NOTICE, "Updated address for node %s to %s", NODEINFO_INFO(ccon->peerid).name, inet_ntop(AF_INET6, &(NODEINFO_INFO(ccon->peerid).addr6.sin6_addr), addrstrbuf, 128));
									if(nodeinfo_saverecord(ccon->peerid) != NODEINFO_OK) logmsg(LOGGER_WARNING, "Error saving nodeinfo record");
								}
							}
						}
						// SSL connection successful - set the new connection state
						ccon->state = CONNECTION_STATE_CONNECTED;
						ccon->ssl_want_read = 0;
						ccon->ssl_want_write = 0;
						ccon->event = 1;
						logmsg(LOGGER_DEBUG, "All verifications succeeded.  SSL connected.");
						break;
					}
					// Check if the connection was shut down with an error
					if(r == 0) {
						logmsg(LOGGER_NOTICE, "Connection was shut down: %s", ERR_error_string(SSL_get_error(ccon->ssl, r), NULL));
						conn_log_ssl_err_queue(LOGGER_NOTICE);
						close(ccon->fd);
						ccon->state = CONNECTION_STATE_CLOSED;
						ccon->event = 1;
						break;
					}
					// Check if some specific error occurred
					if(r < 0) {
						sslerr = SSL_get_error(ccon->ssl, r);
						// Check for wanting a read or write
						if(sslerr == SSL_ERROR_WANT_READ) {
							ccon->ssl_want_read = 1;
							ccon->ssl_want_write = 0;
							break;
						}
						if(sslerr == SSL_ERROR_WANT_WRITE) {
							ccon->ssl_want_read = 0;
							ccon->ssl_want_write = 1;
							break;
						}
						// Any other error means a connection close
						close(ccon->fd);
						ccon->state = CONNECTION_STATE_CLOSED;
						ccon->event = 1;
						// Output the error message ... maybe add more detailed checking later
						logmsg(LOGGER_ERR, "SSL negotiation error: %s", ERR_error_string(sslerr, NULL));
						if(sslerr == SSL_ERROR_SYSCALL) logmsg(LOGGER_ERR, "System error: %s", strerror(errno));
						conn_log_ssl_err_queue(LOGGER_ERR);
						break;
					}
					// Should never get here
				}
				break;
			case CONNECTION_STATE_CONNECTED:
				// Only do something if this FD was in one of the sets
				if(FD_ISSET(ccon->fd, &read_fds) || FD_ISSET(ccon->fd, &write_fds) || SSL_pending(ccon->ssl) > 0) {
					logmsg(LOGGER_DEBUG, "Connection %p all connected and has readability, writability, or pending data", ccon);
					// Check if there's data to be sent
					if(ccon->sendbuf && ccon->sendlen > 0) if(ccon->sendbuf + ccon->sendlen > ccon->sendpos) {
						r = SSL_write(ccon->ssl, ccon->sendpos, ccon->sendbuf + ccon->sendlen - ccon->sendpos);
						if(r > 0) {
							// Send was successful
							ccon->sendpos += r;
							ccon->event = 1;
						} else if(r == 0) {
							logmsg(LOGGER_WARNING, "Connection closed unexpectedly during send");
							close(ccon->fd);
							ccon->state = CONNECTION_STATE_CLOSED;
							ccon->event = 1;
							break;
						} else {
							sslerr = SSL_get_error(ccon->ssl, r);
							if(sslerr == SSL_ERROR_WANT_READ) ccon->ssl_want_read = 1;
							if(sslerr == SSL_ERROR_WANT_WRITE) ccon->ssl_want_write = 1;
							if(sslerr != SSL_ERROR_WANT_WRITE && sslerr != SSL_ERROR_WANT_READ) {
								logmsg(LOGGER_ERR, "SSL Error");
								close(ccon->fd);
								ccon->state = CONNECTION_STATE_CLOSED;
								ccon->event = 1;
								break;
							}
						}
					}
					// Check if there's data to be received
					//logmsg(LOGGER_DEBUG, "Checking receive - recvbuf %p recvlen %d recvpos %p", ccon->recvbuf, ccon->recvlen, ccon->recvpos);
					if(ccon->recvbuf && ccon->recvlen > 0) if(ccon->recvbuf + ccon->recvlen > ccon->recvpos) {
						//logmsg(LOGGER_DEBUG, "mainsendrecv - trying to receive data");
						r = SSL_read(ccon->ssl, ccon->recvpos, ccon->recvbuf + ccon->recvlen - ccon->recvpos);
						//logmsg(LOGGER_DEBUG, "mainsendrecv - receive data - return %d", r);
						if(r > 0) {
							// Receive was successful
							ccon->recvpos += r;
							ccon->event = 1;
						} else if(r == 0) {
							logmsg(LOGGER_WARNING, "Connection closed unexpectedly during receive");
							close(ccon->fd);
							ccon->state = CONNECTION_STATE_CLOSED;
							ccon->event = 1;
							break;
						} else {
							sslerr = SSL_get_error(ccon->ssl, r);
							if(sslerr == SSL_ERROR_WANT_READ) ccon->ssl_want_read = 1;
							if(sslerr == SSL_ERROR_WANT_WRITE) ccon->ssl_want_write = 1;
							if(sslerr != SSL_ERROR_WANT_WRITE && sslerr != SSL_ERROR_WANT_READ) {
								logmsg(LOGGER_ERR, "SSL Error");
								close(ccon->fd);
								ccon->state = CONNECTION_STATE_CLOSED;
								ccon->event = 1;
								break;
							}
						}
					}
				}
				break;
			case CONNECTION_STATE_SSLCLOSING:
				// If the FD is in either set, try to shut it down
				if(FD_ISSET(ccon->fd, &read_fds) || FD_ISSET(ccon->fd, &write_fds)) {
					r = SSL_shutdown(ccon->ssl);
					if(r >= 0) {
						close(ccon->fd);
						ccon->state = CONNECTION_STATE_CLOSED;
						ccon->event = 1;
						break;
					}
					sslerr = SSL_get_error(ccon->ssl, r);
					if(sslerr == SSL_ERROR_WANT_READ) ccon->ssl_want_read = 1;
					if(sslerr == SSL_ERROR_WANT_WRITE) ccon->ssl_want_write = 1;
					if(sslerr != SSL_ERROR_WANT_WRITE && sslerr != SSL_ERROR_WANT_READ) {
						logmsg(LOGGER_ERR, "SSL Error");
						close(ccon->fd);
						ccon->state = CONNECTION_STATE_CLOSED;
						ccon->event = 1;
						break;
					}
				}
				break;
			case CONNECTION_STATE_CLOSED:
				break;
		}
	}
	// Check for waiting TCP connections
	if(FD_ISSET(conn_sslservsock.fd, &read_fds)) {
		conn_sslcon_accept();
	}
	// Check for UDP sends
	if(conn_udpcon.sendbuf && conn_udpcon.sendbuflen > 0 && FD_ISSET(conn_udpcon.fd, &write_fds)) {
		logmsg(LOGGER_DEBUG, "Sending UDP packet of length %d", conn_udpcon.sendbuflen);
		r = sendto(conn_udpcon.fd, conn_udpcon.sendbuf, conn_udpcon.sendbuflen, 0, (struct sockaddr *)&conn_udpcon.sendtoaddr, SOCKADDR_SIZE(&conn_udpcon.sendtoaddr));
		if(r < 1) {
			logmsg(LOGGER_ERR, "Error sending UDP packet: %s", strerror(errno));
		}
		conn_udpcon.sendbuflen = 0;
	}
	// Check for UDP receives
	if(conn_udpcon.recvbuf && conn_udpcon.recvbuflen < 1 && conn_udpcon.recvbufsize > 0 && FD_ISSET(conn_udpcon.fd, &read_fds)) {
		recvaddrlen = sizeof(struct sockaddr_storage);
		r = recvfrom(conn_udpcon.fd, conn_udpcon.recvbuf, conn_udpcon.recvbufsize, 0, (struct sockaddr *)&conn_udpcon.recvfromaddr, &recvaddrlen);
		if(r > 0) {
			// Receive successful
			conn_udpcon.recvbuflen = r;
		} else {
			// Receive error
			logmsg(LOGGER_ERR, "Error receiving UDP packet: %s", strerror(errno));
		}
	}
	// Check for tun sends
	if(conn_tuncon.sendbuf && conn_tuncon.sendbuflen > 0 && FD_ISSET(conn_tuncon.fd, &write_fds)) {
		logmsg(LOGGER_DEBUG, "Sending %d bytes to tun", conn_tuncon.sendbuflen);
		r = write(conn_tuncon.fd, conn_tuncon.sendbuf, conn_tuncon.sendbuflen);
		if(r < 1) {
			logmsg(LOGGER_ERR, "Error sending tun packet");
		}
		conn_tuncon.sendbuflen = 0;
	}
	// Check for tun receives
	if(conn_tuncon.recvbuf && conn_tuncon.recvbuflen < 1 && conn_tuncon.recvbufsize > 0 && FD_ISSET(conn_tuncon.fd, &read_fds)) {
		r = read(conn_tuncon.fd, conn_tuncon.recvbuf, conn_tuncon.recvbufsize);
		if(r > 0) {
			// Receive successful
			conn_tuncon.recvbuflen = r;
		} else {
			// Receive error
			logmsg(LOGGER_ERR, "Error receiving tun packet");
		}
	}
	return 1;
}

