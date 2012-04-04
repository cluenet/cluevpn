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
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "routetable.h"
#include "configfile.h"
#include "logger.h"
#include "signature.h"
#include "nodeinfo.h"
#include "bnl.h"
#include "comp.h"
#include "crypt.h"
#include "connections.h"
#include "nodeinfo.h"
#include "netpackets.h"
#include "tcpcons.h"
#include "datapackage.h"

#define SENDRECVBUFSIZE 69632
#define SPARECONNTHRESHOLD 25

char bgdaemon = 1;

int main_loglevel = LOGGER_WARNING;
char loglevel_opt = 0;
int trigger_interval = 5;
int bnlpull_interval = 90;
int preneg_interval = 15;

time_t last_trigger = 0;
time_t last_bnlpull = 0;
int nextbnlpullnode = -1;
time_t last_preneg = 0;
int nextprenegnode = -1;
int nextbnlpushnode = -1;

char pidfilename[256] = "";

void reloadBNLSignalHandler(int sig) {
	int r;
	char *newbnl;
	int newbnllen;
	logmsg(LOGGER_INFO, "Loading New BNL");
	r = bnl_loadbnlfile(&newbnl, &newbnllen);
	if(r != NODEINFO_OK) {
		logmsg(LOGGER_ERR, "Could not load new BNL");
		return;
	}
	logmsg(LOGGER_INFO, "BNL loaded - merging");
	r = handleNewBNL(newbnl, newbnllen);
	free(newbnl);
	if(r != NODEINFO_OK) {
		logmsg(LOGGER_ERR, "Could not merge new BNL");
		return;
	}
	nextbnlpushnode = 0;
}

int setupSignals() {
	int r;
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = reloadBNLSignalHandler;
	r = sigaction(SIGUSR1, &sa, NULL);
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = reloadBNLSignalHandler;
	r = sigaction(SIGHUP, &sa, NULL);
	return 0;
}

int spawnBNLPulls(int num) {
	int loopstart, node, spawned = 0, r;
	if(nextbnlpullnode < 0) nextbnlpullnode = rand() % (maxvpnnodeid + 1);
	loopstart = nextbnlpullnode;
	node = loopstart;
	for(;;) {
		if(NODEINFO_EXISTS(node) && node != global_config.id) {
			if(!tcpcon_checkExistingConn(node, TCPCON_BNLPULL, 0) && !tcpcon_checkExistingConn(node, TCPCON_BNLPUSH, 1)) {
				logmsg(LOGGER_DEBUG, "Spawning BNL pull to node %d", node);
				r = tcpcon_newbnlpull(node);
				if(r != TCPCON_OK) {
					logmsg(LOGGER_ERR, "Error starting BNL pull");
				} else {
					spawned++;
				}
			}
		}
		node++;
		if(node > maxvpnnodeid) node = 0;
		if(node == loopstart) break;
		if(spawned >= num) break;
	}
	nextbnlpullnode = node;
	return 0;
}

int spawnBNLPushes(int num) {
	int loopstart, node, spawned = 0, r;
	if(nextbnlpushnode < 0) return 1;
	loopstart = nextbnlpushnode;
	node = loopstart;
	for(;;) {
		if(NODEINFO_EXISTS(node) && node != global_config.id) {
			if(!tcpcon_checkExistingConn(node, TCPCON_BNLPULL, 1) && !tcpcon_checkExistingConn(node, TCPCON_BNLPUSH, 0)) {
				logmsg(LOGGER_DEBUG, "Spawning BNL push to node %d", node);
				r = tcpcon_newbnlpush(node);
				if(r != TCPCON_OK) {
					logmsg(LOGGER_ERR, "Error starting BNL push");
				} else {
					spawned++;
				}
			}
		}
		node++;
		if(node > maxvpnnodeid) {
			node = -1;
			break;
		}
		if(spawned >= num) break;
	}
	nextbnlpushnode = node;
	return 0;
}

int spawnPrenegs(int num) {
	int loopstart, node, spawned = 0, r;
	if(nextprenegnode < 0) nextprenegnode = rand() % (maxvpnnodeid + 1);
	loopstart = nextprenegnode;
	node = loopstart;
	for(;;) {
		if(NODEINFO_EXISTS(node) && node != global_config.id && !NODEINFO_INFO(node).negotiated) {
			if(!tcpcon_checkExistingConn(node, TCPCON_NEGOTIATION, 2)) {
				logmsg(LOGGER_DEBUG, "Spawning negotiation to node %d", node);
				r = tcpcon_newnegotiate(node);
				if(r != TCPCON_OK) {
					logmsg(LOGGER_ERR, "Error starting negotiation");
				} else {
					spawned++;
				}
			}
		}
		node++;
		if(node > maxvpnnodeid) node = 0;
		if(node == loopstart) break;
		if(spawned >= num) break;
	}
	nextprenegnode = node;
	return 0;
}

int doTrigger() {
	int sparecons, r;
	last_trigger = time(NULL);
	logmsg(LOGGER_DEBUG, "Handling trigger");
	// Figure out how many "spare" TCP connections there are
	sparecons = SPARECONNTHRESHOLD - conn_numsslcons;
	if(sparecons < 0) sparecons = 0;
	logmsg(LOGGER_DEBUG, "Spare connections: %d", sparecons);
	// Spawn some BNL pushes if necessary
	if(nextbnlpushnode >= 0) {
		logmsg(LOGGER_DEBUG, "Doing BNL pushes");
		if(sparecons >= 2) r = spawnBNLPushes(sparecons - 1); else r = spawnBNLPushes(1);
		if(r != 0) {
			logmsg(LOGGER_ERR, "Error pushing BNLs");
		}
	}
	// Recalc spare connections
	sparecons = SPARECONNTHRESHOLD - conn_numsslcons;
	if(sparecons < 0) sparecons = 0;
	// See if it's time to spawn some BNL pulls
	if(time(NULL) - last_bnlpull >= bnlpull_interval) {
		logmsg(LOGGER_DEBUG, "Doing BNL pulls");
		last_bnlpull = time(NULL);
		if(sparecons >= 2) r = spawnBNLPulls(sparecons - 1); else r = spawnBNLPulls(1);
		if(r != 0) {
			logmsg(LOGGER_ERR, "Error pulling BNLs");
		}
	}
	// Recalc spare connections
	sparecons = SPARECONNTHRESHOLD - conn_numsslcons;
	if(sparecons < 0) sparecons = 0;
	// See if it's time to prenegotiate some connections
	if(time(NULL) - last_preneg >= preneg_interval) {
		logmsg(LOGGER_DEBUG, "Doing prenegotiation");
		last_preneg = time(NULL);
		r = 0;
		if(sparecons) r = spawnPrenegs((sparecons > 4) ? 4 : sparecons);
		if(r != 0) {
			logmsg(LOGGER_ERR, "Error prenegotiating");
		}
	}
	return 0;
}

int initializeComponents() {
	int r;
	// Change directory to the config directory
	r = chdir(configfile_dir);
	if(r != 0) {
		logpreinitmsg("Error: Could not change to config directory.");
		return 1;
	}
	// Open and load the configuration file
	r = configfile_load();
	if(r != CONFIGFILE_OK) {
		logpreinitmsg("Error: Could not parse configuration file.");
		return 1;
	}
	if(!loglevel_opt) if(global_config.loglevel > 0) main_loglevel = global_config.loglevel;
	if(!bgdaemon) { free(global_config.logmethod); global_config.logmethod = strdup("stderr"); }
	// Initialize logging
	logger_init(main_loglevel);
	// Initialize SSL
	logmsg(LOGGER_INFO, "Initializing SSL");
	r = conn_initssl();
	if(r != 0) {
		logmsg(LOGGER_CRIT, "Could not initialize SSL");
		return 1;
	}
	// Initialize signature handling
	logmsg(LOGGER_INFO, "Initializing signatures");
	r = sig_init();
	if(r != SIG_OK) {
		logmsg(LOGGER_CRIT, "Could not initialize signatures");
		return 1;
	}
	// Initialize routing tables
	logmsg(LOGGER_INFO, "Initializing routing tables");
	r = routetable_init(&ipv4routetable);
	if(r != ROUTETABLE_OK) {
		logmsg(LOGGER_CRIT, "Could not initialize routing tables");
		return 1;
	}
	r = routetable_init(&ipv6routetable);
	if(r != ROUTETABLE_OK) {
		logmsg(LOGGER_CRIT, "Could not initialize routing tables");
		return 1;
	}
	// Initialize the node info system, which includes opening the nodeinfo file
	logmsg(LOGGER_INFO, "Initializing nodeinfo");
	r = nodeinfo_init();
	if(r != NODEINFO_OK) {
		logmsg(LOGGER_CRIT, "Could not initialize nodeinfo");
		return 1;
	}
	// Load the node info data
	logmsg(LOGGER_INFO, "Loading nodeinfo");
	r = nodeinfo_load();
	if(r != NODEINFO_OK) {
		logmsg(LOGGER_CRIT, "Could not load nodeinfo");
		return 1;
	}
	// Load the local BNL into memory
	logmsg(LOGGER_INFO, "Loading BNL");
	r = bnl_loadbnlfile(&bnl_current, &bnl_current_len);
	if(r != NODEINFO_OK) {
		logmsg(LOGGER_CRIT, "Could not load BNL");
		return 1;
	}
	// Merge the BNL into the node info
	logmsg(LOGGER_INFO, "Merging BNL with nodeinfo");
	r = bnl_loadnewbnl(SIG_DATA(bnl_current), SIG_DATALEN(bnl_current));
	if(r != NODEINFO_OK) {
		logmsg(LOGGER_CRIT, "Could not load BNL into nodeinfo cache");
		return 1;
	}
	// Save the nodeinfo file now
	logmsg(LOGGER_INFO, "Saving nodeinfo file");
	r = nodeinfo_save();
	if(r != NODEINFO_OK) {
		logmsg(LOGGER_CRIT, "Could not save nodeinfo file");
		return 1;
	}
	// Associate config file host options with nodeinfo entries
	logmsg(LOGGER_INFO, "Associating node IDs with config file entries");
	nodeinfo_assocnodeconfigopts();
	// Initialize compression
	logmsg(LOGGER_INFO, "Initializing compression");
	r = comp_init();
	if(r != COMP_OK) {
		logmsg(LOGGER_CRIT, "Could not initialize compression");
		return 1;
	}
	// Initialize encryption
	logmsg(LOGGER_INFO, "Initializing encryption");
	r = crypt_init();
	if(r != COMP_OK) {
		logmsg(LOGGER_CRIT, "Could not initialize encryption");
		return 1;
	}
	// Initialize sockets
	logmsg(LOGGER_INFO, "Initializing networking");
	r = conn_initsocks();
	if(r != 0) {
		logmsg(LOGGER_CRIT, "Could not initialize networking");
		return 1;
	}
	return 0;
}

int handleTunPacket() {
	char ipversion;
	struct in_addr destaddr4;
	struct in6_addr destaddr6;
	int r;
	int tosendlen;
	int destnodeid;
	struct sockaddr *udpsendaddr;
	socklen_t udpsendaddrlen;
	// Make sure there actually is data available on the tun interface
	if(!TUN_HASDATA()) return 0;
	// Make sure that it's at least as long as an IP packet, and extract the IP version and destination address
	if(TUN_RECVLEN < IPPACKET_MINLEN) {
		logmsg(LOGGER_NOTICE, "Received invalid IP packet from tun");
		TUN_CLEARRECVBUF();
		return 1;
	}
	ipversion = IPPACKET_VERSION(TUN_RECVBUF);
	if(ipversion == 4) {
		if(TUN_RECVLEN < sizeof(struct ip)) {
			logmsg(LOGGER_NOTICE, "Received invalid IP packet from tun");
			TUN_CLEARRECVBUF();
			return 1;
		}
		destaddr4 = IP4PACKET_DESTADDR(TUN_RECVBUF);
	} else if(ipversion == 6) {
		if(TUN_RECVLEN < sizeof(struct ip6_hdr)) {
			logmsg(LOGGER_NOTICE, "Received invalid IP packet from tun");
			TUN_CLEARRECVBUF();
			return 1;
		}
		destaddr6 = IP6PACKET_DESTADDR(TUN_RECVBUF);
	} else {
		logmsg(LOGGER_NOTICE, "Received invalid IP packet from tun");
		TUN_CLEARRECVBUF();
		return 1;
	}
	// Figure out the destination node id to route to
	if(ipversion == 4) {
		r = routetable_getroute(&ipv4routetable, &destaddr4, 32, &destnodeid);
	} else {
		r = routetable_getroute(&ipv6routetable, &destaddr6, 128, &destnodeid);
	}
	// If there's no route, send back an ICMP host unreachable
	if(r == ROUTETABLE_NOROUTE) {
		if(ipversion == 4) {
			netpacket_make4Unreachable(IP4PACKET_SRCADDR(TUN_RECVBUF), IP4PACKET_DESTADDR(TUN_RECVBUF), TUN_SENDBUF, &TUN_SENDLEN, TUN_RECVBUF, TUN_RECVLEN);
		} else {
			netpacket_make6Unreachable(IP6PACKET_SRCADDR(TUN_RECVBUF), IP6PACKET_DESTADDR(TUN_RECVBUF), TUN_SENDBUF, &TUN_SENDLEN, TUN_RECVBUF, TUN_RECVLEN);
		}
		TUN_CLEARRECVBUF();
		logmsg(LOGGER_DEBUG, "Got unreachable packet, putting ICMP unreachable in send buf");
		return 0;
	} else if(r != ROUTETABLE_OK) {
		logmsg(LOGGER_ERR, "Routing error");
		TUN_CLEARRECVBUF();
		return 1;
	}
	logmsg(LOGGER_DEBUG, "Packet is routable to node %d", destnodeid);
	// If we haven't negotiated with the peer yet, start a negotiation
	if(!NODEINFO_INFO(destnodeid).negotiated) {
		TUN_CLEARRECVBUF();
		logmsg(LOGGER_INFO, "Starting negotiation with %d", destnodeid);
		r = tcpcon_newnegotiate(destnodeid);
		if(r != TCPCON_OK) {
			logmsg(LOGGER_ERR, "Error starting negotiation");
			return 1;
		}
		return 0;
	}
	// Encrypt/everything the data and put it in the send buffer
	logmsg(LOGGER_DEBUG, "Packing data to send");
	tosendlen = SENDRECVBUFSIZE;
	r = packageDataForNetwork(TUN_RECVBUF, TUN_RECVLEN, UDP_SENDBUF, &tosendlen, destnodeid);
	if(r != 0) {
		logmsg(LOGGER_ERR, "Error packaging data for network transmission");
		TUN_CLEARRECVBUF();
		return 1;
	}
	UDP_SENDLEN = tosendlen;
	r = getnodeaddress(destnodeid, &udpsendaddr, &udpsendaddrlen);
	if(r == NODEINFO_NOENT) {
		logmsg(LOGGER_NOTICE, "Cannot communicate with node %s - incompatable supported addresses", NODEINFO_INFO(destnodeid).name);
		TUN_CLEARRECVBUF();
		return 1;
	}
	memset(&UDP_SENDADDR, 0, sizeof(struct sockaddr_storage));
	memcpy(&UDP_SENDADDR, udpsendaddr, udpsendaddrlen);
	// Clear the recv buf
	TUN_CLEARRECVBUF();
	return 0;
}

int handleUdpPacket() {
	int r, srcnode, dlen;
	int srcroute;
	char ipversion;
	struct in_addr srcaddr4;
	struct in6_addr srcaddr6;
	// Make sure there's actually UDP data
	if(!UDP_HASDATA()) return 0;
	logmsg(LOGGER_DEBUG, "Received UDP packet");
	// Make sure the data is above the minimum length
	if(UDP_RECVLEN < DPACK_MINPACKLEN) {
		logmsg(LOGGER_NOTICE, "Received too short UDP packet");
		UDP_CLEARRECVBUF();
		return 1;
	}
	// Make sure the packet type is 0
	if(!DPACK_CHECKPTYPE(UDP_RECVBUF)) {
		logmsg(LOGGER_NOTICE, "Invalid packet type");
		UDP_CLEARRECVBUF();
		return 1;
	}
	// Make sure the source node is known
	srcnode = DPACK_GETSRCNODE(UDP_RECVBUF);
	if(!NODEINFO_EXISTS(srcnode)) {
		logmsg(LOGGER_NOTICE, "Received packet from invalid node");
		UDP_CLEARRECVBUF();
		return 1;
	}
	// If the source node isn't negotiated yet, start a negotiation
	// If we haven't negotiated with the peer yet, start a negotiation
	if(!NODEINFO_INFO(srcnode).negotiated) {
		UDP_CLEARRECVBUF();
		logmsg(LOGGER_INFO, "Starting negotiation with %d", srcnode);
		r = tcpcon_newnegotiate(srcnode);
		if(r != TCPCON_OK) {
			logmsg(LOGGER_ERR, "Error starting negotiation");
			return 1;
		}
		return 0;
	}
	// Unpack everything into the tun send buffer
	dlen = SENDRECVBUFSIZE;
	r = unpackageDataFromNetwork(UDP_RECVBUF, UDP_RECVLEN, TUN_SENDBUF, &dlen);
	if(r != 0) {
		logmsg(LOGGER_ERR, "Error unpacking data");
		UDP_CLEARRECVBUF();
		return 1;
	}
	TUN_SENDLEN = dlen;
	// Clear receive buf and return
	UDP_CLEARRECVBUF();
	// Extract the source IP address and check if it's spoofed
	logmsg(LOGGER_DEBUG, "Checking for spoofed source address");
	if(TUN_SENDLEN < IPPACKET_MINLEN) {
		logmsg(LOGGER_ERR, "Packet too short");
		return 1;
	}
	ipversion = IPPACKET_VERSION(TUN_SENDBUF);
	if(ipversion == 4) {
		if(TUN_SENDLEN < sizeof(struct ip)) {
			logmsg(LOGGER_ERR, "Packet too short");
			return 1;
		}
		srcaddr4 = IP4PACKET_SRCADDR(TUN_SENDBUF);
		r = routetable_getroute(&ipv4routetable, &srcaddr4, 32, &srcroute);
		if(r == ROUTETABLE_NOROUTE) {
			logmsg(LOGGER_WARNING, "Received packet from unroutable source address");
			return 1;
		}
		if(r != ROUTETABLE_OK) {
			logmsg(LOGGER_ERR, "Error looking up route");
			return 1;
		}
		if(srcroute != srcnode) {
			logmsg(LOGGER_ERR, "Received packet from spoofed source address.  Packet from node %d with source address routable to node %d.", srcnode, srcroute);
			return 1;
		}
	} else if(ipversion == 6) {
		if(TUN_SENDLEN < sizeof(struct ip6_hdr)) {
			logmsg(LOGGER_ERR, "Packet too short");
			return 1;
		}
		srcaddr6 = IP6PACKET_SRCADDR(TUN_SENDBUF);
		r = routetable_getroute(&ipv6routetable, &srcaddr6, 128, &srcroute);
		if(r == ROUTETABLE_NOROUTE) {
			logmsg(LOGGER_WARNING, "Received packet from unroutable source address");
			return 1;
		}
		if(r != ROUTETABLE_OK) {
			logmsg(LOGGER_ERR, "Error looking up route");
			return 1;
		}
		if(srcroute != srcnode) {
			logmsg(LOGGER_ERR, "Received packet from spoofed source address.  Packet from node %d with source address routable to node %d.", srcnode, srcroute);
			return 1;
		}
	} else {
		logmsg(LOGGER_ERR, "Invalid IP version");
		return 1;
	}
	return 0;
}

int mainloopiteration() {
	int r;
	struct conn_sslcon *ccon;
	time_t ttnt;
	// Wait for an event to occur
	logmsg(LOGGER_DEBUG, "Entering main loop iteration");
	ttnt = trigger_interval - (time(NULL) - last_trigger);
	if(ttnt <= 0) ttnt = 1;
	logmsg(LOGGER_DEBUG, "mainsendrecv with timeout %d", ttnt * 1000);
	r = conn_mainsendrecv(ttnt * 1000);
	if(r != 1) {
		logmsg(LOGGER_CRIT, "Error sending/receiving");
		return 1;
	}
	logmsg(LOGGER_DEBUG, "Event occurred");
	// Check if data was received on the tun interface
	if(TUN_HASDATA()) {
		logmsg(LOGGER_DEBUG, "Tun data received");
		r = handleTunPacket();
		//if(r != 0) return r;
	}
	// Check if data was received on the UDP interface
	if(UDP_HASDATA()) {
		logmsg(LOGGER_DEBUG, "UDP data received");
		r = handleUdpPacket();
	}
	// Cycle through all TCP connections and handle those with events
	for(ccon = conn_sslconlist_start(); ccon; ccon = conn_sslconlist_next(ccon)) {
		logmsg(LOGGER_DEBUG, "Checking connection %p", ccon);
		if(ccon->event) {
			logmsg(LOGGER_DEBUG, "Connection has event - handling");
			r = tcpcon_handleevent(ccon);
		}
		// If the connection is closed, free its data to prepare it for reaping
		if(ccon->state == CONNECTION_STATE_CLOSED) {
			logmsg(LOGGER_DEBUG, "Connection is closed - reaping");
			if(ccon->data) {
				tcpcon_freeconndata((struct tcpcon_data *)ccon->data);
				free(ccon->data);
			}
		}
	}
	// Reap closed TCP connections
	conn_sslcons_cleanupclosed();
	return 0;
}

int callUpCmd() {
	int r;
	if(global_config.upcmd) {
		setenv("TUNDEV", tundevname, 1);
		r = system(global_config.upcmd);
		unsetenv("TUNDEV");
		if(r < 0) return 1;
	}
	return 0;
}

int mainloop() {
	char *udpsendbuf, *udprecvbuf, *tunsendbuf, *tunrecvbuf;
	int r;
	logmsg(LOGGER_DEBUG, "Allocating static buffers");
	udpsendbuf = malloc(SENDRECVBUFSIZE);
	udprecvbuf = malloc(SENDRECVBUFSIZE);
	tunsendbuf = malloc(SENDRECVBUFSIZE);
	tunrecvbuf = malloc(SENDRECVBUFSIZE);
	conn_setudptunbufs(udpsendbuf, udprecvbuf, SENDRECVBUFSIZE, tunsendbuf, tunrecvbuf, SENDRECVBUFSIZE);
	logmsg(LOGGER_DEBUG, "Calling up command");
	r = callUpCmd();
	if(r != 0) {
		logmsg(LOGGER_ERR, "Error calling up command");
		return 1;
	}
	logmsg(LOGGER_DEBUG, "Calling subnet up commands");
	r = bnl_callsubnetups(SIG_DATA(bnl_current), SIG_DATALEN(bnl_current));
	if(r != 0) {
		logmsg(LOGGER_ERR, "Error calling subnet up commands");
		return 1;
	}
	logmsg(LOGGER_INFO, "Entering main loop");
	for(;;) {
		r = mainloopiteration();
		if(r != 0) {
			logmsg(LOGGER_CRIT, "Main loop iteration failed");
			break;
		}
		if(time(NULL) - last_trigger >= trigger_interval) {
			r = doTrigger();
			if(r != 0) {
				logmsg(LOGGER_ERR, "Trigger handling failed");
			}
		}
	}
}

int parseMainOptions(int argc, char * const argv[]) {
	char *optstring = "c:p:d:f";
	int opt;
	while((opt = getopt(argc, argv, optstring)) > 0) {
		if(opt == '?') return 1;
		switch(opt) {
			case 'c':
				strcpy(configfile_dir, optarg);
				break;
			case 'p':
				strcpy(pidfilename, optarg);
				break;
			case 'd':
				main_loglevel = atoi(optarg);
				loglevel_opt = 1;
				break;
			case 'f':
				bgdaemon = 0;
				break;
		}
	}
	return 0;
}

void makeDaemon() {
	int fd, r, pid;
	pid = fork();
	if(pid != 0) exit(0);
	setsid();
	close(0);
	close(1);
	close(2);
	fd = open("/dev/null", O_RDWR);
	r = dup(fd); r = dup(fd);
}

void writePIDFile() {
	FILE *f;
	f = fopen(pidfilename, "w");
	if(!f) {
		logmsg(LOGGER_ERR, "Error creating PID file.");
		return;
	}
	fprintf(f, "%d\n", (int)getpid());
	fclose(f);
}

int main(int argc, char **argv) {
	int r;
	r = parseMainOptions(argc, argv);
	if(r != 0) {
		fprintf(stderr, "Error parsing options.\n");
		return 1;
	}
	umask(027);
	r = initializeComponents();
	if(r != 0) {
		logmsg(LOGGER_CRIT, "Initialization failed.");
		return 1;
	}
	setupSignals();
	if(bgdaemon) makeDaemon();
	if(pidfilename[0]) writePIDFile();
	logmsg(LOGGER_INFO, "Initialized.");
	mainloop();
}

