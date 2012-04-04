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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <unistd.h>
#include <errno.h>
#include "tunio.h"
#include "logger.h"

int tunio_open(char *dev) {
	struct ifreq ifr;
	int fd, r;
	logmsg(LOGGER_DEBUG, "Opening device ...");
	fd = open("/dev/net/tun", O_RDWR);
	if(fd == -1) {
		logmsg(LOGGER_CRIT, "Could not open tun device: %s", strerror(errno));
		return -1;
	}
	logmsg(LOGGER_DEBUG, "Setting up ifreq ...");
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	if(dev) if(*dev) strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	logmsg(LOGGER_DEBUG, "Setting options ...");
	r = ioctl(fd, TUNSETIFF, (void *)&ifr);
	if(r < 0) { close(fd); return -1; }
	if(dev) strcpy(dev, ifr.ifr_name);
	return fd;
}

void tunio_close(int fd) {
	close(fd);
}

int tunio_write(int fd, char *buf, int len) {
	return write(fd, buf, len);
}

int tunio_read(int fd, char *buf, int len) {
	return read(fd, buf, len);
}

void hexprint(unsigned char *buf, int len) {
	int c;
	for(c = 0; c < len; c++) {
		printf("%.2X", buf[c]);
		if((c + 1) % 16 == 0) { printf("\n"); continue; }
		if((c + 1) % 4 == 0) { printf(" "); continue; }
	}
	printf("\n");
}

int tunio_test() {
	unsigned char buf[65536];
	int buflen;
	char devname[10];
	strcpy(devname, "cluetest");
	int fd = tunio_open(devname);
	if(fd == -1) {
		printf("Error.\n");
		return 1;
	}
	printf("Opened device %s\n", devname);
	for(;;) {
		printf("Reading packet ...\n");
		buflen = tunio_read(fd, buf, 65536);
		if(buflen < 4) {
			printf("Huh?  Got a length %d\n", buflen);
			continue;
		}
		printf("Packet length %d:\n", buflen);
		hexprint(buf, buflen);
		printf("\n");
	}
}
