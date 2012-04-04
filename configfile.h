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


#ifndef _CONFIGFILE_H
#define _CONFIGFILE_H

#include <stdio.h>

#define CONFIGFILE_FILENAME "cluevpn.conf"
#define CONFIGFILE_DIR_DEFAULT "/etc/cluevpn"
#define CONFIGFILE_FILENAME_LEN 1024

#define CONFIGFILE_OK 0
#define CONFIGFILE_MALFORMED 1
#define CONFIGFILE_ERROR 2

struct configfile_algo_pref {
	int algo;
	unsigned short level;
	int pref;
};

struct configfile_globalopts {
	char *name;									// String
	int id;
	struct configfile_algo_pref *cryptalgos;	// List terminated by an algo < 0
	struct configfile_algo_pref *compalgos;		// List terminated by an algo < 0
	char *devname;								// String
	int loglevel;
	char *logfile;
	char *logmethod;
	unsigned short port;
	char disableipv6;
	char preferipv6;
	char *cert;
	char *privkey;
	char *cacert;
	char *restrictouname;
	char *bnlpubkey;
	char *bnlprivkey;
	char *nodeinfofile;
	char *upcmd;
	char *subnetupcmd;
	char *mysubnetupcmd;
};

struct configfile_hostopts {
	char *node;
	struct configfile_algo_pref *cryptalgos;	// List terminated by an algo < 0
	struct configfile_algo_pref *compalgos;		// List terminated by an algo < 0
};

extern char configfile_origdir[CONFIGFILE_FILENAME_LEN];
extern char configfile_dir[CONFIGFILE_FILENAME_LEN];
extern char configfile_filename[CONFIGFILE_FILENAME_LEN];
extern struct configfile_globalopts global_config;
extern struct configfile_hostopts *host_config;

void configfile_free();
int configfile_loadfile(FILE *f);
int configfile_load();

#endif
