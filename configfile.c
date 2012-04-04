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
#include <strings.h>
#include <errno.h>
#include "logger.h"
#include "crypt.h"
#include "comp.h"
#include "configfile.h"

char configfile_origdir[CONFIGFILE_FILENAME_LEN] = ".";
char configfile_dir[CONFIGFILE_FILENAME_LEN] = CONFIGFILE_DIR_DEFAULT;
char configfile_filename[CONFIGFILE_FILENAME_LEN];

struct configfile_globalopts global_config;
struct configfile_hostopts *host_config;

void configfile_free() {
	struct configfile_hostopts *ccf;
	free(global_config.name);
	free(global_config.cryptalgos);
	free(global_config.compalgos);
	free(global_config.devname);
	free(global_config.cert);
	free(global_config.privkey);
	free(global_config.cacert);
	free(global_config.restrictouname);
	free(global_config.nodeinfofile);
	free(global_config.bnlpubkey);
	free(global_config.bnlprivkey);
	if(host_config) {
		for(ccf = host_config; ccf->node; ccf++) {
			free(ccf->cryptalgos);
			free(ccf->compalgos);
			free(ccf->node);
		}
	}
	free(host_config);
}

char configfile_parsebool(char *value) {
	if(strcasecmp(value, "true") == 0) return 1;
	if(strcasecmp(value, "yes") == 0) return 1;
	if(strcasecmp(value, "1") == 0) return 1;
	if(strcasecmp(value, "false") == 0) return 0;
	if(strcasecmp(value, "no") == 0) return 0;
	if(strcasecmp(value, "0") == 0) return 0;
	return 2;
}

struct configfile_algo_pref *configfile_parsealgopref(char *value, int algotype) {
	struct configfile_algo_pref *algos = NULL;
	int numalgos = 0;
	int i = 0;
	char *calgostr;
	char *clevelstr;
	char *cnumstr;
	char *endptr;
	int calgo, clevel, cnum;
	if(!value) return NULL;
	if(!*value) return NULL;
	for(;;) {
		if(!value[i]) return algos;
		calgostr = &value[i];
		for(; value[i] != ':' && value[i]; i++);
		if(!value[i]) { free(algos); return NULL; }
		value[i] = 0;
		i++;
		clevelstr = &value[i];
		for(; value[i] != ':' && value[i]; i++);
		if(!value[i]) { free(algos); return NULL; }
		value[i] = 0;
		i++;
		clevel = strtol(clevelstr, &endptr, 10);
		if(*endptr != 0) { free(algos); return NULL; }
		cnumstr = &value[i];
		for(; value[i] != ' ' && value[i]; i++);
		if(value[i]) {
			value[i] = 0;
			i++;
		}
		cnum = strtol(cnumstr, &endptr, 10);
		if(*endptr != 0) { free(algos); return NULL; }
		calgo = -1;
		if(algotype == 1) {
			if(strcmp(calgostr, "aescbc") == 0) calgo = CRYPT_AESCBC;
		}
		if(algotype == 2) {
			if(strcmp(calgostr, "none") == 0) calgo = COMP_NONE;
			if(strcmp(calgostr, "zlib") == 0) calgo = COMP_ZLIB;
		}
		if(calgo == -1) { free(algos); return NULL; }
		algos = realloc(algos, (numalgos + 2) * sizeof(struct configfile_algo_pref));
		algos[numalgos].algo = calgo;
		algos[numalgos].level = clevel;
		algos[numalgos].pref = cnum;
		numalgos++;
		algos[numalgos].algo = -1;
	}
}

int configfile_loadfile(FILE *f) {
	char line[2048];
	char *start, *key, *value;
	int i, l, linenum = 0;
	int numhostconf = 0;
	char *endptr;
	struct configfile_hostopts *chostconf = NULL;
	memset(&global_config, 0, sizeof(struct configfile_globalopts));
	global_config.id = -1;
	host_config = NULL;
	// Keep reading lines
	while(fgets(line, 2048, f)) {
		linenum++;
		l = strlen(line);
		// Strip off trailing newline
		for(i = 0; i < l; i++) if(line[i] == '\n') line[i] = 0;
		l = strlen(line);
		// Eliminate starting whitespace
		for(i = 0; line[i] == ' ' || line[i] == '\t'; i++);
		start = line + i;
		// Skip comments and blank lines
		if(start[0] == '#') continue;
		if(!start[0]) continue;
		// Go through characters until a = is found
		key = start;
		for(value = key; *value != '=' && *value; value++);
		if(!*value) {
			logpreinitmsg("Malformed configuration file: Line %d", linenum);
			configfile_free();
			return CONFIGFILE_MALFORMED;
		}
		// Setting this to a NULL makes the key a string
		*value = 0;
		// The value starts here, ends at the end of the line
		value++;
		// Check if it's a "node" option, for specific host options
		if(strcmp(key, "node") == 0) {
			host_config = realloc(host_config, (numhostconf + 2) * sizeof(struct configfile_hostopts));
			chostconf = &host_config[numhostconf];
			numhostconf++;
			host_config[numhostconf].node = NULL;
			chostconf->node = malloc(strlen(value) + 1);
			strcpy(chostconf->node, value);
		} else {
			// If chostconf is NULL, check for global options
			if(chostconf == NULL) {
				if(strcmp(key, "name") == 0) {
					global_config.name = malloc(strlen(value) + 1);
					strcpy(global_config.name, value);
				} else if(strcmp(key, "devname") == 0) {
					global_config.devname = malloc(strlen(value) + 1);
					strcpy(global_config.devname, value);
				} else if(strcmp(key, "cert") == 0) {
					global_config.cert = malloc(strlen(value) + 1);
					strcpy(global_config.cert, value);
				} else if(strcmp(key, "privkey") == 0) {
					global_config.privkey = malloc(strlen(value) + 1);
					strcpy(global_config.privkey, value);
				} else if(strcmp(key, "cacert") == 0) {
					global_config.cacert = malloc(strlen(value) + 1);
					strcpy(global_config.cacert, value);
				} else if(strcmp(key, "restrictouname") == 0) {
					global_config.restrictouname = malloc(strlen(value) + 1);
					strcpy(global_config.restrictouname, value);
				} else if(strcmp(key, "nodeinfofile") == 0) {
					global_config.nodeinfofile = malloc(strlen(value) + 1);
					strcpy(global_config.nodeinfofile, value);
				} else if(strcmp(key, "bnlpubkey") == 0) {
					global_config.bnlpubkey = strdup(value);
					// Reminder: Make all the other string copy things strdup()
				} else if(strcmp(key, "bnlprivkey") == 0) {
					global_config.bnlprivkey = strdup(value);
				} else if(strcmp(key, "upcmd") == 0) {
					global_config.upcmd = strdup(value);
				} else if(strcmp(key, "subnetupcmd") == 0) {
					global_config.subnetupcmd = strdup(value);
				} else if(strcmp(key, "mysubnetupcmd") == 0) {
					global_config.mysubnetupcmd = strdup(value);
				} else if(strcmp(key, "logfile") == 0) {
					global_config.logfile = strdup(value);
				} else if(strcmp(key, "logmethod") == 0) {
					global_config.logmethod = strdup(value);
				} else if(strcmp(key, "id") == 0) {
					global_config.id = strtol(value, &endptr, 10);
					if(*endptr) {
						logpreinitmsg("Malformed configuration file: Line %d", linenum);
						configfile_free();
						return CONFIGFILE_MALFORMED;
					}
				} else if(strcmp(key, "loglevel") == 0) {
					global_config.loglevel = strtol(value, &endptr, 10);
					if(*endptr) {
						logpreinitmsg("Malformed configuration file: Line %d", linenum);
						configfile_free();
						return CONFIGFILE_MALFORMED;
					}
				} else if(strcmp(key, "port") == 0) {
					global_config.port = strtol(value, &endptr, 10);
					if(*endptr) {
						logpreinitmsg("Malformed configuration file: Line %d", linenum);
						configfile_free();
						return CONFIGFILE_MALFORMED;
					}
				} else if(strcmp(key, "cryptalgos") == 0) {
					global_config.cryptalgos = configfile_parsealgopref(value, 1);
					if(global_config.cryptalgos == NULL) {
						logpreinitmsg("Malformed configuration file: Line %d", linenum);
						configfile_free();
						return CONFIGFILE_MALFORMED;
					}
				} else if(strcmp(key, "compalgos") == 0) {
					global_config.compalgos = configfile_parsealgopref(value, 2);
					if(global_config.compalgos == NULL) {
						logpreinitmsg("Malformed configuration file: Line %d", linenum);
						configfile_free();
						return CONFIGFILE_MALFORMED;
					}
				} else if(strcmp(key, "disableipv6") == 0) {
					global_config.disableipv6 = configfile_parsebool(value);
					if(global_config.disableipv6 == 2) {
						logpreinitmsg("Malformed configuration file: Line %d", linenum);
						configfile_free();
						return CONFIGFILE_MALFORMED;
					}
				} else if(strcmp(key, "preferipv6") == 0) {
					global_config.preferipv6 = configfile_parsebool(value);
					if(global_config.preferipv6 == 2) {
						logpreinitmsg("Malformed configuration file: Line %d", linenum);
						configfile_free();
						return CONFIGFILE_MALFORMED;
					}
				} else {
					logpreinitmsg("Malformed configuration file: Line %d", linenum);
					configfile_free();
					return CONFIGFILE_MALFORMED;
				}
			} else {
				if(strcmp(key, "cryptalgos") == 0) {
					chostconf->cryptalgos = configfile_parsealgopref(value, 1);
					if(chostconf->cryptalgos == NULL) {
						logpreinitmsg("Malformed configuration file: Line %d", linenum);
						configfile_free();
						return CONFIGFILE_MALFORMED;
					}
				} else if(strcmp(key, "compalgos") == 0) {
					chostconf->compalgos = configfile_parsealgopref(value, 2);
					if(chostconf->compalgos == NULL) {
						logpreinitmsg("Malformed configuration file: Line %d", linenum);
						configfile_free();
						return CONFIGFILE_MALFORMED;
					}
				} else {
					logpreinitmsg("Malformed configuration file: Line %d", linenum);
					configfile_free();
					return CONFIGFILE_MALFORMED;
				}
			}
		}
	}
	// Check for required entries
	if(!global_config.name) {
		logpreinitmsg("Configuration file missing \"name\" entry.");
		configfile_free();
		return CONFIGFILE_MALFORMED;
	}
	/*if(global_config.id == -1) {
		logpreinitmsg("Configuration file missing \"id\" entry.");
		configfile_free();
		return CONFIGFILE_MALFORMED;
	}*/
	return CONFIGFILE_OK;
}

void configfile_initfilenames() {
	strcpy(configfile_filename, configfile_dir);
	strcat(configfile_filename, "/");
	strcat(configfile_filename, CONFIGFILE_FILENAME);
}

int configfile_load() {
	FILE *f;
	int r;
	configfile_initfilenames();
	f = fopen(configfile_filename, "r");
	if(!f) {
		logpreinitmsg("Error opening config file \"%s\": %s", configfile_filename, strerror(errno));
		return CONFIGFILE_ERROR;
	}
	r = configfile_loadfile(f);
	fclose(f);
	return r;
}

