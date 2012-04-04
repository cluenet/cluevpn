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
#include <stdarg.h>
#include <syslog.h>
#include "logger.h"
#include "configfile.h"

int log_minlevel;
char log_inited = 0;
int log_type = LOGGER_STDERR;
FILE *log_file;

void logpreinitmsg(char *format, ...) {
	va_list ap;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

void logger_init(int minlevel) {
	if(!global_config.logmethod) {
		log_type = LOGGER_SYSLOG;
	} else if(strcmp(global_config.logmethod, "syslog") == 0) {
		log_type = LOGGER_SYSLOG;
	} else if(strcmp(global_config.logmethod, "file") == 0) {
		log_type = LOGGER_FILE;
		if(!global_config.logfile) log_type = LOGGER_SYSLOG;
	} else if(strcmp(global_config.logmethod, "stderr") == 0) {
		log_type = LOGGER_STDERR;
	} else {
		fprintf(stderr, "Invalid log method\n");
		log_type = LOGGER_SYSLOG;
	}
	if(log_type == LOGGER_SYSLOG) {
		openlog("cluevpn", 0, LOG_DAEMON);
	} else if(log_type == LOGGER_FILE) {
		log_file = fopen(global_config.logfile, "a");
		if(!log_file) {
			fprintf(stderr, "Error opening log file\n");
			log_type = LOGGER_STDERR;
		}
	} else if(log_type == LOGGER_STDERR) {}
	log_minlevel = minlevel;
	log_inited = 1;
}

void logmsg(int level, char *format, ...) {
	char *msgbuf;
	va_list ap;
	int sysloglevel;
	if(!log_inited) {
		va_start(ap, format);
		vfprintf(stderr, format, ap);
		va_end(ap);
		fprintf(stderr, "\n");
		return;
	}
	if(level < log_minlevel) return;
	sysloglevel = LOGGER_NONE;
	if(level == LOGGER_DEBUG) sysloglevel = LOG_DEBUG;
	if(level == LOGGER_INFO) sysloglevel = LOG_INFO;
	if(level == LOGGER_NOTICE) sysloglevel = LOG_NOTICE;
	if(level == LOGGER_WARNING) sysloglevel = LOG_WARNING;
	if(level == LOGGER_ERR) sysloglevel = LOG_ERR;
	if(level == LOGGER_CRIT) sysloglevel = LOG_CRIT;
	if(level == LOGGER_NONE) return;
	msgbuf = malloc(1024);
	va_start(ap, format);
	msgbuf[1023] = 0;
	vsnprintf(msgbuf, 1023, format, ap);
	va_end(ap);
	if(log_type == LOGGER_SYSLOG) {
		syslog(sysloglevel, "%s", msgbuf);
	} else if(log_type == LOGGER_FILE) {
		fprintf(log_file, "%s\n", msgbuf);
	} else if(log_type == LOGGER_STDERR) {
		fprintf(stderr, "%s\n", msgbuf);
	}
	free(msgbuf);
}

void logger_close() {
	if(log_type == LOGGER_SYSLOG) {
		closelog();
	} else if(log_type == LOGGER_FILE) {
		fclose(log_file);
	}
}
