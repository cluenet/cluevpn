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


#ifndef _LOGGER_H
#define _LOGGER_H

#include <stdarg.h>

#define LOGGER_DEBUG 1
#define LOGGER_INFO 2
#define LOGGER_NOTICE 3
#define LOGGER_WARNING 4
#define LOGGER_ERR 5
#define LOGGER_CRIT 6
#define LOGGER_NONE 100

#define LOGGER_SYSLOG 1
#define LOGGER_FILE 2
#define LOGGER_STDERR 3

void logpreinitmsg(char *format, ...);
void logger_init(int minlevel);
void logmsg(int level, char *format, ...);
void logger_close();

#endif
