#!/bin/bash

if [ $# -ne 1 ]; then
	echo "Usage: $0 <NumHosts>"
	exit 1
fi

if [ $1 -eq 1 ]; then echo 32; exit 0; fi
if [ $1 -eq 2 ]; then echo 31; exit 0; fi
if [ $1 -eq 256 ]; then echo 24; exit 0; fi

RNUM="`expr $1 + 2`"
./subaddrnum2cidr $RNUM
exit $?

