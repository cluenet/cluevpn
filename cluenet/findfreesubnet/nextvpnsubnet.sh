#!/bin/bash

VPNNET="10.156.0.0/16"

if [ $# -ne 1 ]; then
	echo "Usage: $0 <NumHosts>"
	exit 1
fi

if [ ! -f ./addrfile.txt ]; then
	echo "$VPNNET" | sed 's|/| |' > ./addrfile.txt
fi

CIDR="`./numhosts2cidr.sh $1`"
if [ $? -ne 0 ]; then
	echo "Error executing script."
	exit 1
fi

./findfreesubnet ./addrfile.txt $CIDR
exit $?

