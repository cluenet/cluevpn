#!/bin/bash
VPNSUBNETCIDR=16
if [ ! -x /sbin/ip ]; then exit 1; fi
if [ "$SUBADDRTYPE" = "INET" ]; then
	BASEIP="`echo $SUBNET | cut -d / -f 1`"
	SUBCIDR="`echo $SUBNET | cut -d / -f 2`"
	if [ $SUBCIDR -ge 31 ]; then
		MYIP="$BASEIP"
	else
		OCT1="`echo $BASEIP | cut -d . -f 1`"
		OCT2="`echo $BASEIP | cut -d . -f 2`"
		OCT3="`echo $BASEIP | cut -d . -f 3`"
		OCT4="`echo $BASEIP | cut -d . -f 4`"
		NEWOCT4="`expr $OCT4 + 1`"
		MYIP="${OCT1}.${OCT2}.${OCT3}.${NEWOCT4}"
	fi
	ip addr add ${MYIP}/$VPNSUBNETCIDR dev $TUNDEV
fi
exit 0

