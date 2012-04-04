CFLAGS = -g -O2

all: signfile csv2bnl bnlutil cluevpn
clean:
	rm -rf signfile csv2bnl cluevpn bnlutil
	rm -rf *.o
install: all
	mkdir -p /usr/local/bin
	mkdir -p /usr/local/sbin
	mkdir -p /etc/cluevpn
	cp csv2bnl bnlutil /usr/local/bin
	cp cluevpn /usr/local/sbin
	cp cluevpn.conf-example /etc/cluevpn
	cp vpn-up-example.sh my-subnet-up-example.sh /etc/cluevpn
uninstall:
	rm -rf /usr/local/bin/csv2bnl /usr/local/bin/bnlutil /usr/local/sbin/cluevpn
	rm -rf /etc/init.d/cluevpn /etc/rc2.d/S55cluevpn

debinstall: install
	cp initscript-debian /etc/init.d/cluevpn
	ln -s /etc/init.d/cluevpn /etc/rc2.d/S55cluevpn

signfile: signfile.o
	cc $(CFLAGS) signfile.o -lssl -o signfile
csv2bnl: csv2bnl.o configfile.o dsv.o signature.o logger.o
	cc $(CFLAGS) csv2bnl.o configfile.o dsv.o signature.o logger.o -lssl -o csv2bnl
bnlutil: bnlutil.o configfile.o signature.o logger.o bnl.o nodeinfo.o connections.o routetable.o seqnum.o tunio.o
	cc $(CFLAGS) bnlutil.o configfile.o signature.o logger.o bnl.o nodeinfo.o connections.o routetable.o seqnum.o tunio.o -lssl -o bnlutil
cluevpn: main.o comp.o comp_zlib.o configfile.o connections.o crypt_aescbc.o crypt.o dsv.o logger.o routetable.o seqnum.o signature.o tunio.o bnl.o nodeinfo.o netpackets.o tcpcons.o datapackage.o
	cc $(CFLAGS) main.o comp.o comp_zlib.o configfile.o connections.o crypt_aescbc.o crypt.o dsv.o logger.o routetable.o seqnum.o signature.o tunio.o bnl.o nodeinfo.o netpackets.o tcpcons.o datapackage.o -lssl -lz -o cluevpn

comp.o: comp.c comp.h comp_zlib.h
	cc $(CFLAGS) -c comp.c
comp_zlib.o: comp_zlib.c comp_zlib.h comp.h
	cc $(CFLAGS) -c comp_zlib.c
configfile.o: configfile.c configfile.h logger.h crypt.h comp.h
	cc $(CFLAGS) -c configfile.c
connections.o: connections.c connections.h tunio.h logger.h configfile.h
	cc $(CFLAGS) -c connections.c
crypt_aescbc.o: crypt_aescbc.c crypt_aescbc.h crypt.h
	cc $(CFLAGS) -c crypt_aescbc.c
crypt.o: crypt.c crypt.h crypt_aescbc.h
	cc $(CFLAGS) -c crypt.c
dsv.o: dsv.c dsv.h
	cc $(CFLAGS) -c dsv.c
hostidmap.o: hostidmap.c hostidmap.h
	cc $(CFLAGS) -c hostidmap.c
logger.o: logger.c logger.h
	cc $(CFLAGS) -c logger.c
routetable.o: routetable.c routetable.h
	cc $(CFLAGS) -c routetable.c
seqnum.o: seqnum.c seqnum.h
	cc $(CFLAGS) -c seqnum.c
signature.o: signature.c signature.h logger.h configfile.h
	cc $(CFLAGS) -c signature.c
signfile.o: signfile.c
	cc $(CFLAGS) -c signfile.c
tunio.o: tunio.c tunio.h logger.h
	cc $(CFLAGS) -c tunio.c
bnl.o: bnl.c bnl.h logger.h crypt.h configfile.h nodeinfo.h routetable.h
	cc $(CFLAGS) -c bnl.c
csv2bnl.o: csv2bnl.c configfile.h bnl.h dsv.h
	cc $(CFLAGS) -c csv2bnl.c
bnlutil.o: bnlutil.c configfile.h signature.h bnl.h
	cc $(CFLAGS) -c bnlutil.c
nodeinfo.o: nodeinfo.c nodeinfo.h logger.h crypt.h configfile.h
	cc $(CFLAGS) -c nodeinfo.c
netpackets.o: netpackets.c netpackets.h
	cc $(CFLAGS) -c netpackets.c
tcpcons.o: tcpcons.c tcpcons.h connections.h configfile.h nodeinfo.h crypt.h comp.h seqnum.h tcpcons.h
	cc $(CFLAGS) -c tcpcons.c
datapackage.o: datapackage.c datapackage.h logger.h configfile.h nodeinfo.h crypt.h comp.h seqnum.h
	cc $(CFLAGS) -c datapackage.c
main.o: main.c routetable.h configfile.h logger.h signature.h nodeinfo.h bnl.h comp.h crypt.h connections.h nodeinfo.h netpackets.h tcpcons.h datapackage.h
	cc $(CFLAGS) -c main.c

