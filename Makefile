.PHONY: all clean install uninstall debinstall

CFLAGS := -g -O2
LDFLAGS := 
LDLIBS := -lssl

BIN := bnlutil cluevpn csv2bnl signfile

DESTDIR :=

all: $(BIN)

clean:
	rm -f $(BIN)
	rm -f *.o

install: all
	install -d $(DESTDIR)/usr/bin
	install -m0755 bnlutil $(DESTDIR)/usr/bin/
	install -m0755 cluevpn $(DESTDIR)/usr/bin/
	install -m0755 csv2bnl $(DESTDIR)/usr/bin/
	install -d $(DESTDIR)/etc/cluevpn
	install -m0644 cluevpn.conf-example $(DESTDIR)/etc/cluevpn/
	install -m0644 vpn-up-example.sh $(DESTDIR)/etc/cluevpn/
	install -m0644 my-subnet-up-example.sh $(DESTDIR)/etc/cluevpn

uninstall:
	rm -rf /usr/local/bin/csv2bnl /usr/local/bin/bnlutil /usr/local/sbin/cluevpn
	rm -rf /etc/init.d/cluevpn /etc/rc2.d/S55cluevpn

debinstall: install
	install -m0755 initscripts/debian.sh /etc/init.d/cluevpn
	update-rc.d -f cluevpn defaults

bnlutil: bnlutil.o configfile.o signature.o logger.o bnl.o nodeinfo.o connections.o routetable.o seqnum.o tunio.o
cluevpn: cluevpn.o comp.o comp_zlib.o configfile.o connections.o crypt_aescbc.o crypt.o dsv.o logger.o routetable.o seqnum.o signature.o tunio.o bnl.o nodeinfo.o netpackets.o tcpcons.o datapackage.o
csv2bnl: csv2bnl.o configfile.o dsv.o signature.o logger.o
signfile: signfile.o

bnl.o: bnl.c bnl.h logger.h crypt.h configfile.h nodeinfo.h routetable.h
bnlutil.o: bnlutil.c configfile.h signature.h bnl.h
comp.o: comp.c comp.h comp_zlib.h
comp_zlib.o: comp_zlib.c comp_zlib.h comp.h
configfile.o: configfile.c configfile.h logger.h crypt.h comp.h
connections.o: connections.c connections.h tunio.h logger.h configfile.h
crypt.o: crypt.c crypt.h crypt_aescbc.h
crypt_aescbc.o: crypt_aescbc.c crypt_aescbc.h crypt.h
csv2bnl.o: csv2bnl.c configfile.h bnl.h dsv.h
datapackage.o: datapackage.c datapackage.h logger.h configfile.h nodeinfo.h crypt.h comp.h seqnum.h
dsv.o: dsv.c dsv.h
hostidmap.o: hostidmap.c hostidmap.h
logger.o: logger.c logger.h
cluevpn.o: cluevpn.c routetable.h configfile.h logger.h signature.h nodeinfo.h bnl.h comp.h crypt.h connections.h nodeinfo.h netpackets.h tcpcons.h datapackage.h
netpackets.o: netpackets.c netpackets.h
nodeinfo.o: nodeinfo.c nodeinfo.h logger.h crypt.h configfile.h
routetable.o: routetable.c routetable.h
seqnum.o: seqnum.c seqnum.h
signature.o: signature.c signature.h logger.h configfile.h
signfile.o: signfile.c
tcpcons.o: tcpcons.c tcpcons.h connections.h configfile.h nodeinfo.h crypt.h comp.h seqnum.h tcpcons.h
tunio.o: tunio.c tunio.h logger.h
