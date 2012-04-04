#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

int main(int argc, char **argv) {
	char *subaddrs;
	FILE *f;
	int r;
	char addrstr[256];
	int ccidr;
	struct in_addr wideaddr, caddr;
	int widecidr;
	struct in_addr naddr;
	int i;
	unsigned int wideaddroff;
	unsigned int caddroff;
	int wantcidr;
	struct in_addr freesub;
	unsigned int tmp;
	if(argc != 3) {
		printf("Usage: %s <AllocSubnetList> <CIDRSize>\n", argv[0]);
		return 1;
	}
	f = fopen(argv[1], "r");
	if(!f) {
		printf("Error opening file.\n");
		return 1;
	}
	wantcidr = atoi(argv[2]);
	// First line is entire subnet
	r = fscanf(f, "%s %d", addrstr, &ccidr);
	if(r != 2) {
		printf("Invalid file format for wide subnet.\n");
		return 1;
	}
	// Convert address to binary format
	r = inet_pton(AF_INET, addrstr, &wideaddr);
	if(r != 1) {
		printf("Invalid address.\n");
		return 1;
	}
	widecidr = ccidr;
	if(widecidr > 29) {
		printf("Wide subnet too small.\n");
		return 1;
	}
	// Allocate the array of all currently used subnet addrs - one bit per addr
	subaddrs = malloc((((int)0x01) << (32 - widecidr)) / 8);
	memset(subaddrs, 0, (((int)0x01) << (32 - widecidr)) / 8);
	// Read lines from file and set bits corresponding to used addresses
	for(;;) {
		r = fscanf(f, "%s %d", addrstr, &ccidr);
		if(r == EOF || r == 0) break;
		if(r != 2) {
			printf("Invalid file format for subnet.\n");
			return 1;
		}
		r = inet_pton(AF_INET, addrstr, &caddr);
		if(r != 1) {
			printf("Invalid address.\n");
			return 1;
		}
		naddr = caddr;
		for(i = 0; i < (((int)0x01) << (32 - ccidr)); i++) {
			wideaddroff = ntohl(*(unsigned int *)&naddr) - ntohl(*(unsigned int *)&wideaddr);
			subaddrs[wideaddroff / 8] |= (0x80 >> (wideaddroff % 8));
			tmp = htonl(ntohl(*(unsigned int *)&naddr) + 1);
			naddr = *(struct in_addr *)&tmp;
		}
	}
	fclose(f);
	// Go through each possible subnet of the desired size and select one that is entirely free
	for(caddroff = 0; caddroff < (((int)0x01) << (32 - widecidr)); caddroff += (((int)0x01) << (32 - wantcidr))) {
		for(i = 0; i < (((int)0x01) << (32 - wantcidr)); i++) {
			if(subaddrs[(caddroff + i) / 8] & (0x80 >> ((caddroff + i) % 8))) break;
		}
		if(i == (((int)0x01) << (32 - wantcidr))) break;
	}
	if(caddroff == (((int)0x01) << (32 - widecidr))) {
		printf("No free subnet.\n");
		return 1;
	}
	tmp = htonl(ntohl(*(unsigned int *)&wideaddr) + caddroff);
	freesub = *(struct in_addr *)&tmp;
	inet_ntop(AF_INET, &freesub, addrstr, 256);
	f = fopen(argv[1], "a");
	if(!f) {
		printf("Error opening file.\n");
		return 1;
	}
	fprintf(f, "%s %d\n", addrstr, wantcidr);
	fclose(f);
	printf("%s/%d\n", addrstr, wantcidr);
	return 0;
}


