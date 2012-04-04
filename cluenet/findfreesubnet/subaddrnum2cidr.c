#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
	int cpow;
	int numaddr;
	int rcidr, cidr;
	if(argc != 2) {
		printf("Usage: %s <NumAddrs>\n", argv[0]);
		return 1;
	}
	numaddr = atoi(argv[1]);
	rcidr = 0;
	for(cpow = 1; cpow < numaddr; cpow <<= 1) rcidr++;
	cidr = 32 - rcidr;
	printf("%d\n", cidr);
	return 0;
}


