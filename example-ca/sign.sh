#!/bin/bash
if [ $# -ne 2 ]; then
	echo "Usage: $0 <Input CSR> <Output Cert>"
	exit 1
fi
openssl ca -batch -config openssl-ca.cnf -in "$1" -out "$2"

