#!/bin/bash

if [ $# -ne 1 ]; then
	echo "Usage: $0 <NodeName>"
	exit 1
fi

openssl req -nodes -config openssl-req.cnf -days 3650 -newkey rsa:1024 -out "csr/${1}.csr" -keyout "private/genkeys/${1}.key" -outform PEM
./sign.sh "csr/${1}.csr" "certs/${1}.cert"

echo "Certificate is in certs/${1}.cert"
echo "Key is in private/genkeys/${1}.key"

exit 0

