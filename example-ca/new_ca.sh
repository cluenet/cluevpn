#!/bin/bash

mkdir -p crl csr certs newcerts private private/genkeys
chmod 700 private
touch index
echo '01' > serial
openssl req -nodes -config openssl-ca.cnf -days 3650 -x509 -newkey rsa:2048 -out ca-cert.pem -outform PEM

