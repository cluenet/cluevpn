#!/bin/bash

openssl dsaparam -out dsaparam.pem 2048
openssl gendsa -out bnlkey-priv.pem dsaparam.pem
openssl dsa -in bnlkey-priv.pem -out bnlkey-pub.pem -pubout
rm -f dsaparam.pem
echo "BNL Private Key In: ./bnlkey-priv.pem"
echo "BNL Public Key In: ./bnlkey-pub.pem"

