#!/bin/bash
if [ $# -ne 2 ]; then
	echo "Usage: $0 <CSR Filename> <Key Filename>"
	exit 1
fi
openssl req -nodes -config openssl-req.cnf -days 3650 -newkey rsa:1024 -out "${1}" -keyout "${2}" -outform PEM

