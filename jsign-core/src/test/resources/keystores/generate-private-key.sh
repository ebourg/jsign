#!/bin/sh
#
# Script generating a private key in various formats
#

# Generate the PKCS#1 and PKCS#8 keys
openssl genrsa -aes128 -traditional -passout pass:password -out privatekey-encrypted.pkcs1.pem 2048
openssl pkcs8 -topk8       -in privatekey-encrypted.pkcs1.pem -out privatekey-encrypted.pkcs8.pem -passin pass:password -passout pass:password -v2 aes128
openssl pkcs8 -topk8       -in privatekey-encrypted.pkcs1.pem -out privatekey.pkcs8.pem -passin pass:password -nocrypt
openssl pkcs8 -traditional -in privatekey.pkcs8.pem           -out privatekey.pkcs1.pem -nocrypt

# Generate the PVK files
# This requires an OpenSSL version with RC4 enabled (works on Debian Stretch)
openssl rsa -in privatekey.pkcs8.pem -outform PVK -out privatekey.pvk                  -pvk-none
openssl rsa -in privatekey.pkcs8.pem -outform PVK -out privatekey-encrypted.pvk        -pvk-weak   -passout pass:password
openssl rsa -in privatekey.pkcs8.pem -outform PVK -out privatekey-encrypted-strong.pvk -pvk-strong -passout pass:password
