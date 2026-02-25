#!/bin/sh
#
# Script generating a certificate chain
#

rm -f jsign-* keystore*

# Create the file defining the x509 extensions
cat > extensions.cnf <<- "EOF"
[ root ]
basicConstraints = CA:TRUE
keyUsage = keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer

[ intermediate ]
basicConstraints = CA:TRUE,pathlen:0
keyUsage = keyCertSign,cRLSign
extendedKeyUsage = codeSigning
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
authorityInfoAccess = caIssuers;URI:http://raw.githubusercontent.com/ebourg/jsign/master/jsign-core/src/test/resources/keystores/jsign-root-ca.cer

[ final ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = codeSigning
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
authorityInfoAccess = @aia
[ aia ]
caIssuers;URI.1 = ldap://ldap.example.com/CN=Jsign%20Code%20Signing%20CA,CN=AIA,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=jsign,DC=net?cACertificate?base?objectClass=certificationAuthority
caIssuers;URI.2 = http://raw.githubusercontent.com/ebourg/jsign/master/jsign-core/src/test/resources/keystores/jsign-code-signing-ca.cer
EOF

CERT_OPTS="-days 7305 -text -sha256"
YEAR=$(date +'%Y')

# Generate the root certificate
openssl req -new -newkey rsa:4096 -nodes -keyout jsign-root-ca.key -x509 -extensions v3_ca -subj "/CN=Jsign Root Certificate Authority $YEAR" -out jsign-root-ca.pem $CERT_OPTS
openssl x509 -in jsign-root-ca.pem -out jsign-root-ca.cer -outform DER

# Generate the intermediate certificate
openssl req -new -newkey rsa:2048 -nodes -keyout jsign-code-signing-ca.key -subj "/CN=Jsign Code Signing CA $YEAR" -out jsign-code-signing-ca.csr
openssl x509 -req -in jsign-code-signing-ca.csr -CA jsign-root-ca.pem -CAkey jsign-root-ca.key -CAcreateserial \
             -out jsign-code-signing-ca.pem $CERT_OPTS -extfile extensions.cnf -extensions intermediate
openssl x509 -in jsign-code-signing-ca.pem -out jsign-code-signing-ca.cer -outform DER

# Generate the test certificates (reusing the existing keys)
openssl req -new -key privatekey.pkcs1.pem -subj "/CN=Jsign Code Signing Test Certificate $YEAR (RSA)" -out jsign-test-certificate.csr
openssl x509 -req -in jsign-test-certificate.csr -CA jsign-code-signing-ca.pem -CAkey jsign-code-signing-ca.key -CAcreateserial \
             -out jsign-test-certificate.pem $CERT_OPTS -extfile extensions.cnf -extensions final

openssl req -new -key privatekey-ec-p384.pkcs1.pem -subj "/CN=Jsign Code Signing Test Certificate $YEAR (EC)" -out jsign-test-certificate-ec.csr
openssl x509 -req -in jsign-test-certificate-ec.csr -CA jsign-code-signing-ca.pem -CAkey jsign-code-signing-ca.key -CAcreateserial \
             -out jsign-test-certificate-ec.pem $CERT_OPTS -extfile extensions.cnf -extensions final

openssl req -new -key privatekey-ed25519.pem -subj "/CN=Jsign Code Signing Test Certificate $YEAR (Ed25519)" -out jsign-test-certificate-ed25519.csr
openssl x509 -req -in jsign-test-certificate-ed25519.csr -CA jsign-code-signing-ca.pem -CAkey jsign-code-signing-ca.key -CAcreateserial \
             -out jsign-test-certificate-ed25519.pem $CERT_OPTS -extfile extensions.cnf -extensions final

openssl req -new -key privatekey-ed448.pem -subj "/CN=Jsign Code Signing Test Certificate $YEAR (Ed448)" -out jsign-test-certificate-ed448.csr
openssl x509 -req -in jsign-test-certificate-ed448.csr -CA jsign-code-signing-ca.pem -CAkey jsign-code-signing-ca.key -CAcreateserial \
             -out jsign-test-certificate-ed448.pem $CERT_OPTS -extfile extensions.cnf -extensions final

openssl req -new -key privatekey.pkcs1.pem -x509 -subj "/CN=Jsign Code Signing Test Certificate $YEAR (self-signed)" -out jsign-test-certificate-self-signed.pem $CERT_OPTS

# Generate the certificate chains
cat jsign-root-ca.pem jsign-code-signing-ca.pem jsign-test-certificate.pem > jsign-test-certificate-full-chain-reversed.pem
cat jsign-test-certificate.pem jsign-code-signing-ca.pem jsign-root-ca.pem > jsign-test-certificate-full-chain.pem
cat jsign-root-ca.pem jsign-code-signing-ca.pem > jsign-test-certificate-partial-chain-reversed.pem
cat jsign-code-signing-ca.pem jsign-root-ca.pem > jsign-test-certificate-partial-chain.pem

# Generate the SPC files (DER encoded certificate chains)
openssl crl2pkcs7 -nocrl -certfile jsign-test-certificate-full-chain.pem          -outform DER -out jsign-test-certificate-full-chain.spc
openssl crl2pkcs7 -nocrl -certfile jsign-test-certificate-full-chain-reversed.pem -outform DER -out jsign-test-certificate-full-chain-reversed.spc

# Generate the PKCS#12 keystores
OPENSSL_OPTS="-export -inkey privatekey.pkcs1.pem -name test -passout pass:password"
openssl pkcs12 $OPENSSL_OPTS -in jsign-test-certificate-full-chain.pem -out keystore.p12
openssl pkcs12 $OPENSSL_OPTS -in jsign-test-certificate.pem            -out keystore-no-chain.p12

OPENSSL_OPTS="-export -inkey privatekey-ec-p384.pkcs1.pem -name test -passout pass:password"
openssl pkcs12 $OPENSSL_OPTS -in jsign-test-certificate-ec.pem         -out keystore-ec.p12

OPENSSL_OPTS="-export -inkey privatekey-ed25519.pem -name test -passout pass:password"
openssl pkcs12 $OPENSSL_OPTS -in jsign-test-certificate-ed25519.pem    -out keystore-ed25519.p12

OPENSSL_OPTS="-export -inkey privatekey-ed448.pem -name test -passout pass:password"
openssl pkcs12 $OPENSSL_OPTS -in jsign-test-certificate-ed448.pem      -out keystore-ed448.p12

# Generate the Java keystores
KEYTOOL_OPTS="-importkeystore -srcstoretype pkcs12 -srcstorepass password -srcalias test -deststoretype jks -deststorepass password -destalias test"
keytool $KEYTOOL_OPTS -srckeystore keystore.p12          -destkeystore keystore.jks
keytool $KEYTOOL_OPTS -srckeystore keystore-no-chain.p12 -destkeystore keystore-no-chain.jks

KEYTOOL_OPTS="-importkeystore -srcstoretype pkcs12 -srcstorepass password -srcalias test -deststoretype jceks -deststorepass password -destalias test"
keytool $KEYTOOL_OPTS -srckeystore keystore.p12          -destkeystore keystore.jceks

# Generate the keystore with two entries
cp keystore.p12 keystore-two-entries.p12
keytool -importkeystore \
        -srcstoretype  pkcs12 -srcstorepass  password -srcalias  test  -srckeystore keystore.p12 \
        -deststoretype pkcs12 -deststorepass password -destalias test2 -destkeystore keystore-two-entries.p12

# Generate the empty keystore
cp keystore.p12 keystore-empty.p12
keytool -delete -alias test -storepass password -keystore keystore-empty.p12

# Cleanup
rm *.srl
rm jsign-root-ca.key
rm jsign-code-signing-ca.key
rm jsign-code-signing-ca.csr
rm jsign-test-certificate*.csr
rm extensions.cnf
