#!/usr/bin/env sh
if [ -z $1 ]; then
    echo "no domain provided"
    exit 1
fi

BASE="/etc/ssl/acme/$1"
TMP_RESP_FILE=$(mktemp /tmp/ocsp.XXXXXXXXXX)

if [ -z "$TMP_RESP_FILE" ]; then
    echo "cant create tmp file"
    exit 1
fi

OCSP_URL=$(openssl x509 -in "${BASE}/cert.cer" -ocsp_uri -nocert)

openssl ocsp \
-issuer "${BASE}/ca.cer" \
-cert "${BASE}/cert.cer" \
-signkey "${BASE}/cert.key" \
-url $OCSP_URL \
-respout $TMP_RESP_FILE

EXIT_STATUS=$?
if [ $EXIT_STATUS -ne 0 ]; then
    echo 'openssl not exit successfully'
    exit $EXIT_STATUS
fi

mv $TMP_RESP_FILE "${BASE}/ocsp"