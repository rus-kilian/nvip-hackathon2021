#!/bin/bash -e
if [ $# -ne 1 -a ! -f "$1" ];then
    echo "No such PKCS12 file: $1"
    exit 1
fi
KEYSTORE_TMP=$(mktemp -d)
echo "Stopping proteusServer"
/usr/local/bluecat/proteusServer.sh stop
echo "Importing PKCS12 into keystore"
keytool -keypass bluecat -storepass bluecat -srcstorepass bluecat -importkeystore -srckeystore "$1" -srcstoretype PKCS12 -destkeystore "${KEYSTORE_TMP}/keystore" -noprompt
# keep permissions
cat "${KEYSTORE_TMP}/keystore" > /opt/server/proteus/etc/keystore
echo "Starting proteusServer"
/usr/local/bluecat/proteusServer.sh start
echo "Cleaning up"
rm -f "${KEYSTORE_TMP}/keystore" "$1"
rmdir "${KEYSTORE_TMP}"

