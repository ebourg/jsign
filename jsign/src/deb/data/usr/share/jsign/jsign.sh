#!/bin/sh

# Allow unsafe memory access with Java 23+ to avoid warnings when signing MSI files
if java --sun-misc-unsafe-memory-access=allow -version >/dev/null 2>&1; then
    JSIGN_OPTS="--sun-misc-unsafe-memory-access=allow $JSIGN_OPTS"
fi

java  $JSIGN_OPTS \
     -Djava.net.useSystemProxies=true \
     -Dbasename=`basename "$0"` \
     -jar /usr/share/jsign/jsign-@VERSION@.jar "$@"
