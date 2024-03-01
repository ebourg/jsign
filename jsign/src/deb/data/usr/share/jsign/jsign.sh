#!/bin/sh

java  $JSIGN_OPTS \
     -Djava.net.useSystemProxies=true \
     -Dbasename=`basename "$0"` \
     -jar /usr/share/jsign/jsign-@VERSION@.jar "$@"
