#!/bin/sh

java -Xmx128m -Djava.net.useSystemProxies=true -Dbasename=`basename "$0"` -jar /usr/share/jsign/jsign-@VERSION@.jar "$@"
