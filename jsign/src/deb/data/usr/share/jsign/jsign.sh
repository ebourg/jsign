#!/bin/sh

java -Djava.net.useSystemProxies=true -Dbasename=`basename "$0"` -Dlog4j2.loggerContextFactory=net.jsign.log4j.simple.SimpleLoggerContextFactory -jar /usr/share/jsign/jsign-@VERSION@.jar "$@"
