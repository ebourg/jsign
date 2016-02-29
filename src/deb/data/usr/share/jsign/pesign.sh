#!/bin/sh

java -Xmx128m -Djava.net.useSystemProxies=true -jar /usr/share/jsign/jsign-1.2.jar "$@"
