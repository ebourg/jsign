#!/bin/sh

java -Xmx128m -Djava.net.useSystemProxies=true -jar /usr/share/jsign/jsign-app-1.4.jar "$@"
