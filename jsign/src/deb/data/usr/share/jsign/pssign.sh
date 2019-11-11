#!/bin/sh

java -Xmx128m -Djava.net.useSystemProxies=true -cp /usr/share/jsign/jsign-@VERSION@.jar net.jsign.PSSignerCLI "$@"
