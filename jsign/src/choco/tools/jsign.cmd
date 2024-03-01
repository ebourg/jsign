@echo off

java %JSIGN_OPTS% ^
     -Djava.net.useSystemProxies=true ^
     -Dbasename=jsign ^
     -jar %~dp0\jsign.jar %*
