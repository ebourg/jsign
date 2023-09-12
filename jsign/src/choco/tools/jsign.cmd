@echo off

java %JSIGN_OPTS% ^
     -Djava.net.useSystemProxies=true ^
     -Dbasename=jsign ^
     -Dlog4j2.loggerContextFactory=net.jsign.log4j.simple.SimpleLoggerContextFactory ^
     -jar %~dp0\jsign.jar %*
