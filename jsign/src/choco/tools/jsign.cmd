@echo off
setlocal

@rem Add the YubiKey library path to the PATH environment variable
if exist "C:\Program Files\Yubico\Yubico PIV Tool\bin\" (
    set "PATH=%PATH%;C:\Program Files\Yubico\Yubico PIV Tool\bin"
)

java %JSIGN_OPTS% ^
     -Djava.net.useSystemProxies=true ^
     -Dbasename=jsign ^
     -jar %~dp0\jsign.jar %*
