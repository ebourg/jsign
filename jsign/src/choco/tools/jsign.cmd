@echo off
setlocal

@rem Add the YubiKey library path to the PATH environment variable
if exist "C:\Program Files\Yubico\Yubico PIV Tool\bin\" (
    set "PATH=%PATH%;C:\Program Files\Yubico\Yubico PIV Tool\bin"
)

@rem Allow unsafe memory access with Java 23+ to avoid warnings when signing MSI files
java --sun-misc-unsafe-memory-access=allow -version >nul 2>&1
if %errorlevel% EQU 0 (
    set "JSIGN_OPTS=--sun-misc-unsafe-memory-access=allow %JSIGN_OPTS%"
)

java %JSIGN_OPTS% ^
     -Djava.net.useSystemProxies=true ^
     -Dbasename=jsign ^
     -jar "%~dp0\jsign.jar" %*
