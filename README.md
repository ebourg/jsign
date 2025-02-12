Jsign - Authenticode signing tool in Java
=========================================

[![Build Status](https://github.com/ebourg/jsign/actions/workflows/build.yml/badge.svg?branch=master&event=push)](https://github.com/ebourg/jsign/actions/workflows/build.yml)
[![Coverage Status](https://coveralls.io/repos/github/ebourg/jsign/badge.svg?branch=master)](https://coveralls.io/github/ebourg/jsign?branch=master)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![Maven Central](https://img.shields.io/maven-central/v/net.jsign/jsign.svg)](https://search.maven.org/#search%7Cga%7C1%7Cg%3A%22net.jsign%22)

Jsign is a versatile code signing tool that allows you to sign and timestamp Windows
executable files, installer packages and scripts. Jsign is platform independent
and provides an alternative to native tools like signtool on Windows or the Mono
development tools on Unix systems. It's particularly well-suited for signing
executable wrappers and installers generated by tools such as NSIS, msitools,
install4j, exe4j or launch4j. It emphasizes on seamless integration with cloud key
management systems and hardware tokens.

Jsign is available as a command line tool for Linux, macOS and Windows, as a task/plugin
for various build systems (Maven, Gradle, Ant, GitHub Actions), and as a Java library.

Jsign is free to use and licensed under the [Apache License version 2.0](https://www.apache.org/licenses/LICENSE-2.0).

## Features
* Platform independent signing of Windows executables, DLLs, Microsoft Installers (MSI), Cabinet files (CAB), Catalog files (CAT), Windows packages (APPX/MSIX), Microsoft Dynamics 365 extension packages, NuGet packages and scripts (PowerShell, VBScript, JScript, WSF)
* Timestamping with retries and fallback on alternative servers (RFC 3161 and Authenticode protocols supported)
* Supports multiple signatures per file, for all file types
* Extracts and embeds detached signatures to support [reproducible builds](https://reproducible-builds.org/docs/embedded-signatures/)
* Tags signed files with unsigned data (for user identification)
* Hashing algorithms: MD5, SHA-1, SHA-256, SHA-384 and SHA-512
* Keystores supported:
  * PKCS#12, JKS and JCEKS files
  * PKCS#11 hardware tokens ([YubiKey](https://www.yubico.com), [Nitrokey](https://www.nitrokey.com), [SafeNet eToken](https://cpl.thalesgroup.com/access-management/authenticators/pki-usb-authentication), etc)
  * Cloud key management systems:
    * [AWS KMS](https://aws.amazon.com/kms/)
    * [Azure Key Vault](https://azure.microsoft.com/services/key-vault/)
    * [Azure Trusted Signing](https://learn.microsoft.com/en-us/azure/trusted-signing/)
    * [DigiCert ONE](https://www.digicert.com/digicert-one) / [DigiCert KeyLocker](https://docs.digicert.com/en/digicert-keylocker.html)
    * [GaraSign](https://garantir.io/garasign/)
    * [Google Cloud KMS](https://cloud.google.com/security-key-management)
    * [HashiCorp Vault](https://www.vaultproject.io/)
    * [Keyfactor SignServer](https://www.signserver.org)
    * [Oracle Cloud KMS](https://www.oracle.com/security/cloud-security/key-management/)
    * [SignPath](https://signpath.io)
    * [SSL.com eSigner](https://www.ssl.com/esigner/)
* Private key formats: PVK and PEM (PKCS#1 and PKCS#8), encrypted or not
* Certificates: PKCS#7 in PEM and DER format
* Automatic download of the intermediate certificates
* Build tools integration (Maven, Gradle, Ant, GitHub Actions)
* Command line signing tool
* Authenticode signing API ([Javadoc](https://javadoc.io/doc/net.jsign/jsign-core))
* JCA security provider to use the keystores supported by Jsign with other tools such as jarsigner or apksigner

See https://ebourg.github.io/jsign for more information.


## Changes

#### Version 7.1 (in development)

* New signing service: SignPath
* The "Unsupported file" error when using the Ant task has been fixed
* The `timestamp` and `tag` commands have been fixed for MSI, catalog and script files
* The `--debug`, `--verbose` and `--quiet` parameters now work for all commands

#### Version 7.0 (2025-01-16)

* New signing services:
  * Azure Trusted Signing
  * Oracle Cloud
  * GaraSign
  * HashiCorp Vault Transit (contributed by Eatay Mizrachi)
  * Keyfactor SignServer (contributed by Björn Kautler)
* Signing of NuGet packages has been implemented (contributed by Sebastian Stamm)
* Commands have been added:
  * `timestamp`: timestamps the signatures of a file
  * `tag`: adds unsigned data (such as user identification data) to signed files
  * `extract`: extracts the signature from a signed file, in DER or PEM format
  * `remove`: removes the signature from a signed file
* The intermediate certificates are downloaded if missing from the keystore or the certificate chain file
* File list files prefixed with `@` are now supported with the command line tool to sign multiple files
* Wildcard patterns are now accepted by the command line tool to scan directories for files to sign
* Jsign now checks if the certificate subject matches the app manifest publisher before signing APPX/MSIX packages (with contributions from Scott Cooper)
* The new `--debug`, `--verbose` and `--quiet` parameters control the verbosity of the output messages
* The JCA provider now works with [apksigner](https://developer.android.com/tools/apksigner) for signing Android applications
* RSA 4096 keys are supported with the `PIV` storetype (for Yubikeys with firmware version 5.7 or higher)
* Certificates using an Ed25519 or Ed448 key are now supported (experimental)
* Signatures on MSI files with gaps in the mini FAT are no longer invalid
* The APPX/MSIX bundles are now signed with the correct Authenticode UUID
* The signed APPX/MSIX files no longer contain a `[Content_Types].old` entry
* The error message displayed when the password of a PKCS#12 keystore is missing has been fixed
* The log4j configuration warning displayed when signing a MSI file has been fixed (contributed by Pascal Davoust)
* The value of the `storetype` parameter is now case insensitive
* The Azure Key Vault account no longer needs the permission to list the keys when signing with jarsigner
* The DigiCert ONE host can now be specified with the `keystore` parameter
* The `AWS_USE_FIPS_ENDPOINT` environment variable is now supported to use the AWS KMS FIPS endpoints (contributed by Sebastian Müller)
* On Windows the YubiKey library path is automatically added to the PATH of the command line tool
* Signing more than one file with the `YUBIKEY` storetype no longer triggers a `CKR_USER_NOT_LOGGED_IN` error
* MS Cabinet files with a pre-allocated reserve are now supported
* The `--certfile` parameter can now be used to replace the certificate chain from the keystore
* PVK and PEM key files are now properly loaded even if the extension is not recognized (contributed by Alejandro González)
* API changes:
  * The keystore builder and the JCA provider are now in a separate `jsign-crypto` module
  * The PEFile class has been refactored to keep only the methods related to signing
  * The java.util.logging API is now used to log debug messages under the `net.jsign` logger
  * `Signable` implementations are now discovered dynamically using the ServiceLoader mechanism
  * `Signable.createContentInfo()` has been replaced with `Signable.createSignedContent()`
* Switched to BouncyCastle LTS 2.73.7

#### Version 6.0 (2024-01-17)

* Signing of APPX/MSIX packages has been implemented (thanks to Maciej Panek for the help)
* Signing of Microsoft Dynamics 365 extension packages has been implemented
* PIV cards are now supported with the new `PIV` storetype
* SafeNet eToken support has been improved with automatic PKCS#11 configuration using the new `ETOKEN` storetype
* The certificate chain in the file specified by the `certfile` parameter can now be in any order
* VBScript, JScript and PowerShell XML files without byte order marks are now parsed as Windows-1252 instead of ISO-8859-1
* The `keystore` parameter can now be specified with the `OPENPGP` storetype to distinguish between multiple connected devices
* The format detection based on the file extension is now case insensitive (contributed by Mathieu Delrocq)
* Only one call to the Google Cloud API is performed when the version of the key is specified in the alias parameter
* JVM arguments can now be passed using the `JSIGN_OPTS` environment variable
* API changes:
  * New `net.jsign.jca.JsignJcaProvider` JCA security provider to be used with other signing tools such as jarsigner
  * The signature can be removed by setting a null signature on the `Signable` object
  * `Signable.computeDigest(MessageDigest)` has been replaced by `Signable.computeDigest(DigestAlgorithm)`
  * The value of the `http.agent` system property is now appended to the User-Agent header when calling REST services
  * `AuthenticodeSigner` sets the security provider automatically if the keystore used is backed by a PKCS#11 token or a cloud service
  * `AmazonSigningService` now supports dynamic credentials
* Upgraded BouncyCastle to 1.77

#### Version 5.0 (2023-06-06)

* The AWS KMS signing service has been integrated (with contributions from Vincent Malmedy)
* Nitrokey support has been improved with automatic PKCS#11 configuration using the new `NITROKEY` storetype
* Smart cards are now supported with the new `OPENSC` storetype
* OpenPGP cards are now supported with the new `OPENPGP` storetype
* Google Cloud KMS via HashiCorp Vault is now supported with the new `HASHICORPVAULT` storetype (contributed by Maria Merkel)
* The Maven plugin can now use passwords defined in the Maven settings.xml file
* The "X.509 Certificate for PIV Authentication" on a Yubikey (slot 9a) is now automatically detected
* SHA-1 signing with Azure Key Vault is now possible (contributed by Andrij Abyzov)
* MSI signing has been improved:
  * MSI files with embedded sub storages (such as localized installers) are now supported
  * Signing a MSI file already signed with an extended signature is no longer rejected
  * An issue causing some MSI files to become corrupted once signed has been fixed
* A user friendly error message is now displayed when the private key and the certificate don't match
* Setting `-Djava.security.debug=sunpkcs11` with the `YUBIKEY` storetype no longer triggers an error
* The cloud keystore name is no longer treated as a relative file by the Ant task and the Maven plugin
* The paths are resolved relatively to the Ant/Maven/Gradle subproject or module directory instead of the root directory
* Signing with SSL.com eSigner now also works when the malware scanning feature is enabled
* API changes:
  * The `KeyStoreUtils` class has been replaced by `KeyStoreBuilder`
* Upgraded BouncyCastle to 1.73

#### Version 4.2 (2022-09-19)

* Signing of Windows catalog files has been implemented
* The syntax to invoke the Gradle plugin with the Kotlin DSL has been simplified
* Several OutOfMemoryError caused by invalid input files have been fixed (thanks to OSS-Fuzz)
* API changes:
  * The Signable interface now extends Closeable and can be used in try-with-resources blocks
  * Files are no longer closed after signing
  * Most parsing errors are now rethrown as IOException
* Upgraded BouncyCastle to 1.71.1

#### Version 4.1 (2022-05-08)

* The SSL.com eSigner service has been integrated
* The Ant task can now sign multiple files by defining a fileset (contributed by Kyle Berezin)
* The type of the keystore is now automatically detected from the file header
* The `storepass` and `keypass` parameters can now be read from a file or from an environment variable
* The execution of the Maven plugin can now be skipped (with the `<skip>` configuration element, or the `jsign.skip` property)
* Fixed the _"Map failed"_ OutOfMemoryError when signing large MSI files
* Certificates using an elliptic-curve key are now supported
* The default timestamping authority is now Sectigo instead of Comodo
* The signed file is now properly closed after attaching or detaching a signature (contributed by Mark Thomas)
* A detached signature added to a PE file whose length isn't a multiple of 8 is no longer invalid
* Fixed an error when signing with a Yubikey on Windows with a 32-bit JRE
* The PKCS#11 slot of the Yubikey is now automatically detected
* Upgraded BouncyCastle to 1.71

#### Version 4.0 (2021-08-09)

* MS Cabinet signing has been implemented (contributed by Joseph Lee)
* Signatures can be detached and re-attached to make the builds reproducible without access to the private key
* The new `YUBIKEY` storetype can be specified to sign with a YubiKey (the SunPKCS11 provider is automatically configured)
* The Azure Key Vault, DigiCert ONE and Google Cloud KMS cloud key management systems have been integrated
* The Maven plugin can now sign multiple files by defining a fileset (contributed by Bernhard Stiftner).
* The command line tool can now sign multiple files
* The `alias` parameter is now optional if the keystore contains only one entry (contributed by Michele Locati)
* The keystore aliases are now listed in the error message if the alias specified is incorrect
* The `storetype` parameter is no longer required for JCEKS keystores
* Fixed the update of the PE checksum (contributed by Markus Kilås)
* The `CMSAlgorithmProtection` attribute is no longer added to the signature (contributed by Yegor Yarko)
* The signature algorithm is identified as `RSA` instead of `sha*RSA` when using SHA-2 digests (contributed by Yegor Yarko)
* Upgraded BouncyCastle to 1.69

#### Version 3.1 (2020-03-01)

* Certificate files can now be used with a PKCS11 token to support OpenPGP cards unable to hold a whole certificate chain (contributed by Erwin Tratar)
* Fixed an IllegalArgumentException when parsing large entries of MSI files

#### Version 3.0 (2020-01-07)

* Jsign now requires Java 8 or higher
* MSI signing has been implemented
* Script signing has been implemented: PowerShell (contributed by Björn Kautler), VBScript, JScript and WSF
* The Maven plugin now uses the proxy defined in the Maven settings for the timestamping (contributed by Denny Bayer)
* The Maven plugin now accepts passwords encrypted using the Maven security settings (contributed by Denny Bayer)
* The Maven plugin is now bound by default to the `package` phase
* The timestamping is no longer enabled by default with the Maven plugin
* Renamed the command line tool from `pesign` to `jsign`
* Renamed the Ant task and the Gradle extension method from `signexe` to `jsign`
* SOCKS proxies are now supported
* Fixed the invalid SHA-512 signatures (contributed by Markus Kilås)
* The non-timestamped signatures are now reproducible (the `signingTime` attribute has been removed)
* Upgraded BouncyCastle to 1.64

#### Version 2.1 (2018-10-08)

* Fixed the loading of SunPKCS11 configuration files with Java 9
* SunPKCS11 configuration files can be loaded from any directory
* Maven plugin settings can now be passed on the command line (contributed by Nicolas Roduit)
* The first timestamping authority specified is no longer skipped (contributed by Thomas Atzmueller)
* Fixed the typo on the withTimestampingAuthority() methods in PESigner (contributed by Bjørn Madsen)
* Upgraded BouncyCastle to 1.60

#### Version 2.0 (2017-06-12)

* Jsign now requires Java 7 or higher
* Multiple signatures are now supported. New signatures can replace or be added to the previous ones.
* PKCS#11 hardware tokens are now supported.
* The signature algorithm can now be specified independently of the digest algorithm (contributed by Markus Kilås)
* Timestamping is attempted 3 times by default with a 10 seconds pause if an exception occurs (contributed by Erwin Tratar)
* Timestamping can now fail over to other services
* Private keys in PEM format are now supported (PKCS#1 and PKCS#8, encrypted or not)
* Upgraded BouncyCastle to 1.54 (contributed by Markus Kilås)
* Fixed the Accept header for RFC 3161 requests (contributed by Markus Kilås)
* Internal refactoring to share the code between the Ant task and the CLI tool (contributed by Michael Peterson)
* The code has been split into distinct modules (core, ant, cli).
* Jsign is now available as a plugin for Maven (net.jsign:jsign-maven-plugin) and Gradle
* The API can be used to sign in-memory files using a SeekableByteChannel

#### Version 1.3 (2016-08-04)

* The command line tool now supports HTTP proxies (contributed by Michael Szediwy)
* RFC 3161 timestamping services are now supported (contributed by Florent Daigniere)
* The digest algorithm now defaults to SHA-256
* The shaded dependencies are now relocated to avoid conflicts
* Added SHA-384 and SHA-512 checksums support
* SHA-2 is accepted as an alias for SHA-256

#### Version 1.2 (2013-01-10)

* Reduced the memory usage when signing large files
* Files over 2 GB are now supported
* Improved the thread safety

#### Version 1.1 (2012-11-03)

* Command line interface with bash completion for signing files (available as RPM and DEB packages)
* The keystore is no longer locked if the signing fails

#### Version 1.0 (2012-10-05)

* Initial release
