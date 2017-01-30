Jsign - Java implementation of Microsoft Authenticode
=====================================================

[![Build Status](https://secure.travis-ci.org/ebourg/jsign.svg)](http://travis-ci.org/ebourg/jsign)
[![Coverage Status](https://coveralls.io/repos/github/ebourg/jsign/badge.svg?branch=master)](https://coveralls.io/github/ebourg/jsign?branch=master)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0)
[![Maven Central](https://img.shields.io/maven-central/v/net.jsign/jsign.svg)](http://search.maven.org/#search|gav|1|g%3A"net.jsign" AND a%3A"jsign")

Jsign is a Java implementation of Microsoft Authenticode that lets you sign
and timestamp executable files for Windows. Jsign is platform independent and
provides an alternative to native tools like signcode/signtool on Windows
or the Mono development tools on Unix systems.

Jsign comes as an easy to use Ant task to be integrated in any automated build.
It's especially suitable for signing executable wrappers and installers generated
by tools like NSIS, exe4j, launch4j or JSmooth. Jsign can also be used with Maven
using the Antrun plugin, or standalone as a command line tool.

Jsign is free to use and licensed under the Apache License version 2.0.


See http://ebourg.github.com/jsign for more information.


Changes
=======

Version 1.4 (in development)
* Jsign now requires Java 7 or higher
* Multiple signatures are now supported. New signatures can replace or be added to the previous ones.
* The signature algorithm can now be specified independently of the digest algorithm (contributed by Markus Kilås)
* Timestamping is attempted 3 times by default with a 10 seconds pause if an IOException occurs (contributed by Erwin Tratar)
* Timestamping can now fail over to other services
* Upgraded BouncyCastle to 1.54 (contributed by Markus Kilås)
* Fixed the Accept header for RFC 3161 requests (contributed by Markus Kilås)
* Internal refactoring to share the code between the Ant task and the CLI tool (contributed by Michael Peterson)
* The code has been split into distinct modules (core, ant, cli).
* Jsign is now available as a Maven plugin (net.jsign:jsign-maven-plugin)
* The API can be used to sign in-memory files using a SeekableByteChannel

Version 1.3, 2016-08-04
* The command line tool now supports HTTP proxies (contributed by Michael Szediwy)
* RFC 3161 timestamping services are now supported (contributed by Florent Daigniere)
* The digest algorithm now defaults to SHA-256
* The shaded dependencies are now relocated to avoid conflicts
* Added SHA-384 and SHA-512 checksums support
* SHA-2 is accepted as an alias for SHA-256

Version 1.2, 2013-01-10
* Reduced the memory usage when signing large files
* Files over 2GB are now supported
* Improved the thread safety

Version 1.1, 2012-11-03
* Command line interface with bash completion for signing files (available as RPM and DEB packages)
* The keystore is no longer locked if the signing fails

Version 1.0, 2012-10-05
* Initial release
