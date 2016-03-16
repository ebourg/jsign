Jsign - Java implementation of Microsoft Authenticode
=====================================================

[![Build Status](https://secure.travis-ci.org/ebourg/jsign.svg)](http://travis-ci.org/ebourg/jsign)
[![Coverage Status](https://coveralls.io/repos/github/ebourg/jsign/badge.svg?branch=master)](https://coveralls.io/github/ebourg/jsign?branch=master)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0)

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

Version 1.3, in development
* The command line tool now supports HTTP proxies (contributed by Michael Szediwy)
* RFC 3161 timestamping services are now supported (contributed by Florent Daigniere)

Version 1.2, 2013-01-10
* Reduced the memory usage when signing large files
* Files over 2GB are now supported
* Improved the thread safety

Version 1.1, 2012-11-03
* Command line interface with bash completion for signing files (available as RPM and DEB packages)
* The keystore is no longer locked if the signing fails

Version 1.0, 2012-10-05
* Initial release
