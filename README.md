Jsign - Java implementation of Microsoft Authenticode
=====================================================

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

Jsign 1.2
* Reduced the memory usage when signing large files
* Files over 2GB are now supported
* Improved the thread safety

Jsign 1.1
* Command line interface with bash completion for signing files (available as RPM and DEB packages)
* The keystore is no longer locked if the signing fails

Jsign 1.0
* Initial release
