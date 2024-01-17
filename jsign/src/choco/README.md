Jsign Chocolatey package
------------------------

Deployment procedure:
* Build Jsign with `mvn package`
* Update the version in `jsign.nuspec`
* Update the version and the checksum in `tools/VERIFICATION.md`
* Run:
  * `choco pack`
  * `choco push jsign.<version>.nupkg`
